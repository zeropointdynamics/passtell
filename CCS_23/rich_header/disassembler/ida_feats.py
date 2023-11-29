# (C) Zeropoint Dynamics, 2022
# Author(s): 
#   Kevin Z. Snow (kzsnow)
#   Ryan Court (rcourt-zp)
#   Yufei Du (yufeidu)
import argparse
import functools
import hashlib
import os
import subprocess
import tempfile
import traceback
import capstone
import magic
import pandas as pd
from pathlib import Path
import re
import json
from tqdm import tqdm

# List of known C/C++ MSVC ID going as old as MSVC 6.0
COMP_ID_LIST = ['104', '105', '0e0', '0e1', '0ce', '0cf', '0aa', '0ab', '083', '084', '06d', '06e', '05f', '060', '01c', '01d', '00a', '00b', '015', '016']

# Sanitize the operands
def normalize_insts(op: str, max_imm=-1) -> str:
    # Immediate
    for imm in re.findall(r"\$0x[a-z0-9]+", op):
        if int(imm[1:], 16) > max_imm:
            op = op.replace(imm, "#IMM#")
    for imm in re.findall(r"\$\-?[0-9]+", op):
        if abs(int(imm[1:])) > max_imm:
            op = op.replace(imm, "#IMM#")
    # Memory
    for mem in re.findall(r"(?:0x)?\-?[a-z0-9]+\(", op):
        op = op.replace(mem, "#MEM# ").replace(")", "")
    # Target
    for target in re.findall(r"^0x[a-z0-9]+$", op):
        op = op.replace(target, "#TARGET#")
    # Replace IDA style comma to objdump style space
    op = op.replace(", ", " ").replace("(", "").replace(")", "")

    return op

# Returns the list of "fuzzy" functions from the binary
def dump_fuzzy(md, N=100, debug=False):
    hashes = []
    for func_ea in idautils.Functions():
        if idc.get_func_flags(func_ea) & (idc.FUNC_LIB | idc.FUNC_THUNK):
            continue
        func_name = idc.get_func_name(func_ea)
        f = idautils.ida_funcs.get_func(func_ea)
        if debug:
            print(hex(f.start_ea) + " - " + hex(f.end_ea) + " " + func_name)
        data = ida_bytes.get_bytes(f.start_ea, f.end_ea - f.start_ea)
        if debug:
            print("bytes:   " + str(data))
        fuzzy_hash = []
        for i, inst in enumerate(md.disasm(data, len(data))):
            if inst.bytes[0] == 0x0F:
                # 2 byte opcode
                fuzzy_hash.append(inst.bytes[0])
                fuzzy_hash.append(inst.bytes[1])
            else:
                # 1 byte opcode
                fuzzy_hash.append(inst.bytes[0])

            if i > N:
                break

        if len(fuzzy_hash) < 1:
            continue

        hashes.append("")
        for b in fuzzy_hash:
            hashes[-1] += f"{b:02x}"
        if debug:
            print(f"    {hashes[-1]}")
    return hashes


def dump_functions(md, debug=False):
    functions = []
    for func_ea in idautils.Functions():
        if idc.get_func_flags(func_ea) & (idc.FUNC_LIB | idc.FUNC_THUNK):
            continue
        func_name = idc.get_func_name(func_ea)
        f = idautils.ida_funcs.get_func(func_ea)
        if debug:
            print(hex(f.start_ea) + " - " + hex(f.end_ea) + " " + func_name)
        data = ida_bytes.get_bytes(f.start_ea, f.end_ea - f.start_ea)
        if debug:
            print("bytes:   " + str(data))
        if len(data) < 1:
            continue
        functions.append([])
        for i, inst in enumerate(md.disasm(data, len(data))):
            if debug:
                print("    %s\t%s" % (inst.mnemonic, inst.op_str))
            functions[-1].append(f"{inst.mnemonic} {normalize_insts(inst.op_str)}")
    return json.dumps(functions)

# Same as dump_functions but returns a 2D list instead of an 1D list of strings
def dump_functions_multi_level(md, debug=False):
    functions = []
    for func_ea in idautils.Functions():
        if idc.get_func_flags(func_ea) & (idc.FUNC_LIB | idc.FUNC_THUNK):
            continue
        func_name = idc.get_func_name(func_ea)
        f = idautils.ida_funcs.get_func(func_ea)
        if debug:
            print(hex(f.start_ea) + " - " + hex(f.end_ea) + " " + func_name)
        data = ida_bytes.get_bytes(f.start_ea, f.end_ea - f.start_ea)
        if debug:
            print("bytes:   " + str(data))
        if len(data) < 1:
            continue
        functions.append([])
        for i, inst in enumerate(md.disasm(data, len(data))):
            if debug:
                print("    %s\t%s" % (inst.mnemonic, inst.op_str))
            functions[-1].append(f"{inst.mnemonic} {normalize_insts(inst.op_str)}")
            # If the instruction doesn't have any operands, get rid of the ending space
            if functions[-1][-1][-1] == ' ':
                functions[-1][-1] = functions[-1][-1][0:-1]
    return functions

def simple_filetype(fileinfo):
    if "PE32" in fileinfo or "DOS executable" in fileinfo:
        return "PE"
    elif "ELF" in fileinfo:
        return "ELF"
    elif "Mach-O" in fileinfo:
        return "Mach-O"
    else:
        return "other"

def parse_richprint(binfile, richprint_path, filter=False):
    richprint_args = (richprint_path, binfile)
    result = subprocess.run(richprint_args, capture_output=True)
    configs = []
    for line in result.stdout.decode().split('\n'):
        # print(line)
        # We only care about lines with compiler ID
        if len(line) == 0 or not line[0] == '0':
            continue
        # Format: [comp_id, id, version, count, (desc)]
        config = line.split(maxsplit=4)
        if not filter or config[1] in COMP_ID_LIST:
            configs.append(config)
    return configs




def ida_main(binfile, binfile_md5, binfile_label, output_type, csvfile, fileinfo, richprint_file):
    """The Actual IDA Pro Script"""
    # print(binfile_md5, binfile_label, binfile)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.syntax = capstone.CS_OPT_SYNTAX_ATT
    idc.auto_wait()
    if output_type == "fuzzy":
        feats = dump_fuzzy(md)
    else:
        feats = dump_functions(md)

    apt = Path(binfile).resolve().parts[-2]
    # print(apt)
    filetype = simple_filetype(fileinfo)

    rich = parse_richprint(binfile, richprint_file, True)
    
    comp = []
    for entry in rich:
        if len(entry) == 5:
            comp.append(entry[0] + ': ' + entry[4])
        else:
            comp.append(entry[0])
    
    ver = ''
    for subp in binfile.split('/'):
        if 'msvc-' in subp:
            ver = subp

    data = {
        "hash": binfile_md5,
        "label": apt,
        "path": str(Path(binfile).resolve()),
        "feats": [feats],
        "type": filetype,
        "info": fileinfo,
        # "rich": json.dumps(parse_richprint(binfile, '../richprint/richprint', True)),
        "comp": json.dumps(comp),
        "ver": ver,
    }

    df = pd.DataFrame(data)

    # output_path = "../fuzzy.csv"

    header = True
    if Path(csvfile).exists():
        header = False
    df.to_csv(csvfile, mode="a", index=False, header=header)


def _ida_main_wrapper():
    global print
    """
    IDA scripts don't print to stdout on commandline, and also don't
    show stack traces on an exception. This bit of wrapper code
    transparently resolves those issues for the IDA script.
    """
    logfile = idc.ARGV[1]
    binfile = idc.ARGV[2]
    binfile_md5 = idc.ARGV[3]
    binfile_label = idc.ARGV[4]
    output_type = idc.ARGV[5]
    csvfile = idc.ARGV[6]
    fileinfo = idc.ARGV[7].replace('__', ' ')
    richprint_file = idc.ARGV[8]
    f = open(logfile, "w")
    print = functools.partial(print, file=f)
    try:
        ida_main(binfile, binfile_md5, binfile_label, output_type, csvfile, fileinfo, richprint_file)
    except Exception as e:
        print("".join(traceback.format_exception(None, e, e.__traceback__)))
    f.close()
    idc.qexit(0)


def _md5_file(filename):
    md5 = hashlib.md5()
    with open(filename, "rb") as f:
        md5.update(f.read())
    return md5.hexdigest()


def run_ida_script(args, label="bin"):
    # Use recursive mode if it's a binary
    binpath = Path(args.binary)
    binlist = []
    if binpath.is_dir():
        for subp in binpath.rglob('**/*.exe'):
            binlist.append(subp.resolve().as_posix())
        for subp in binpath.rglob('**/*.dll'):
            binlist.append(subp.resolve().as_posix())
    else:
        binlist.append(binpath.resolve().as_posix())
    for binfile in tqdm(binlist):
        fileinfo = magic.from_file(binfile)
        output_type = "function"
        if args.fuzzy:
            output_type = "fuzzy"
        csvfile = args.csv_path
        if not os.path.exists(binfile):
            print("File not found")
            return
        binfile_md5 = _md5_file(binfile)
        curdir = os.path.abspath(os.getcwd())
        scriptfile = os.path.abspath(__file__)
        idadb_dir = os.path.join(curdir, "ida_databases")
        os.makedirs(idadb_dir, exist_ok=True)
        idbfile = os.path.join(idadb_dir, binfile_md5)
        idb_extension = None
        if os.path.exists(idbfile + ".i64"):
            idb_extension = ".i64"
        elif os.path.exists(idbfile + ".idb"):
            idb_extension = ".idb"
        with tempfile.NamedTemporaryFile() as tmp:
            if idb_extension is None:
                # New binary being analyzed
                ida_args = (
                    "idat64",
                    "-c",
                    "-A",
                    "-P+",
                    f"-S{scriptfile} {tmp.name} {binfile} {binfile_md5} {label} {output_type} {csvfile} {fileinfo.replace(' ', '__')} {args.richprint}",
                    f"-o{idbfile}",
                    binfile,
                )
            else:
                # Open existing idb/i64 analysis
                ida_args = (
                    "idat64",
                    "-A",
                    f"-S{scriptfile} {tmp.name} {binfile} {binfile_md5} {label} {output_type} {csvfile} {fileinfo.replace(' ', '__')} {args.richprint}",
                    idbfile + idb_extension,
                )
            # print(" ".join(ida_args))
            subprocess.call(ida_args)
            with open(tmp.name, "r") as infile:
                for line in infile:
                    print(line.rstrip())


def _script_main():
    """
    When run directly from commandline with specified binary:
     - Facilitate logging from IDA to stdout (for debugging only):
       - Create a temporary log file the IDA script writes to
       -
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("csv_path")
    parser.add_argument("--richprint", default="richprint/richprint")
    parser.add_argument("--fuzzy", action="store_true")
    args = parser.parse_args()
    run_ida_script(args)


if __name__ == "__main__":
    try:
        import idc
        import idautils
        import idaapi
        import ida_bytes

        _ida_main_wrapper()
    except:
        _script_main()
