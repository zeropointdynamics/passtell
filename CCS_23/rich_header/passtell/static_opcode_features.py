# Copyright 2022, Zeropoint
# Author(s): Kevin Snow, Ryan Court, Yufei Du
import argparse
import hashlib
import json
import re
import subprocess
import sys

from collections import defaultdict, deque
from itertools import islice


register_normals = {
    "%al": "%_l",
    "%ah": "%_h",
    "%ax": "%_x",
    "%bl": "%_l",
    "%bh": "%_h",
    "%bx": "%_x",
    "%cl": "%_l",
    "%ch": "%_h",
    "%cx": "%_x",
    "%dl": "%_l",
    "%dh": "%_h",
    "%dx": "%_x",
    "%eax": "%e_x",
    "%ebx": "%e_x",
    "%ecx": "%e_x",
    "%edx": "%e_x",
    "%edi": "%e_i",
    "%esi": "%e_i",
    "%r8": "%r__",
    "%r8b": "%r__b",
    "%r8d": "%r__d",
    "%r8w": "%r__w",
    "%r9": "%r__",
    "%r9b": "%r__b",
    "%r9d": "%r__d",
    "%r9w": "%r__w",
    "%r10": "%r__",
    "%r10b": "%r__b",
    "%r10d": "%r__d",
    "%r10w": "%r__w",
    "%r11": "%r__",
    "%r11b": "%r__b",
    "%r11d": "%r__d",
    "%r11w": "%r__w",
    "%r12": "%r__",
    "%r12d": "%r__d",
    "%r12w": "%r__w",
    "%r13": "%r__",
    "%r13d": "%r__d",
    "%r13w": "%r__w",
    "%r14": "%r__",
    "%r14d": "%r__d",
    "%r14w": "%r__w",
    "%r15": "%r__",
    "%r15d": "%r__d",
    "%r15w": "%r__w",
    "%rax": "%r_x",
    "%rbx": "%r_x",
    "%rcx": "%r_x",
    "%rdx": "%r_x",
    "%rdi": "%r_i",
    "%rsi": "%r_i",
    "%xmm0": "%xmm_",
    "%xmm1": "%xmm_",
    "%xmm2": "%xmm_",
    "%xmm3": "%xmm_",
    "%xmm4": "%xmm_",
    "%xmm5": "%xmm_",
    "%xmm6": "%xmm_",
    "%xmm7": "%xmm_",
}


class StaticFunction:
    """Represents a function section, name and instructions."""

    def __init__(self, offset, section, name, insts, targets=[]):
        self.offset = offset
        self.section = section
        self.name = name
        self.insts = insts
        self.targets = targets
        raw_insts = [x[1] for x in self.insts]
        self.hash = hashlib.md5(
            "; ".join(raw_insts).encode("utf8")
        ).hexdigest()
        self.srcfile = "??"
        self.lineno = "??"

    def __repr__(self):
        inst_cnt = len(self.insts)
        return f"[{self.section}] <{self.name}>: {inst_cnt} insts"


class StaticBinaryFeatures:
    """Binary features from static analysis."""

    def __init__(
        self,
        filename,
        debug=False,
        include_regs=False,
        normalize_registers=False,
        max_imms=-1,
    ):
        self.filename = filename
        self.debug = debug
        self.include_regs = include_regs
        self.normalize_registers = normalize_registers
        self.max_imms = max_imms
        self._re_section = re.compile(r"Disassembly of section (.*):")
        self._re_function = re.compile(r"[a-z0-9]{8,} <(.*)>:")
        self._re_imm = re.compile(r"\$0x[a-z0-9]+")
        self._re_imm2 = re.compile(r",[0-9]+\)")
        self._re_mem = re.compile(r"0x[a-z0-9]+")
        self._re_target = re.compile(r"^[a-z0-9]{4,}$")

    def _objdump(self, filename):
        """
        Returns raw `objdump` stdout.
        """
        cmd = ["objdump", "-C", "-d", filename]
        p = subprocess.Popen(" ".join(cmd), stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        if p_status != 0:
            return None
        return output.splitlines()

    def _addr2line(self, filename, offsets):
        """
        Given a list of binary offsets, returns an equally sized list
        of [(filename,lineno)] that those addresses correspond to.
        """
        filenames = []
        cmd = ["addr2line", "-e", filename]
        for chunk in self._chunks(offsets, 100):
            p = subprocess.Popen(
                " ".join(cmd + chunk), stdout=subprocess.PIPE, shell=True
            )
            (output, err) = p.communicate()
            p_status = p.wait()
            if p_status != 0:
                return None
            stdout = output.splitlines()
            if len(stdout) != len(chunk):
                raise (
                    "addr2line output does not match number of addresses requested"
                )
            for line in stdout:
                parts = line.decode("utf8").split(":")
                filenames.append((parts[0], parts[1]))
        return filenames

    def _functions(self):
        """
        Returns iterable `StaticFunction`.
        """
        o = self._objdump(self.filename)
        if o is None:
            print("ERROR: objdump failed on", self.filename)
            return
        section = None
        function = None
        function_offset = None
        insts = []
        targets = []
        for line in o:
            line = str(line.decode("utf8"))

            # Parse ELF section name
            match = self._re_section.match(line)
            if match is not None:
                if function is not None:
                    yield StaticFunction(
                        function_offset, section, function, insts, targets
                    )
                    function = None
                    function_offset = None
                    insts = []
                    targets = []
                section = match.group(1)

            # Parse Function name
            if section is None:
                continue
            match = self._re_function.match(line)
            if match is not None:
                if function is not None:
                    yield StaticFunction(
                        function_offset, section, function, insts, targets
                    )
                    function = None
                    function_offset = None
                    insts = []
                    targets = []
                function = match.group(1)
                function_offset = line.split(" ")[0]

            # Verify we're parsing insts in a section and function
            if section is None or function is None:
                continue
            if not line.startswith("  "):
                continue

            # Parse instruction and operands
            #
            # Parse the opcode and operand parts
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            address = int(parts[0][:-1].strip(), 16)
            opcode = parts[2]
            if opcode.startswith("data"):
                continue
            opcode = re.sub("\s+", " ", opcode)
            parts = opcode.split(" ")
            opcode = parts[0]
            operands = ""
            if len(parts) > 1:
                operands = parts[1]
            #
            # Normalize the operands by removing immediates and operands
            orig_operands = operands
            operands = operands.replace("-0x", "0x")
            for imm in self._re_imm.findall(operands):
                if int(imm[1:], 16) > self.max_imms:
                    operands = operands.replace(imm, "#IMM#")
            for imm in self._re_imm2.findall(operands):
                if int(imm[1:-1]) > self.max_imms:
                    operands = operands.replace(imm, ",#IMM#)")

            operands = self._re_mem.sub("#MEM#", operands)
            # If the instruction is a direct call, add target
            if not self._re_target.match(operands) is None and "call" in opcode and len(parts) == 3:
                target = parts[2][1:-1]
                if not target in targets:
                    targets.append(target)
            operands = self._re_target.sub("#TARGET#", operands)
            inst_normalized = f"{opcode} {operands}"

            op_tok_norm = (
                inst_normalized.replace("(", ",")
                .replace(")", ",")
                .replace(":", ",")
                .replace("*", "*,")
                .replace(" ", ",")
            )
            tokens = [i for i in op_tok_norm.split(",") if i]
            if self.normalize_registers:
                tokens = [register_normals.get(i, i) for i in tokens if i]
            inst_normalized = " ".join(tokens)

            if self.include_regs:
                imms = []
                if (
                    "call" not in inst_normalized
                    and "#IMM#" in inst_normalized
                ):
                    reg = re.compile(r".*%([a-zA-Z0-9]+)\W?").match(
                        orig_operands
                    )
                    if reg is not None:
                        reg = reg.group(1)
                        imm = re.compile(r"\$(-?0x[a-z0-9]+)").match(
                            orig_operands
                        )
                        imm2 = re.compile(r".*,([0-9]+)\)").match(
                            orig_operands
                        )
                        if imm is not None:
                            imms.append(imm.group(1))
                        if imm2 is not None:
                            imms.append(imm2.group(1))
                        if len(imms) > 0:
                            imms = ",".join(imms)
                            reg_val_normalized = f"REG:{reg}:{imms}"
                            insts.append([address, reg_val_normalized])

            insts.append([address, inst_normalized])

        if function is not None:
            yield StaticFunction(function_offset, section, function, insts, targets)

    def _functions_with_filenames(self):
        """
        Just like `_functions`, but additionally uses `addr2line` to
        grab the filename that contains the function. Calls addr2line
        in batches of 100 functions to attempt to minimize subprocess
        overhead.
        """
        funcs = []
        for func in self._functions():
            funcs.append(func)
            if len(funcs) >= 100:
                offsets = [x.offset for x in funcs]
                addr2line_results = self._addr2line(self.filename, offsets)
                if addr2line_results is not None:
                    for i, srcfile in enumerate(addr2line_results):
                        funcs[i].srcfile = srcfile[0]
                        funcs[i].lineno = srcfile[1]
                yield from [x for x in funcs]
                funcs = []
        offsets = [x.offset for x in funcs]
        addr2line_results = self._addr2line(self.filename, offsets)
        if addr2line_results is not None:
            for i, srcfile in enumerate(addr2line_results):
                funcs[i].srcfile = srcfile[0]
                funcs[i].lineno = srcfile[1]
        yield from [x for x in funcs]

    def _chunks(self, lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    def _window(self, iterable, n=1, tuple=tuple):
        """Boilerplate iteration using a sliding window"""
        it = iter(iterable)
        win = deque(islice(it, n), n)
        if len(win) < n:
            return
        append = win.append
        yield tuple(win)
        for e in it:
            append(e)
            yield tuple(win)

    def features_per_function(
        self,
        n=3,
        filter=None,
        min_insts=None,
        max_insts=None,
        sequence_feats=False,
        targets=False,
    ):
        """
        Returns dictionary of instruction ngrams with values
        representing the frequency of that ngram within grams of
        the same n value. Frequencies are global (entire binary).
        An instruction sequence is measured as an ngram only within
        function boundaries, i.e. instructions crossing function
        boundaries are not counted as an ngram.
        """
        if filter is not None:
            if self.debug:
                print("[DEBUG] Filter Regexp:", filter)
            filter_re = re.compile(filter)
        func_results = []
        # Generate instruction ngrams and track total/global counts
        for func in self._functions():
            if min_insts is not None and len(func.insts) < min_insts:
                continue
            if filter is not None:
                func_id = f"{func.section.replace(' ', '_')} {func.name.replace(' ', '_')}"
                if filter_re.match(func_id) is None:
                    continue
                if self.debug:
                    print("[DEBUG] Filter includes:", func_id)
            freqs = [defaultdict(int) for i in range(n)]
            totals = [0 for i in range(n)]
            for i in range(n):
                for ngram in self._window(func.insts[:max_insts], n=i + 1):
                    val = "; ".join(list(ngram))
                    freqs[i][val] += 1
                    totals[i] += 1
            # Normalize counts to frequency of the ngram in entire program
            for i in range(n):
                # ngram_total = len(freqs[i])
                ngram_total = totals[i]
                for ngram in freqs[i].keys():
                    freqs[i][ngram] = freqs[i][ngram] / ngram_total
            # Merge all ngram dictionaries together
            big_dict = {}
            for i in range(n):
                big_dict.update(freqs[i])
            entry = {
                "section": func.section,
                "function": func.name,
                "hash": func.hash,
                "features": big_dict,
            }
            if sequence_feats:
                seq_feats = []
                for inst in func.insts[:max_insts]:
                    seq_feats.append(inst.split(" "))
                entry["bagofwords"] = seq_feats
            if targets:
                entry["targets"] = func.targets
            func_results.append(entry)
        # Return ngram dictionary w/ ngram frequencies ready to dump
        # to a file as json.
        return func_results

    def features_per_object(self, n=3, filter=None):
        if filter is not None:
            if self.debug:
                print("[DEBUG] Filter Regexp:", filter)
            filter_re = re.compile(filter)
        objects = {}
        # Generate instruction ngrams and track total/global counts
        for func in self._functions_with_filenames():
            if func.srcfile in ["??", ""]:
                continue  # Skip unidentified functions
            # print(func.section, func.name, func.srcfile)
            if filter is not None:
                func_id = f"{func.section.replace(' ', '_')} {func.name.replace(' ', '_')}"
                if filter_re.match(func_id) is None:
                    continue
                if self.debug:
                    print("[DEBUG] Filter includes:", func_id)

            if func.srcfile not in objects:
                objects[func.srcfile] = {
                    "object": func.srcfile,
                    "functions": [],
                    "features": {},
                    "freqs": [defaultdict(int) for i in range(n)],
                    "totals": [0 for i in range(n)],
                }
            objects[func.srcfile]["functions"].append(func.name)

            freqs = objects[func.srcfile]["freqs"]
            totals = objects[func.srcfile]["totals"]
            for i in range(n):
                for ngram in self._window(func.insts, n=i + 1):
                    val = "; ".join(list(ngram))
                    freqs[i][val] += 1
                    totals[i] += 1

        for _, obj in objects.items():
            obj["functions"] = sorted(obj["functions"])
            freqs = obj["freqs"]
            totals = obj["totals"]
            # Normalize counts to frequency of the ngram in entire program
            for i in range(n):
                ngram_total = totals[i]
                for ngram in freqs[i].keys():
                    freqs[i][ngram] = freqs[i][ngram] / ngram_total
            # Merge all ngram dictionaries together
            big_dict = {}
            for i in range(n):
                big_dict.update(freqs[i])
            obj["features"] = big_dict
            del obj["freqs"]
            del obj["totals"]

        return [v for _, v in sorted(objects.items())]

    def functions(self, max_insts=None, min_insts=None, start_end=False):
        funcs = {}
        #for func in self._functions():
        for func in self._functions_with_filenames():
            if min_insts is not None and len(func.insts) < min_insts:
                continue
            funcs[func.hash] = {}
            if max_insts is not None and len(func.insts) > max_insts:
                if start_end:
                    funcs[func.hash]["insts"] = (
                        func.insts[: (max_insts // 2)]
                        + func.insts[-(max_insts // 2) :]
                    )
                else:
                    funcs[func.hash]["insts"] = func.insts[:max_insts]
            else:
                funcs[func.hash]["insts"] = func.insts
            funcs[func.hash]["hash"] = func.hash
            funcs[func.hash]["name"] = func.name
            funcs[func.hash]["offset"] = func.offset
            funcs[func.hash]["section"] = func.section
            funcs[func.hash]["srcfile"] = func.srcfile
            funcs[func.hash]["lineno"] = func.lineno
            funcs[func.hash]["targets"] = func.targets
        return funcs


def main(
    filename,
    n=1,
    filter=None,
    filter_debug=False,
    min_insts=None,
    max_insts=None,
    byobj=False,
    byfunc=False,
    regs=False,
    regnorms=False,
    byfuncseqs=False,
    target=False,
    raw_funcs=False,
    max_imms=-1,
):
    sbf = StaticBinaryFeatures(
        filename,
        debug=filter_debug,
        include_regs=regs,
        normalize_registers=regnorms,
        max_imms=max_imms,
    )
    if raw_funcs:
        funcs = sbf.functions(max_insts, min_insts)
        # print(json.dumps(funcs, indent=2))
        with open(f"{filename}.json", "w") as outfile:
            json.dump(funcs, outfile, indent=2)
        # print(filename)
        return
    if byobj is False and byfunc is False and byfuncseqs is False:
        feats = sbf.features(n=n, filter=filter)
    elif byfunc or byfuncseqs:
        feats = sbf.features_per_function(
            n=n,
            filter=filter,
            min_insts=min_insts,
            max_insts=max_insts,
            sequence_feats=byfuncseqs,
            targets=target,
        )
    elif byobj:
        feats = sbf.features_per_object(n=n, filter=filter)
    if not filter_debug:
        print(json.dumps(feats, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument(
        "--byfunc",
        dest="byfunc",
        help="Use features by function instead of whole-program (default: False)",
        action="store_true",
    )
    parser.add_argument(
        "--byfuncseqs",
        dest="byfuncseqs",
        help="Use tokenized function inst sequence features (default: False)",
        action="store_true",
    )
    parser.add_argument(
        "--byobj",
        dest="byobj",
        help="Use features by object instead of whole-program (default: False)",
        action="store_true",
    )
    parser.add_argument(
        "--regs",
        dest="regs",
        help="Generate register-immediate features (default: False)",
        action="store_true",
    )
    parser.add_argument(
        "--regnorms",
        dest="regnorms",
        help="Normalize reg names, ie. %rax->%r_x (default: False)",
        action="store_true",
    )
    parser.add_argument(
        "--n",
        dest="n",
        help="n-gram length to use (default: 1)",
        default=1,
        type=int,
    )
    parser.add_argument(
        "--filter",
        dest="filter",
        help="section and function name regexp filter",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        help="section and function name regexp filter (debug)",
        action="store_true",
    )
    parser.add_argument(
        "--min_insts",
        dest="min_insts",
        help="for `byfunc` analysis, min instrs used per function (default: unlimited)",
        default=None,
        type=int,
    )
    parser.add_argument(
        "--max_insts",
        dest="max_insts",
        help="for `byfunc` analysis, max instrs used per function (default: unlimited)",
        default=None,
        type=int,
    )
    parser.add_argument(
        "--max_imms",
        dest="max_imms",
        help="maximum of immediate values to preserve",
        default=-1,
        type=int,
    )
    parser.add_argument(
        "--call_targets",
        dest="target",
        help="include call target information for each function",
        default=False,
        action="store_true"
    )
    parser.add_argument("--raw_funcs", dest="raw_funcs", action="store_true")
    args = parser.parse_args()
    main(
        args.binary,
        n=args.n,
        filter=args.filter,
        filter_debug=args.debug,
        min_insts=args.min_insts,
        max_insts=args.max_insts,
        byobj=args.byobj,
        byfunc=args.byfunc,
        regs=args.regs,
        regnorms=args.regnorms,
        byfuncseqs=args.byfuncseqs,
        target=args.target,
        raw_funcs=args.raw_funcs,
        max_imms=args.max_imms,
    )
