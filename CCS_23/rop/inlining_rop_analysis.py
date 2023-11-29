# Copyright 2022, Zeropoint
# Author(s): kzsnow
import argparse
import os
import pandas as pd
import warnings
import ntpath
import pprint 
from collections import defaultdict
warnings.simplefilter(action='ignore', category=FutureWarning)
import json
from tqdm import tqdm
import lief
import math
import subprocess
import re
from pathlib import Path

import ropper
from ropper import RopperService


class GadgetAnalyzer:

    def __init__(self):
        pass

    def percent_change(self, first, second):
        if first == 0:
            return 0
        change = 100 * (second - first) / first
        return round(change, 2)
    
    def get_function_boundaries(self, filename, intersting_function_list):
        result = subprocess.run(['llvm-objdump', '-d', filename], capture_output=True)
        disasm = result.stdout.decode('utf-8')
        output = []
        in_func = False
        prev_addr = -1
        for line in disasm.split('\n'):
            if '>:' in line:
                # Beginning of a function
                func_name = line.split(' <')[1].split('>:')[0]
                addr = int(line.split(' <')[0].replace(' ', ''), 16)
                if func_name in intersting_function_list:
                    output.append({'function':func_name, 'begin':addr})
                    in_func = True
                else:
                    in_func = False
            else:
                try:
                    if in_func:
                        output[-1]['end'] = int(line.split(':')[0].replace(' ', ''), 16)
                except:
                    pass
        return output
    
    def check_address_function(self, addr: int, func_list):
        for entry in func_list:
            if addr > entry['begin'] and addr < entry['end']:
                return entry['function']
        return None
    
    def get_bisect_info(self, num: int, bin_path: Path):
        function_applied = []
        current_path = bin_path.parent
        while not current_path.joinpath('build_err.log').exists():
            if current_path == current_path.parent:
                print("ERROR: Cannot find build log for ", bin_path.as_posix())
                return None
            current_path = current_path.parent

        passNameDict = {}
        funcAddedList = []
        with current_path.joinpath('build_err.log').open() as file:
            i = 0
            passNum = -1
            mod_matcher = re.compile("\[\d\d\d\d\-\d\d\-\d\d .+\] 0x[0-9a-fA-F]+ +Made Modification \'(.+)\' on Function \'(.+)\'\.\.\.")
            for line in file.readlines():
                i += 1
                try:
                    if "BISECT: " in line:
                        funcName = line.split(" on function (")[-1].split(')')[0]
                        # Skip functions that are already parsed
                        if funcName in funcAddedList:
                            continue
                        if "BISECT: running pass" in line and " on function " in line:
                            passName = line.split(") ", 1)[1].split(" on function (")[0]
                            passNum = int(line.split(")")[0].split("(")[1])
                            if passNum == num:
                                passNameDict[funcName] = passName
                                funcAddedList.append(funcName)
                            # del passNameDict[funcName]
                    elif passNum == num:
                        # If the previous line is the pass we want, then check if the pass modified
                        # the code
                        mod_result = mod_matcher.match(line)
                        if not mod_result is None:
                            if funcName == mod_result[2] and passNameDict[funcName] == mod_result[1]:
                                function_applied.append(funcName)
                except Exception as e:
                    print("ERROR parsing file: ", current_path.as_posix(), ":", i)
                    print(e)
                    exit()
                # print(len(passNameDict), " functions have no data for ", subPath.as_posix(), ": ", passNameDict)
        return (function_applied, passNameDict)
            
    
    def get_all_mirrored_files(self, dir, dir2):
        """ Returns list of (filepath, project_name)"""
        isFile = os.path.isfile(dir)
        isDirectory = os.path.isdir(dir)
        if not isFile and not isDirectory:
            return
        if not isDirectory:
            yield (dir,dir2,ntpath.basename(dir))
            return
        subfolders = [ f.path for f in os.scandir(dir) if f.is_dir() ]
        for subfolder in subfolders:
            for root, dirs, files in os.walk(subfolder):
                for file in files:
                    dir1_filename = os.path.join(root, file)
                    # FIXME: dir1/2 names need to be unique in the path for this to work, fine for now...
                    dir2_filename = os.path.join(root, file).replace(dir,dir2)
                    if not os.path.isfile(dir2_filename):
                        continue
                    yield (dir1_filename, dir2_filename, os.path.basename(os.path.normpath(subfolder)) )
    
    def is_useful_stack_pivot(self, gadget):
        # If the gadget starts with a return, then it's not useful
        if 'ret' in gadget.lines[0][2]:
            return False
        # If the gadget contains an exchange before any return, then it should
        # be useful
        for line in gadget.lines:
            if 'ret' in line[2]:
                return False
            if 'xchg' in line[2]:
                return True
        # Should never reach here, but if the gadget doesn't even contain a return,
        # then obviously it's a false
        return False
    
    def get_stack_pivot_reg(self, gadget):
        # NOTE: This function assumes that the gadget is a useful stack pivot gadget, as checked
        # by is_useful_stack_pivot(). 
        reg = None
        for line in gadget.lines:
            # Return the exchanged register in the last exchange instruction that involves rsp
            if 'xchg' in line[2]:
                regs = line[3].split(', ')
                # Sanity check
                if len(regs) < 2:
                    print("ERROR: Unexpected xchg instruction: ", line)
                    continue
                if 'sp' in regs[0]:
                    reg = regs[1]
                if 'sp' in regs[1]:
                    reg = regs[0]
            if 'ret' in line[2]:
                return reg
        # Should never reach here
        return None
    
    def get_gadget_distances(self, gadget_addrs: list, start_addr: int, end_addr: int):
        # Unit of distance: pages (4KB)
        distances = []
        distribution = defaultdict(int)
        # NOTE: This function assumes that gadget_addrs contains at least one element
        prev_addr = start_addr
        for addr in sorted(gadget_addrs):
            if addr > end_addr:
                break
            if addr < prev_addr:
                print("ERROR: Gadget before code segment! Gadget addr: ", hex(addr), "; code segment: ", hex(start_addr), "-", hex(end_addr))
                break
            distance = math.floor((addr - prev_addr) / 4096)
            # We don't really care if a single page contains multiple stack pivots
            if distance > 0:
                distances.append(distance)
                distribution[distance] += 1
            prev_addr = addr
        return (distances, distribution)

    def get_page_percentage(self, gadget_addrs: list, start_addr: int, end_addr: int):
        # Unit: pages
        distance_total = math.ceil((end_addr - start_addr) / 4096)
        pages_with_gadget = 0
        # Handle (normally impossible) div-by-0 edge case
        if end_addr - start_addr < 1:
            return -1
        prev_addr = start_addr - 4096
        for addr in sorted(gadget_addrs):
            if math.floor((addr - prev_addr) / 4096) > 0:
                pages_with_gadget += 1
            prev_addr = addr
        return (pages_with_gadget / distance_total)

    def analyze(self, dir1, dir2, output_filename, detail_out_filename, filter, func_filter = False, bisect_num = -1):
        pp = pprint.PrettyPrinter(indent=4)
        findings = []
        details = []
        for binary_filename,binary_filename2,project_name in tqdm(self.get_all_mirrored_files(dir1, dir2)):
            binary_shortname = ntpath.basename(binary_filename)
            if filter and (binary_shortname.split('.')[-1] == 'o' or binary_shortname.split('.')[-1] == 'bin' or binary_shortname == 'a.out'):
                continue
            try:
                rs = RopperService()
                rs.addFile(binary_filename)
                rs.addFile(binary_filename2)
            except:
                continue
            # Get the list of interesting functions
            if func_filter:
                applied_function_list, _ = self.get_bisect_info(bisect_num, Path(binary_filename2))
                function_list0 = self.get_function_boundaries(binary_filename, applied_function_list)
                function_list1 = self.get_function_boundaries(binary_filename2, applied_function_list)
                function_list = [function_list0, function_list1]
                func_size0 = 0
                for entry in function_list0:
                    func_size0 += (entry['end'] - entry['begin'])
                func_size1 = 0
                for entry in function_list1:
                    func_size1 += (entry['end'] - entry['begin'])
            cat_cnts = [defaultdict(int), defaultdict(int)]
            for i,binname in enumerate([binary_filename, binary_filename2]):
                rs = RopperService()
                rs.options.multiprocessing = True
                rs.addFile(binname)
                detail_gadgets = defaultdict(list)
                stack_pivot_regs = []
                stack_pivot_addrs = []
                for t in ["rop","jop","sys"]:#,"all"]:
                    rs.options.type = t
                    rs.loadGadgetsFor()
                    gadgets = rs.getFileFor(name=binname).gadgets
                    gadget_len = 0
                    if gadgets is not None:
                        gadget_len = len(gadgets)
                    # print(binary_shortname, f"{t}_{i}", gadget_len)
                    cat_cnts[i][f"{t}_TOTAL"] = gadget_len
                    detail_gadgets[t] = {}
                    for g in gadgets:
                        if func_filter and self.check_address_function(g.address, function_list[i]) is None:
                            continue
                        category = g.category[0]
                        if category != ropper.gadget.Category.NONE:
                            cat_cnts[i][f"{t}_SEMANTIC"] += 1
                            # stack pivot is handled below
                            if not category == ropper.gadget.Category.STACK_PIVOT:
                                if not str(category) in detail_gadgets[t]:
                                    detail_gadgets[t][str(category)] = []
                                detail_gadgets[t][str(category)].append(str(g))
                        # Special case for stack pivot since Ropper seems to include "ret #IMM#"
                        # as valid stack pivot gadgets, but they are not that useful
                        if category == ropper.gadget.Category.STACK_PIVOT:
                            if self.is_useful_stack_pivot(g):
                                cat_cnts[i][f"{t}_{category}_USEFUL"] += 1
                                if not str(category) + "_USEFUL" in detail_gadgets[t]:
                                    detail_gadgets[t][str(category) + "_USEFUL"] = []
                                detail_gadgets[t][str(category) + "_USEFUL"].append(str(g))
                                reg = self.get_stack_pivot_reg(g)
                                if not reg is None and not reg in stack_pivot_regs:
                                    stack_pivot_regs.append(reg)
                                # Store the address of the beginning of the gadget
                                if not g.address in stack_pivot_addrs:
                                    stack_pivot_addrs.append(g.address)
                            else:
                                cat_cnts[i][f"{t}_{category}_RET_ONLY"] += 1
                                if not str(category) + "_RET_ONLY" in detail_gadgets[t]:
                                        detail_gadgets[t][str(category) + "_RET_ONLY"] = []
                                detail_gadgets[t][str(category) + "_RET_ONLY"].append(str(g))
                        else:
                            cat_cnts[i][f"{t}_{category}"] += 1
                        # print("Gadget Category:", g.category[0], "\t", g)
                cat_cnts[i][f"rop_STACK_PIVOT_REG_NUM"] = len(stack_pivot_regs)
                # Compute the number of pages needed to find a stack pivot
                binary = lief.parse(binname)
                start_addr = -1
                end_addr = -1
                for segment in binary.segments:
                    if int(segment.flags) % 2 == 1:
                        # Executable segment
                        if start_addr > 0:
                            print("ERROR: Multiple executable segments!")
                            exit()
                        start_addr = segment.virtual_address
                        end_addr = segment.virtual_address + segment.virtual_size
                distances, dist_distribution = self.get_gadget_distances(stack_pivot_addrs, start_addr, end_addr)
                percentage = self.get_page_percentage(stack_pivot_addrs, start_addr, end_addr)
                if len(distances) == 0:
                    cat_cnts[i][f"rop_STACK_PIVOT_MAX_DISTANCE"] = 'NULL'
                    cat_cnts[i][f"rop_STACK_PIVOT_AVG_DISTANCE"] = 'NULL'
                    cat_cnts[i][f"rop_STACK_PIVOT_PAGES_AFTER_LAST_GADGET"] = 'NULL'
                else:
                    cat_cnts[i][f"rop_STACK_PIVOT_MAX_DISTANCE"] = max(distances)
                    cat_cnts[i][f"rop_STACK_PIVOT_AVG_DISTANCE"] = sum(distances) / len(distances)
                    cat_cnts[i][f"rop_STACK_PIVOT_PAGES_AFTER_LAST_GADGET"] = end_addr - max(stack_pivot_addrs)
                if percentage == -1:
                    cat_cnts[i][f"rop_STACK_PIVOT_PAGE_PERCENTAGE"] = 'NULL'
                else:
                    cat_cnts[i][f"rop_STACK_PIVOT_PAGE_PERCENTAGE"] = percentage
                # Generate details for JSON
                details.append({'project_name':project_name, 'binary_name':binary_shortname,
                    'filename':binname, 'gadgets':detail_gadgets, 'stack_pivot_regs':stack_pivot_regs,
                    'stack_pivot_distances':distances, 'stack_pivot_distribution':dist_distribution})
            # pp.pprint(cat_cnts)
            # Get file size for ratio calculation
            size_0 = os.path.getsize(binary_filename)
            size_1 = os.path.getsize(binary_filename2)
            if func_filter:
                size_0 = func_size0
                size_1 = func_size1
                if size_0 == 0:
                    # If there is no function then everything should be 0 anyway
                    size_0 = 1
                if size_1 == 0:
                    size_1 = 1
            # Compute the ratios
            if cat_cnts[0]["rop_TOTAL"] > 0:
                cat_cnts[0]["rop_STACK_PIVOT_TOTAL_RATIO"] = cat_cnts[0]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[0]["rop_TOTAL"]
            else:
                cat_cnts[0]["rop_STACK_PIVOT_TOTAL_RATIO"] = 0
            if cat_cnts[0]["rop_SEMANTIC"] > 0:
                cat_cnts[0]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = cat_cnts[0]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[0]["rop_SEMANTIC"]
            else:
                cat_cnts[0]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = 0
            cat_cnts[0]["rop_STACK_PIVOT_PAGE_RATIO"] = cat_cnts[0]["rop_STACK_PIVOT_USEFUL"] / math.ceil(size_0 / 4096)
            if cat_cnts[1]["rop_TOTAL"] > 0:
                cat_cnts[1]["rop_STACK_PIVOT_TOTAL_RATIO"] = cat_cnts[1]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[1]["rop_TOTAL"]
            else:
                cat_cnts[1]["rop_STACK_PIVOT_TOTAL_RATIO"] = 0
            if cat_cnts[1]["rop_SEMANTIC"] > 0:
                cat_cnts[1]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = cat_cnts[1]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[1]["rop_SEMANTIC"]
            else:
                cat_cnts[1]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = 0
            cat_cnts[1]["rop_STACK_PIVOT_PAGE_RATIO"] = cat_cnts[1]["rop_STACK_PIVOT_USEFUL"] / math.ceil(size_1 / 4096)
            diffs = {}
            for cat in cat_cnts[0].keys():
                if cat_cnts[0][cat] == "NULL" or cat_cnts[1][cat] == "NULL":
                    diffs[f"gain_{cat}_gain"] = "NULL"
                    diffs[f"pct__{cat}"] = "NULL"
                    continue
                diffs[f"gain_{cat}_gain"] = cat_cnts[1][cat] - cat_cnts[0][cat]
                diffs[f"pct__{cat}"] = self.percent_change(cat_cnts[0][cat], cat_cnts[1][cat])
            # pp.pprint(diffs)
            finding = {}
            cat_cnts0 = {str(key) + "_0": val for key, val in cat_cnts[0].items()}
            cat_cnts1 = {str(key) + "_1": val for key, val in cat_cnts[1].items()}
            finding.update({
                "project_name": project_name,
                "binary_name": binary_shortname,
                "config_0": dir1,
                "config_1": dir2,
            })
            finding.update(cat_cnts0)
            finding.update(cat_cnts1)
            finding.update(diffs)
            findings.append(finding)
        findings_df = pd.DataFrame(findings)
        findings_df = findings_df.fillna(0)
        print(findings_df)
        findings_df.to_csv(output_filename, index=False)
        if not detail_out_filename is None:
            with open(detail_out_filename, 'w') as file:
                json.dump(details, file)

    def analyze_by_pass(self, dir1, dir2, output_dirname, filter, func_filter = False, bisect_num = -1):
        pp = pprint.PrettyPrinter(indent=4)
        findings = defaultdict(list)
        details = defaultdict(list)
        # This mode requires func_filter to be enabled
        if not func_filter:
            print("ERROR: Pass level analysis requires function filter!")
            return
        for binary_filename,binary_filename2,project_name in tqdm(self.get_all_mirrored_files(dir1, dir2)):
            binary_shortname = ntpath.basename(binary_filename)
            if filter and (binary_shortname.split('.')[-1] == 'o' or binary_shortname.split('.')[-1] == 'bin' or binary_shortname == 'a.out'):
                continue
            try:
                rs = RopperService()
                rs.addFile(binary_filename)
                rs.addFile(binary_filename2)
            except:
                continue
            # Get the list of interesting functions
            if func_filter:
                applied_function_list, func_pass_dict = self.get_bisect_info(bisect_num, Path(binary_filename2))
                function_list0 = self.get_function_boundaries(binary_filename, applied_function_list)
                function_list1 = self.get_function_boundaries(binary_filename2, applied_function_list)
                function_list = [function_list0, function_list1]
                func_size0 = 0
                for entry in function_list0:
                    func_size0 += (entry['end'] - entry['begin'])
                func_size1 = 0
                for entry in function_list1:
                    func_size1 += (entry['end'] - entry['begin'])
            # cat_cnts = [defaultdict(int), defaultdict(int)]
            cat_cnts = {}
            for i,binname in enumerate([binary_filename, binary_filename2]):
                rs = RopperService()
                rs.options.multiprocessing = False
                rs.addFile(binname)
                detail_gadgets = defaultdict(list)
                stack_pivot_regs = []
                stack_pivot_addrs = []
                for t in ["rop","jop","sys"]:#,"all"]:
                    rs.options.type = t
                    rs.loadGadgetsFor()
                    gadgets = rs.getFileFor(name=binname).gadgets
                    gadget_len = 0
                    if gadgets is not None:
                        gadget_len = len(gadgets)
                    # print(binary_shortname, f"{t}_{i}", gadget_len)
                    # cat_cnts[i][f"{t}_TOTAL"] = gadget_len
                    detail_gadgets[t] = {}
                    for g in gadgets:
                        func_name = self.check_address_function(g.address, function_list[i])
                        if not func_filter or not(func_name is None):
                            if not func_name in cat_cnts:
                                cat_cnts[func_name] = [defaultdict(int), defaultdict(int)]
                        category = g.category[0]
                        if category != ropper.gadget.Category.NONE:
                            if not func_filter or not(func_name is None):
                                cat_cnts[func_name][i][f"{t}_SEMANTIC"] += 1
                            # stack pivot is handled below
                            if not category == ropper.gadget.Category.STACK_PIVOT:
                                if not str(category) in detail_gadgets[t]:
                                    detail_gadgets[t][str(category)] = []
                                detail_gadgets[t][str(category)].append(str(g))
                        # Special case for stack pivot since Ropper seems to include "ret #IMM#"
                        # as valid stack pivot gadgets, but they are not that useful
                        if category == ropper.gadget.Category.STACK_PIVOT:
                            if self.is_useful_stack_pivot(g):
                                if not func_filter or not(func_name is None):
                                    cat_cnts[func_name][i][f"{t}_{category}_USEFUL"] += 1
                                if not str(category) + "_USEFUL" in detail_gadgets[t]:
                                    detail_gadgets[t][str(category) + "_USEFUL"] = []
                                detail_gadgets[t][str(category) + "_USEFUL"].append(str(g))
                                reg = self.get_stack_pivot_reg(g)
                                if not reg is None and not reg in stack_pivot_regs:
                                    stack_pivot_regs.append(reg)
                                # Store the address of the beginning of the gadget
                                if not g.address in stack_pivot_addrs:
                                    stack_pivot_addrs.append(g.address)
                            else:
                                if not func_filter or not(func_name is None):
                                    cat_cnts[func_name][i][f"{t}_{category}_RET_ONLY"] += 1
                                if not str(category) + "_RET_ONLY" in detail_gadgets[t]:
                                        detail_gadgets[t][str(category) + "_RET_ONLY"] = []
                                detail_gadgets[t][str(category) + "_RET_ONLY"].append(str(g))
                        else:
                            if not func_filter or not(func_name is None):
                                cat_cnts[func_name][i][f"{t}_{category}"] += 1
                        # print("Gadget Category:", g.category[0], "\t", g)
                # cat_cnts[i][f"rop_STACK_PIVOT_REG_NUM"] = len(stack_pivot_regs)
                # Compute the number of pages needed to find a stack pivot
                binary = lief.parse(binname)
                start_addr = -1
                end_addr = -1
                for segment in binary.segments:
                    if int(segment.flags) % 2 == 1:
                        # Executable segment
                        if start_addr > 0:
                            print("ERROR: Multiple executable segments!")
                            exit()
                        start_addr = segment.virtual_address
                        end_addr = segment.virtual_address + segment.virtual_size
                distances, dist_distribution = self.get_gadget_distances(stack_pivot_addrs, start_addr, end_addr)
                percentage = self.get_page_percentage(stack_pivot_addrs, start_addr, end_addr)
                # These fields are included only for compatibility
                for func_name in cat_cnts:
                    if len(distances) == 0:
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_MAX_DISTANCE"] = 'NULL'
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_AVG_DISTANCE"] = 'NULL'
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_PAGES_AFTER_LAST_GADGET"] = 'NULL'
                    else:
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_MAX_DISTANCE"] = max(distances)
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_AVG_DISTANCE"] = sum(distances) / len(distances)
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_PAGES_AFTER_LAST_GADGET"] = end_addr - max(stack_pivot_addrs)
                    if percentage == -1:
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_PAGE_PERCENTAGE"] = 'NULL'
                    else:
                        cat_cnts[func_name][i][f"rop_STACK_PIVOT_PAGE_PERCENTAGE"] = percentage
                    # Generate details for JSON
                    try:
                        details[func_pass_dict[func_name]].append({'project_name':project_name, 'binary_name':binary_shortname,
                            'filename':binname, 'function':func_name, 'gadgets':detail_gadgets, 'stack_pivot_regs':stack_pivot_regs,
                            'stack_pivot_distances':distances, 'stack_pivot_distribution':dist_distribution})
                    except:
                        print("ERROR on ", func_name, ' with pass ')
                        exit()
                
                    # Get file size for ratio calculation
                    # If there is no function then everything should be 0 anyway
                    size_0 = 1
                    size_1 = 1
                    for entry in function_list0:
                        if entry['function'] == func_name:
                            size_0 = entry['end'] - entry['begin']
                        if size_0 == 0:
                            size_0 = 1
                    for entry in function_list1:
                        if entry['function'] == func_name:
                            size_1 = entry['end'] - entry['begin']
                        if size_1 == 0:
                            size_1 = 1
                    # Compute the ratios
                    if cat_cnts[func_name][0]["rop_TOTAL"] > 0:
                        cat_cnts[func_name][0]["rop_STACK_PIVOT_TOTAL_RATIO"] = cat_cnts[func_name][0]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[func_name][0]["rop_TOTAL"]
                    else:
                        cat_cnts[func_name][0]["rop_STACK_PIVOT_TOTAL_RATIO"] = 0
                    if cat_cnts[func_name][0]["rop_SEMANTIC"] > 0:
                        cat_cnts[func_name][0]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = cat_cnts[func_name][0]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[func_name][0]["rop_SEMANTIC"]
                    else:
                        cat_cnts[func_name][0]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = 0
                    cat_cnts[func_name][0]["rop_STACK_PIVOT_PAGE_RATIO"] = cat_cnts[func_name][0]["rop_STACK_PIVOT_USEFUL"] / math.ceil(size_0 / 4096)
                    if cat_cnts[func_name][1]["rop_TOTAL"] > 0:
                        cat_cnts[func_name][1]["rop_STACK_PIVOT_TOTAL_RATIO"] = cat_cnts[func_name][1]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[func_name][1]["rop_TOTAL"]
                    else:
                        cat_cnts[func_name][1]["rop_STACK_PIVOT_TOTAL_RATIO"] = 0
                    if cat_cnts[func_name][1]["rop_SEMANTIC"] > 0:
                        cat_cnts[func_name][1]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = cat_cnts[func_name][1]["rop_STACK_PIVOT_USEFUL"] / cat_cnts[func_name][1]["rop_SEMANTIC"]
                    else:
                        cat_cnts[func_name][1]["rop_STACK_PIVOT_SEMANTIC_RATIO"] = 0
                    cat_cnts[func_name][1]["rop_STACK_PIVOT_PAGE_RATIO"] = cat_cnts[func_name][1]["rop_STACK_PIVOT_USEFUL"] / math.ceil(size_1 / 4096)
                    diffs = {}
                    for cat in cat_cnts[func_name][0].keys():
                        if cat_cnts[func_name][0][cat] == "NULL" or cat_cnts[func_name][1][cat] == "NULL":
                            diffs[f"gain_{cat}_gain"] = "NULL"
                            diffs[f"pct__{cat}"] = "NULL"
                            continue
                        diffs[f"gain_{cat}_gain"] = cat_cnts[func_name][1][cat] - cat_cnts[func_name][0][cat]
                        diffs[f"pct__{cat}"] = self.percent_change(cat_cnts[func_name][0][cat], cat_cnts[func_name][1][cat])
                    # pp.pprint(diffs)
                    finding = {}
                    cat_cnts0 = {str(key) + "_0": val for key, val in cat_cnts[func_name][0].items()}
                    cat_cnts1 = {str(key) + "_1": val for key, val in cat_cnts[func_name][1].items()}
                    finding.update({
                        "project_name": project_name,
                        "binary_name": binary_shortname,
                        "function_name": func_name,
                        "config_0": dir1,
                        "config_1": dir2,
                    })
                    if func_filter:
                        finding.update({"pass_index": bisect_num})
                    finding.update(cat_cnts0)
                    finding.update(cat_cnts1)
                    finding.update(diffs)
                    findings[func_pass_dict[func_name]].append(finding)
        return (findings, details)
        # for pass_name in findings:
        #     # Sanitize pass_name
        #     pass_filename = output_dirname + '/' + pass_name.replace('/', '_').replace(' ', '_').replace('>', '') + '.csv'
        #     if os.path.exists(pass_filename):
        #         orig_df = pd.read_csv(pass_filename)
        #         findings_df = pd.concat([orig_df, pd.DataFrame(findings[pass_name])])
        #     else:
        #         findings_df = pd.DataFrame(findings[pass_name])
        #     findings_df = findings_df.fillna(0)
        #     findings_df.to_csv(pass_filename, index=False)
            
        # for pass_name in details:
        #     details_filename = output_dirname + '/' + pass_name.replace('/', '_').replace(' ', '_').replace('>', '') + '.json'
        #     if os.path.exists(details_filename):
        #         with open(details_filename, 'r') as file:
        #             orig_details = json.load(file)
        #         details_merged = orig_details + details[pass_name]
        #     else:
        #         details_merged = details[pass_name]
        #     with open(details_filename, 'w') as file:
        #         json.dump(details_merged, file)


if __name__ == "__main__":
    """
    Given two directories with identical structure and binaries built with differing
    compile options (i.e. inline vs. noinline, etc.), perform a ROP gadget search
    on each of the two binary variations.
    
    For each binary comparison, save the following
    information for BIN_A and BIN_B:
      Count of gadgets: pivot,rop,jop,syscall,all
    
    And save the following information for BIN_RELATIVE
    % increase from BIN_A to BIN_B of:
      % increase of gadgets: pivot,rop,jop,syscall,all
    
    Ignore any binaries that don't appear in BOTH directory structures.

    Usage:
      inlining_rop_analysis.py --dir1 XXX --dir2 YYY --output results.csv (--detail-output details.json)
    
    Results file has the following columns:
      project_name, binary_name, a_pivot, a_rop, a_jop, a_syscall, a_all, b_pivot, b_rop, b_jop, b_syscall, b_all, gain_pivot, gain_rop, gain_jop, gain_syscall, gain_all 
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dir1",
        dest="dir1",
        help="first dir",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--dir2",
        dest="dir2",
        help="second dir",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--output",
        dest="output",
        help="output csv filename",
        default="output.csv",
        type=str,
    )
    parser.add_argument(
        "--detail-output",
        dest="detail",
        help="gadget details in JSON format",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--exclude-o",
        dest="filter",
        help="exclude intermediate binary files such as .o and .bin",
        default=False,
        action="store_true",
    )
    args = parser.parse_args()
    if args.dir1 is None or args.dir2 is None:
        print("Usage: python3 inlining_rop_analysis.py --dir1 XXX --dir2 YYY --output results.csv")
    else:
        ga = GadgetAnalyzer()
        ga.analyze(args.dir1, args.dir2, args.output, args.detail, args.filter)
