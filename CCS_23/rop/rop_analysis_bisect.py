import argparse
from collections import defaultdict
import glob
from inlining_rop_analysis import GadgetAnalyzer
from multiprocessing import Pool
import functools
from pathlib import Path
import json
from tqdm import tqdm
import re
import os
import pandas as pd

PASS_RE_PATTERN = "\[\d\d\d\d\-\d\d\-\d\d .+\] 0x[0-9a-fA-F]+ +Made Modification \'(.+)\' on Function \'(.+)\'\.\.\."

def getBisectInfo(num: int, dirPath: Path):
    passCountDict = defaultdict(int)
    projectsApplied = defaultdict(dict)
    # Go through each program
    for subPath in dirPath.iterdir():
        passNameDict = {}
        funcAddedList = []
        with subPath.joinpath('build_err.log').open() as file:
            i = 0
            passNum = -1
            mod_matcher = re.compile(PASS_RE_PATTERN)
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
                                passCountDict[passNameDict[funcName]] += 1
                                funcAddedList.append(funcName)
                            # del passNameDict[funcName]
                    elif passNum == num:
                        # If the previous line is the pass we want, then check if the pass modified
                        # the code
                        mod_result = mod_matcher.match(line)
                        if not mod_result is None:
                            if funcName == mod_result[2] and passNameDict[funcName] == mod_result[1]:
                                if not subPath.name in projectsApplied[passNameDict[funcName]]:
                                    projectsApplied[passNameDict[funcName]][subPath.name] = 1
                                else:
                                    projectsApplied[passNameDict[funcName]][subPath.name] += 1
                except Exception as e:
                    print("ERROR parsing file: ", subPath.as_posix(), ":", i)
                    print(e)
                    exit()
            # print(len(passNameDict), " functions have no data for ", subPath.as_posix(), ": ", passNameDict)
    return (passCountDict, projectsApplied)

def getBuildPath(i: int, inPath: Path):
    subPath = inPath.joinpath(str(i))
    if not subPath.is_dir():
        print("ERROR: Missing configuration #", i)
        return None
    buildPath = subPath.joinpath("built")
    return buildPath

def analyze_worker(i: int, inDir: Path, outDir: Path, filter: bool):
    pathA = getBuildPath(i, inDir).as_posix()
    pathB = getBuildPath(i + 1, inDir).as_posix()
    if pathA is None or pathB is None:
        return None
    ga = GadgetAnalyzer()
    # ga.analyze_by_pass(pathA, pathB, args.out_dir.as_posix(), outJsonName, args.filter, func_filter=True, bisect_num=(i + 1))
    findings, details = ga.analyze_by_pass(pathA, pathB, outDir.as_posix(), filter, func_filter=True, bisect_num=(i + 1))
    return (findings, details)

def getBisectInfoRunner(i: int, inPath: Path):
    buildPath = getBuildPath(i, inPath)
    if buildPath is None:
        return None
    (bisectDict, projsApplied) = getBisectInfo(i, buildPath)
    return (i, bisectDict, projsApplied)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "in_dir",
        help="build directory",
        type=Path,
    )
    parser.add_argument(
        "out_dir",
        help="output directory",
        type=Path,
    )
    parser.add_argument(
        "--exclude-o",
        dest="filter",
        help="exclude intermediate binary files such as .o and .bin",
        default=False,
        action="store_true",
    )
    args = parser.parse_args()

    # Bisect builds are named in numbers. Get the higheest number first
    maxConfigNum = int(max(glob.glob('*', root_dir=args.in_dir), key=int))

    # for i in range(1, maxConfigNum - 1):
    #     subPath = args.in_dir.joinpath(str(i))
    #     if not subPath.is_dir():
    #         print("ERROR: Missing configuration #", i)
    #         break
    #     buildPath = subPath.joinpath("built")
    #     bisectDict = getBisectInfo(buildPath)
    #     print('i == ', i, ': ')
    #     print(bisectDict)
    #     print()
    
    # Generate the distribution of bisected passes in parallel first
    passDistDict = {}
    projsAppliedDict = {}
    runner = functools.partial(getBisectInfoRunner, inPath=args.in_dir)
    print("Computing the distribution of passes in each iteration:")
    with Pool() as pool:
        results = pool.imap(runner, range(1, maxConfigNum + 1))
        for entry in tqdm(results, total=maxConfigNum):
            if entry is None:
                continue
            passDistDict[entry[0]] = entry[1]
            projsAppliedDict[entry[0]] = entry[2]
            # print('i == ', entry[0], ':')
            # print(entry[1], '\n')
    # Write distribution to JSON file
    with args.out_dir.joinpath('distribution.json').open('w') as file:
        json.dump(passDistDict, file)
    with args.out_dir.joinpath('dist_projects.json').open('w') as file:
        json.dump(projsAppliedDict, file)
    print("Done")
    
    # Generate the actual gadget analysis
    print("Performing gadget analysis:")
    runner = functools.partial(analyze_worker, inDir=args.in_dir, outDir=args.out_dir, filter=args.filter)
    with Pool() as pool:
        results = pool.imap(runner, range(1, maxConfigNum))
        for entry in tqdm(results, total=maxConfigNum):
            findings = entry[0]
            details = entry[1]
            for pass_name in findings:
                # Sanitize pass_name
                pass_filename = args.out_dir.as_posix() + '/' + pass_name.replace('/', '_').replace(' ', '_').replace('>', '') + '.csv'
                if os.path.exists(pass_filename):
                    orig_df = pd.read_csv(pass_filename)
                    findings_df = pd.concat([orig_df, pd.DataFrame(findings[pass_name])])
                else:
                    findings_df = pd.DataFrame(findings[pass_name])
                findings_df = findings_df.fillna(0)
                findings_df.to_csv(pass_filename, index=False)
                
            for pass_name in details:
                details_filename = args.out_dir.as_posix() + '/' + pass_name.replace('/', '_').replace(' ', '_').replace('>', '') + '.json'
                if os.path.exists(details_filename):
                    with open(details_filename, 'r') as file:
                        orig_details = json.load(file)
                    details_merged = orig_details + details[pass_name]
                else:
                    details_merged = details[pass_name]
                with open(details_filename, 'w') as file:
                    json.dump(details_merged, file)
    # for i in tqdm(range(1, maxConfigNum)):
    #     pathA = getBuildPath(i, args.in_dir).as_posix()
    #     pathB = getBuildPath(i + 1, args.in_dir).as_posix()
    #     if pathA is None or pathB is None:
    #         break
    #     # outCsvName = args.out_dir.joinpath(str(i) + '_' + str(i + 1) + '.csv').as_posix()
    #     # outJsonName = args.out_dir.joinpath(str(i) + '_' + str(i + 1) + '.json').as_posix()
    #     ga = GadgetAnalyzer()
    #     # ga.analyze_by_pass(pathA, pathB, args.out_dir.as_posix(), outJsonName, args.filter, func_filter=True, bisect_num=(i + 1))
    #     ga.analyze_by_pass(pathA, pathB, args.out_dir.as_posix(), args.filter, func_filter=True, bisect_num=(i + 1))
    print("Done")