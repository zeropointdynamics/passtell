import json
from pathlib import Path
from girvan_decompose import loadCsv
import argparse
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

COLORS = ["blue", "yellow", "green", "red"]

def check(groups: list, funcDict: dict, verbosity: int = 0):
    countMisses = 0
    numUnknown = 0
    numFuncInGroups = 0
    listNumFunc = []
    numMultiFuncGroups = 0
    libStats = defaultdict(int)
    successGroupStats = defaultdict(int)
    i = 0
    for group in groups:
        src = None
        miss = False
        for funcName in group:
            libname = None
            for lib in funcDict:
                if funcName in funcDict[lib]:
                    libname = lib
                    break
            if libname is None:
                libname = "unknown"
                numUnknown += 1
                if verbosity > 2:
                    print("Unknown function: ", funcName)
            if src is None:
                src = libname
            elif not src == libname:
                miss = True
            # Add library statistic count
            libStats[libname] += 1
        if miss:
            countMisses += 1
        else:
            # Ignore group of single function for now?
            if len(group) > 1:
                if verbosity > 1:
                    print("Group ", i, ": ", src)
                successGroupStats[src] += 1
                numFuncInGroups += len(group)
                listNumFunc.append(len(group))
                numMultiFuncGroups += 1
        i += 1
    if verbosity > 0:
        print("Function statistics: ", dict(libStats))
        print("Valid group statistics: ", dict(successGroupStats))
    numGoodGroup = len(groups) - countMisses
    return numGoodGroup, numMultiFuncGroups, numUnknown, numFuncInGroups / numMultiFuncGroups, listNumFunc[int(len(listNumFunc) / 2)]

def fuzzyLibMatch(groups: list, funcDict: dict, thres: float):
    successGroupStats = defaultdict(int)
    for group in groups:
        localStats = defaultdict(int)
        for funcName in group:
            found = False
            for lib in funcDict:
                if funcName in funcDict[lib]:
                    localStats[lib] += 1
                    found = True
                    break
            if not found:
                localStats["unknown"] += 1
        for libname in localStats:
            if localStats[libname] > len(group) * thres:
                successGroupStats[libname] += 1
    return successGroupStats

def mapGroupSrc(groups: list, funcDict: dict):
    output = []
    i = 0
    for group in groups:
        result = {'group':group, 'src':[], 'name':str(i)}
        for funcName in group:
            src = None
            for lib in funcDict:
                if funcName in funcDict[lib]:
                    src = lib
                    break
            if src is None:
                src = "unknown"
            if not src in result['src']:
                result['src'].append(src)
        output.append(result)
        i += 1
    return output
                    

def drawCommFigure(groups: list, funcDict: dict, csvPath: Path, outputPath: Path):
    _, G = loadCsv(csvPath)
    Ggroup = nx.DiGraph()
    groupSrcList = mapGroupSrc(groups, funcDict)
    for entry in groupSrcList:
        group = entry['group']
        srcList = entry['src']
        Ggroup.add_node(entry['name'], src=srcList)
        for funcName in group:
            for funcNameB in G.neighbors(funcName):
                for entryB in groupSrcList:
                    if entryB['name'] == entry['name']:
                        continue
                    if funcNameB in entryB['group']:
                        Ggroup.add_edge(entry['name'], entryB['name'])
    nx.draw(Ggroup, with_labels=False, pos=nx.spiral_layout(Ggroup))
    plt.savefig(outputPath)



def drawFigures(groups: list, funcDict: dict, csvPath: Path, outputDir: Path):
    _, G = loadCsv(csvPath)
    if not outputDir.exists():
        outputDir.mkdir(parents=True)
    i = 0
    for group in groups:
        plt.clf()
        subG = G.subgraph(group)
        # colorList = []
        # for node in subG:
        #     j = 0
        #     for lib in funcDict:
        #         if node in funcDict[lib]:
        #             colorList.append(COLORS[j])
        #             break
        #         j += 1
        # print(colorList)
        # nx.draw(subG, with_labels=True, pos=nx.spiral_layout(subG), node_color=colorList)
        nx.draw(subG, with_labels=True, pos=nx.spiral_layout(subG))
        plt.savefig(outputDir.joinpath(str(i) + '.png'))
        i += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "result_json",
        type=Path,
    )
    parser.add_argument(
        "func_dict_json",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--draw",
        type=Path,
        required=False,
        default=None,
    )
    parser.add_argument(
        "--csv",
        type=Path,
        required=False,
        default=None,
    )
    parser.add_argument(
        "--fuzzy_lib_match",
        type=float,
        default=0.0,
        required=False,
    )
    parser.add_argument(
        "--verbosity",
        type=int,
        default=0,
        required=False,
    )

    args = parser.parse_args()
    with args.result_json.open() as file:
        resultList = json.load(file)
    with args.func_dict_json.open() as file:
        funcDict = json.load(file)
    numCorrect, numMultiFuncCorrect, numUnknown, avgGroupLen, medianGroupLen = check(resultList, funcDict, args.verbosity)
    if not args.draw is None:
        # drawFigures(resultList, funcDict, args.csv, args.draw)
        drawCommFigure(resultList, funcDict, args.csv, args.draw)
    print("Result: ", numCorrect, "/", len(resultList), " (groups with more than one function: ", numMultiFuncCorrect, ")", " (with ", numUnknown, " unknown functions), Average group size for groups with multiple functions: ", avgGroupLen, ", Median: ", medianGroupLen)
    if args.fuzzy_lib_match > 0.0:
        fuzzyMatchDict = fuzzyLibMatch(resultList, funcDict, args.fuzzy_lib_match)
        print("Fuzzy matched libraries with threshold ", args.fuzzy_lib_match, ": ", dict(fuzzyMatchDict))