import networkx as nx
from networkx.algorithms.community import girvan_newman
from pathlib import Path
import pandas as pd
import json
from collections import defaultdict
import argparse
from tqdm import tqdm

def loadCsv(p: Path):
    df = pd.read_csv(p)
    passDict = {}
    G = nx.DiGraph()
    for _, row in df.iterrows():
        passDict[row['name']] = json.loads(row['pass'].replace("'", '"'))
        targets = json.loads(row['targets'].replace("'", '"'))
        for t in targets:
            G.add_edge(row['name'], t)
    return passDict, G

def verify(groups: list, passDict: dict, thresLocal: float) -> float:

    verifiedGroups = 0
    numGroups = 0

    groupSizeTotal = 0


    # We need to take consideration of group sizes where we award higher points
    # for large groups that are consistent
    maxGroupSize = 0
    for group in groups:
        if len(group) > maxGroupSize:
            maxGroupSize = len(group)
    
    for group in groups:
        passStatsDict = defaultdict(int)
        funcFound = 0
        count = 0
        for func in group:
            if not func in passDict:
                continue
            funcFound += 1
            for p in passDict[func]:
                passStatsDict[p] += 1
                count += 1
        # Ignore groups whose functions don't exist in passtell's result
        if len(passStatsDict) == 0:
            continue
        numGroups += 1
        # # Ignore single function group
        # if len(group) == 1:
        #     continue

        groupSizeTotal += len(group)
        # Terribly naive similarity comparison approach: 
        # sum(pass_count) / num_passes > thresLocal * num_funcs
        if count / len(passStatsDict) > thresLocal * funcFound:
            verifiedGroups += len(group)
    print("Score: ", verifiedGroups / groupSizeTotal)
    # if verifiedGroups / numGroups > thresGlobal:
    #     return True
    # return False
    return verifiedGroups / groupSizeTotal

def verifygirvanJson(dirPath: Path, filePrefix: str, passDict: dict, thresLocal: float, thresGlobal: float):
    i = 0
    scoreList = []
    while True:
        jsonPath = dirPath.joinpath(filePrefix + str(i) + ".json")
        if not jsonPath.exists():
            break
        with jsonPath.open() as file:
            groups = json.load(file)
        print("Verifying iteration ", i, "...")
        score = verify(groups, passDict, thresLocal)
        scoreList.append(score)
        # if verify(groups, passDict, thresLocal) > thresGlobal:
        #     return i
        i += 1
    i = 1
    maxDelta = 0
    maxIndex = 0
    while i < len(scoreList):
        if scoreList[i] - scoreList[i - 1] > maxDelta:
            maxDelta = scoreList[i] - scoreList[i - 1]
            maxIndex = i
        i += 1
    return maxIndex

def rungirvan(passDict: dict, G: nx.DiGraph, thresLocal: float, thresGlobal: float, outPath: Path, cacheDirPath: Path):
    communities = girvan_newman(G)
    i = 0
    for entry in communities:
        nodeGroups = []
        for com in entry:
            nodeGroups.append(list(com))
        score = verify(nodeGroups, passDict, thresLocal)
        if not cacheDirPath is None:
            with cacheDirPath.joinpath(str(i) + '_' + f"{score:.2f}" + '.json').open('w') as file:
                json.dump(nodeGroups, file)
        if score > thresGlobal:
            print("Stopping at Iteration ", i)
            with outPath.open('w') as file:
                json.dump(nodeGroups, file)
            break
        i += 1

def gengirvan(G: nx.DiGraph, cacheDirPath: Path):
    communities = girvan_newman(G)
    i = 0
    for entry in tqdm(communities):
        nodeGroups = []
        for com in entry:
            nodeGroups.append(list(com))
        if not cacheDirPath is None:
            # with cacheDirPath.joinpath(str(i) + '_' + f"{score:.2f}" + '.json').open('w') as file:
            #     json.dump(nodeGroups, file)
            with cacheDirPath.joinpath(str(i) + '.json').open('w') as file:
                json.dump(nodeGroups, file)
        i += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "result_csv",
        type=Path,
    )
    parser.add_argument(
        "mode",
        choices=["run_girvan", "parse_json", "gen_girvan"]
    )
    parser.add_argument(
        "--json_dir",
        type=Path,
    )

    parser.add_argument(
        "--json_prefix",
        type=str,
    )
    parser.add_argument(
        "--out_path",
        type=Path,
    )
    parser.add_argument(
        "--local_thres",
        default=0.8,
        type=float
    )
    parser.add_argument(
        "--global_thres",
        default=0.8,
        type=float
    )
    parser.add_argument(
        "--cache_iterations",
        default=None,
        type=Path,
    )
    parser.add_argument(
        "--subgraph",
        type=int,
        default=None,
        required=False
    )
    parser.add_argument(
        "--subgraph_json",
        type=Path,
        default=None,
    )

    args = parser.parse_args()
    passDict, G = loadCsv(args.result_csv)
    if not args.subgraph is None:
        with args.subgraph_json.open() as file:
            comm = json.load(file)
        G = G.subgraph(comm[args.subgraph])
    if not args.cache_iterations is None and not args.cache_iterations.exists():
        args.cache_iterations.mkdir()
    if args.mode == "parse_json":
        iter = verifygirvanJson(args.json_dir, args.json_prefix, passDict, args.local_thres, args.global_thres)
        print("Stopping iteration is: ", iter)
    elif args.mode == "run_girvan":
        rungirvan(passDict, G, args.local_thres, args.global_thres, args.out_path, args.cache_iterations)
    elif args.mode == "gen_girvan":
        gengirvan(G, args.cache_iterations)