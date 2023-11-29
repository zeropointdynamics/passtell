import networkx as nx
from networkx.algorithms.community import greedy_modularity_communities, asyn_lpa_communities, louvain_communities
from pathlib import Path
import pandas as pd
import json
from collections import defaultdict
import argparse
from girvan_decompose import loadCsv, verify

ALGORITHM_LIST = {"Greedy Modularity Communities": greedy_modularity_communities, 
                  "Asynchronous Label Propagation": asyn_lpa_communities, 
                  "Louvain Community Detection": louvain_communities}

def verifyAlgorithm(algorithm, name: str, G: nx.DiGraph, passDict: dict, thresLocal: float, outDirPath: Path):
    communities = algorithm(G)
    nodeGroups = []
    for com in communities:
        nodeGroups.append(list(com))
    if not outDirPath is None:
        with outDirPath.joinpath(name.replace(" ", "_") + ".json").open('w') as file:
            json.dump(nodeGroups, file)
    return verify(nodeGroups, passDict, thresLocal)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "result_csv",
        type=Path,
    )
    parser.add_argument(
        "--out_path",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--local_thres",
        default=0.8,
        type=float
    )

    args = parser.parse_args()
    passDict, G = loadCsv(args.result_csv)

    bestAlgo = None
    bestScore = -1.0
    for algoName in ALGORITHM_LIST:
        score = verifyAlgorithm(ALGORITHM_LIST[algoName], algoName, G, passDict, args.local_thres, args.out_path)
        print(algoName, ": ", score)
        if score > bestScore:
            bestAlgo = algoName
            bestScore = score
    print("Best Algorithm: ", bestAlgo, "; score: ", bestScore)