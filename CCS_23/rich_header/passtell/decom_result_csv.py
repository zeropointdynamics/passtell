from girvan_decompose import loadCsv
from verify_decomposition_result import check
import argparse
from pathlib import Path
from csv import DictWriter
import json
from tqdm import tqdm

CSV_HEADER = ["iteration", "total_group", "correct_group", "correct_multifunction_group", "avg_multifunction_group_size", "median_multifunction_group_size", "pass_score"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "result_json_dir",
        type=Path,
    )
    parser.add_argument(
        "func_dict_json",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "csv",
        type=Path,
    )

    args = parser.parse_args()

    with args.func_dict_json.open() as file:
        funcDict = json.load(file)
    with args.csv.open("w") as csvfile:
        writer = DictWriter(csvfile, fieldnames=CSV_HEADER)
        writer.writeheader()
        jsonList = list(args.result_json_dir.rglob("*_*.json"))
        for subp in tqdm(jsonList):
            with subp.open() as file:
                resultList = json.load(file)
                numCorrect, numMultiFuncCorrect, numUnknown, avgGroupLen, medianGroupLen = check(resultList, funcDict, 0)
                row = {"iteration": subp.stem.split("_")[0], "total_group":len(resultList), "correct_group":numCorrect, "correct_multifunction_group":numMultiFuncCorrect, "avg_multifunction_group_size":avgGroupLen, "median_multifunction_group_size":medianGroupLen}
                if len(subp.stem.split("_")) > 1:
                    row["pass_score"] = subp.stem.split("_")[1]
                writer.writerow(row)