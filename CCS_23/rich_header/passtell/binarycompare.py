import argparse
import pandas as pd
import json
from sklearn.metrics import precision_recall_fscore_support

def count(df):
    count = 0
    countfuzzy = 0
    for idx, row in df.iterrows():
        localcount = 0
        localfuzzy = 0
        pred = json.loads(row.prediction.replace("'", '"'))
        truth = json.loads(row.comp.replace("'", '"'))
        # Keep only the ID for comparision
        pred = [entry[:8] for entry in pred]
        truth = [entry[:8] for entry in truth]
        predfuzzy = [r[4:8] for r in pred]
        truthfuzzy = [r[4:8] for r in truth]
        for entry in pred:
                if entry in truth:
                        localcount += 1
        if localcount == len(pred) and localcount == len(truth):
        # if localcount > (len(pred) / 2):
                count += 1
        else:
                print(hash, ": ")
                print("prediction: ", pred)
                print("truth: ", truth)
                print("Only in prediction: ")
                for entry in pred:
                        if not entry in truth:
                                print(entry)
                print("Only in truth:")
                for entry in truth:
                        if not entry in pred:
                                print(entry)
        predfuzzy = list(set(predfuzzy))
        truthfuzzy = list(set(truthfuzzy))
        for entry in predfuzzy:
                if entry in truthfuzzy:
                        localfuzzy += 1
        if localfuzzy == len(predfuzzy) and localfuzzy == len(truthfuzzy):
                # if localfuzzy >= len(predfuzzy) / 2:
                countfuzzy += 1
    return count, countfuzzy

def verifyDetection(df, fuzzy, fp_thres, fn_thres, verbose = False):
    resultList = []
    countFalse = 0
    fpPredict = 0
    fnPredict = 0
    tPredict = 0
    for _, row in df.iterrows():
        pred = json.loads(row["prediction"].replace("'", '"'))
        comp = json.loads(row["comp_test"])

        num_match = 0
        # Keep only the comp ID to tolerate different formats (e.g. "VS2017 build" vs "VS2017_build")
        # The fuzzy option merges the labels for C/C++ compilers of the same version (e.g., [ C ] VS2017 and [C++] VS2017)
        if fuzzy:
            pred = [p[4:8] for p in pred]
            comp = [p[4:8] for p in comp]
            pred = list(set(pred))
            comp = list(set(comp))
        else:
            pred = [p[0:8] for p in pred]
            comp = [p[0:8] for p in comp]
        for entry in pred:
            if entry in comp:
                num_match += 1
        score_c = num_match / len(comp)
        # If there is no prediction at all, just return false
        if len(pred) == 0:
            resultList.append(False)
            continue
        score_p = num_match / len(pred)
        result = score_c < fn_thres or score_p < fp_thres
        if not result == row["modified"]:
            if verbose:
                print("Mismatch: prediction: ", result, "; truth: ", row["modified"], "; comp_pred: ", pred, "; comp: ", row["comp"], "comp_test: ", row["comp_test"])
            countFalse += 1
            if row["modified"]:
                fnPredict += 1
            else:
                fpPredict += 1
        else:
            tPredict += 1
        resultList.append(result)
    resultDf = pd.DataFrame(resultList)
    precision, recall, f1, _ = precision_recall_fscore_support(
        resultDf, df["modified"], average="weighted"
    )
    precision = round(precision * 100, 2)
    recall = round(recall * 100, 2)
    f1 = round(f1 * 100, 2)
    if verbose:
        print("False positive: ", fpPredict, "; False negative: ", fnPredict, "; True: ", tPredict)
    return precision, recall, f1
    # print(f"LightGBM Precision: {precision}%, Recall: {recall}%, F1: {f1}%")
    # print("total false: ", countFalse)

def verifyGroundTruth(df: pd.DataFrame):
    count = 0
    for idx, row in df.iterrows():
        truth = json.loads(row.comp)
        claim = json.loads(row.comp_test)
        if set(truth) == set(claim) and row.modified:
            count += 1
            df.at[idx, "modified"] = False
    print("Corrected ", count, " false positives in ground truth")
    return df

    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "result_csv",
        type=str,
    )
    parser.add_argument(
        "verify_detection",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--fuzzy",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--fp",
        default=0.0,
        type=float
    )
    parser.add_argument(
        "--fn",
        default=0.9,
        type=float
    )

    parser.add_argument(
        "--test_score",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    df = pd.read_csv(args.result_csv)
    # Verify ground truth first
    df = verifyGroundTruth(df)
    print(count(df))
    if args.verify_detection:
        if not args.test_score:
            precision, recall, f1 = verifyDetection(df, args.fuzzy, args.fp, args.fn, True)
        else:
            bestF1 = 0
            precBest = 0
            recallBest = 0
            bestFuzzy = False
            bestFp = 0
            bestFn = 0
            for fuzzy in [True, False]:
                for fp_thres in [(x/10) for x in range(0,11)]:
                      for fn_thres in [(x/10) for x in range(0,11)]:
                            precision, recall, f1 = verifyDetection(df, fuzzy, fp_thres, fn_thres, False)
                            if f1 > bestF1:
                                bestF1 = f1
                                precBest = precision
                                recallBest = recall
                                bestFuzzy = fuzzy
                                bestFp = fp_thres
                                bestFn = fn_thres
            precision = precBest
            recall = recallBest
            f1 = bestF1
            print("Best scoring parameters: Fuzzy: ", bestFuzzy, "; fp_threshold: ", bestFp, "; fn_threshold: ", bestFn)
        print(f"LightGBM Precision: {precision}%, Recall: {recall}%, F1: {f1}%")