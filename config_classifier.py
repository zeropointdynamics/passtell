# Copyright 2022, Zeropoint
# Author(s): Kevin Snow, Ryan Court, Yufei Du
import json
import datetime
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.tree import export_graphviz
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    precision_recall_fscore_support,
)
from supervised.automl import AutoML


def load_data(filename="balanced_dataset.csv"):
    df = pd.read_csv(filename, index_col=0)
    return df


def plot_decision_tree(tree, feature_labels, filename="ml_tree"):
    import pydot
    export_graphviz(
        tree,
        out_file=filename + ".dot",
        feature_names=feature_labels,
        rounded=True,
        precision=1,
    )
    (graph,) = pydot.graph_from_dot_file(filename + ".dot")
    graph.write_png(filename + ".png")
    print("The depth of this tree is:", tree.tree_.max_depth)


def feature_importance(tree, feature_labels):
    # Get numerical feature importances
    importances = list(tree.feature_importances_)
    # List of tuples with variable and importance
    feature_importances = [
        (feature, round(importance, 2))
        for feature, importance in zip(feature_labels, importances)
    ]
    # Sort the feature importances by most important first
    feature_importances = sorted(
        feature_importances, key=lambda x: x[1], reverse=True
    )
    # Print out the feature and importances
    [
        print("Variable: {:20} Importance: {}".format(*pair))
        for pair in feature_importances
    ]
    # print([pair[0] for pair in feature_importances if pair[1] == 0])
    has_importance = [pair[0] for pair in feature_importances if pair[1] != 0]
    print("Num important:", len(has_importance))
    print(has_importance)
    return has_importance


def get_stats(df, min_cnt=None):
    stats = {
        "opcodes": defaultdict(
            int
        ),  # Total count of this opcode used throughout
        "regs": defaultdict(int),
        "insts": defaultdict(int),
        "has_opcode": defaultdict(
            int
        ),  # Total count of functions with this opcode
        "has_reg": defaultdict(int),
        "has_inst": defaultdict(int),
        "has_inst_2grams": defaultdict(int),
        "has_inst_3grams": defaultdict(int),
        "has_inst_4grams": defaultdict(int),
        "has_opcode_2grams": defaultdict(int),
        # "sample_counts_with_opcode": defaultdict(int),
        # "sample_counts_with_reg": defaultdict(int),
        # "sample_counts_with_inst": defaultdict(int),
    }
    for index, row in df.iterrows():
        has_opcode = set()
        has_reg = set()
        has_inst = set()
        insts = row.insts.split(" ; ")
        for i, inst in enumerate(insts):
            if len(insts) > i + 1:
                stats["has_inst_2grams"][f"{inst} : {insts[i+1]}"] += 1
                stats["has_opcode_2grams"][
                    f"{inst.split(' ')[0]} : {insts[i+1].split(' ')[0]}"
                ] += 1
            # if len(insts) > i + 2:
            #     stats["has_inst_3grams"][
            #         f"{inst} : {insts[i+1]} : {insts[i+2]}"
            #     ] += 1
            # if len(insts) > i + 3:
            #     stats["has_inst_4grams"][
            #         f"{inst} : {insts[i+1]} : {insts[i+2]} : {insts[i+3]}"
            #     ] += 1
            stats["insts"][inst] += 1
            has_inst.add(inst)
            parts = inst.split(" ")
            opcode = parts[0]
            stats["opcodes"][opcode] += 1
            has_opcode.add(opcode)
            for operand in parts[1:]:
                if not operand.startswith("%"):
                    continue
                stats["regs"][operand[1:]] += 1
                has_reg.add(operand[1:])
        for opcode in has_opcode:
            stats["has_opcode"][opcode] += 1
        for reg in has_reg:
            stats["has_reg"][reg] += 1
        for inst in has_inst:
            stats["has_inst"][inst] += 1
    for name in stats.keys():
        stats[name] = dict(
            sorted(stats[name].items(), key=lambda item: item[1], reverse=True)
        )
        # if min_cnt is not None:
        #     for key, value in dict(stats[name]).items():
        #         if value < min_cnt:
        #             del stats[name][key]
    # print(json.dumps(stats, indent=2))
    return stats


def split_by_compiler(df):
    icc = df[df.compiler.str.startswith("icc")]
    return {
        "clang": df[df.compiler.str.startswith("clang")].sample(
            n=len(icc), random_state=1
        ),
        "gcc": df[df.compiler.str.startswith("gcc")].sample(
            n=len(icc), random_state=1
        ),
        "icc": icc,
    }


def split_by_compiler_version(df):
    return {
        "clang-3.8": df[df.compiler.str.startswith("clang-3.8")],
        "clang-5.0": df[df.compiler.str.startswith("clang-5.0")],
        "gcc-4": df[df.compiler.str.startswith("gcc-4")],
        "gcc-6": df[df.compiler.str.startswith("gcc-6")],
        "icc-19": df[df.compiler.str.startswith("icc-19")],
    }


def split_by_opt(df):
    return {
        "O0": df[df.opt.str.startswith("O0")],
        "O1": df[df.opt.str.startswith("O1")],
        "OH": df[df.opt.str.startswith("OH")],
    }


def do_stacked_bar_plot(df, outfilename):
    df["Total"] = df.sum(axis=1)
    print(df)
    for col in df.columns:
        if col == "Total":
            continue
        df[col] = df[col].div(df["Total"])
    print(df)
    df.drop("Total", axis=1).head(100).plot.barh(
        figsize=(20, 20), stacked=True, color=["#BB0000", "#0000BB", "green"]
    ).figure.savefig(outfilename)


def format_samples(data):
    labels = np.array(data["label"])
    features = data.drop("label", axis=1)
    features = pd.get_dummies(features)
    feature_labels = list(features.columns)
    # features = np.array(features)
    return labels, features, feature_labels


def do_decisiontree(samples):
    labels, features, feature_labels = format_samples(samples)
    # (
    #     train_features,
    #     test_features,
    #     train_labels,
    #     test_labels,
    # ) = train_test_split(features, labels, test_size=0.25, random_state=42)
    # print("Training Features Shape:", train_features.shape)
    # print("Training Labels Shape:", train_labels.shape)
    # print("Testing Features Shape:", test_features.shape)
    # print("Testing Labels Shape:", test_labels.shape)

    # rf = RandomForestClassifier()
    rf = AutoML(
        mode="Compete",
        total_time_limit=3600 * 3,
        eval_metric="f1",
        validation_strategy={
            # "validation_type": "kfold",
            # "k_folds": 2,
            "validation_type": "split",
            "train_ratio": 0.75,
            "shuffle": True,
            "stratify": True,
            "random_seed": 123,
        },
        stack_models=True,
        explain_level=2,
        algorithms=["LightGBM"],
    )
    rf.fit(features, labels)

def do_decision_tree_analysis():
    df = load_data()
    global_stats = get_stats(df, min_cnt=100)
    opcode_labels = list(global_stats["has_opcode"].keys())  # [:100]
    inst_labels = list(global_stats["has_inst"].keys())[:1000]
    reg_labels = list(global_stats["has_reg"].keys())  # [:100]
    ngrams_labels = list(global_stats["has_inst_2grams"].keys())[:1000]
    ngrams3_labels = list(global_stats["has_inst_3grams"].keys())[:1000]
    ngrams4_labels = list(global_stats["has_inst_4grams"].keys())[:1000]
    opcode_ngrams_labels = list(global_stats["has_opcode_2grams"].keys())[
        :1000
    ]
    # print(opcode_labels)

    samples = []
    for index, row in df.iterrows():
        sample = {
            "label": row.opt[:2],
        }
        optimization = row.opt[:2]
        if row.compiler.startswith("clang"):
            compiler = "clang"
        elif row.compiler.startswith("gcc"):
            compiler = "gcc"
        else:
            compiler = "icc"
        if row.compiler.startswith("clang-3.8"):
            compiler_version = "clang-3.8"
        elif row.compiler.startswith("clang-5.0"):
            compiler_version = "clang-5.0"
        elif row.compiler.startswith("gcc-4"):
            compiler_version = "gcc-4"
        elif row.compiler.startswith("gcc-6"):
            compiler_version = "gcc-6"
        else:
            compiler_version = "icc-19"
        full_class = f"{compiler_version}_{optimization}"

        sample["label"] = full_class

        insts = row.insts.split(" ; ")

        sample[f"START {insts[0]}"] = 1
        # if len(insts) > 1:
        #     sample[f"START2 {insts[1]}"] = 1
        sample[f"END {insts[-1]}"] = 1
        # sample["SIZE"] = len(insts)

        for i, inst in enumerate(insts):
            if len(insts) > i + 1:
                ngram = f"{inst} : {insts[i+1]}"
                if ngram in ngrams_labels:
                    sample[ngram] = 1
                ngram = f"{inst.split(' ')[0]} : {insts[i+1].split(' ')[0]}"
                if ngram in opcode_ngrams_labels:
                    sample[ngram] = 1
            if len(insts) > i + 2:
                ngram = f"{inst} : {insts[i+1]} : {insts[i+2]}"
                if ngram in ngrams3_labels:
                    sample[ngram] = 1
            if len(insts) > i + 3:
                ngram = f"{inst} : {insts[i+1]} : {insts[i+2]} : {insts[i+3]}"
                if ngram in ngrams4_labels:
                    sample[ngram] = 1
            if inst in inst_labels:
                # if inst in top_opt_insts:
                sample[inst] = 1
            parts = inst.split(" ")
            opcode = parts[0]
            if opcode in opcode_labels:
                # if opcode in top_opt_opcodes[:20]:
                sample[opcode] = 1
            for operand in parts[1:]:
                if not operand.startswith("%"):
                    continue
                reg = operand[1:]
                if reg in reg_labels:
                    # if reg in top_opt_regs:
                    sample[reg] = 1
        samples.append(sample)
    samples = pd.DataFrame(samples).fillna(0)

    print(samples)
    do_decisiontree(samples)


def do_stats_analysis(dfs, name):
    # opcode -> {"O0": cnt, "O1": cnt, "OH": cnt}
    opcode_stats = defaultdict(lambda: defaultdict(int))
    reg_stats = defaultdict(lambda: defaultdict(int))
    inst_stats = defaultdict(lambda: defaultdict(int))
    for label, df in dfs.items():
        print(f"=== class: {label} {len(df)} ===")
        print(df)
        cls_stats = get_stats(df, min_cnt=100)
        for opcode in cls_stats["has_opcode"].keys():
            opcode_stats[opcode][label] = cls_stats["has_opcode"][opcode]
        for reg in cls_stats["has_reg"].keys():
            reg_stats[reg][label] = cls_stats["has_reg"][reg]
        for inst in cls_stats["has_inst"].keys():
            inst_stats[inst][label] = cls_stats["has_inst"][inst]
    do_stacked_bar_plot(
        pd.DataFrame.from_dict(opcode_stats, orient="index").fillna(0),
        f"{name}_opcode_stats.png",
    )
    do_stacked_bar_plot(
        pd.DataFrame.from_dict(inst_stats, orient="index").fillna(0),
        f"{name}_inst_stats.png",
    )
    do_stacked_bar_plot(
        pd.DataFrame.from_dict(reg_stats, orient="index").fillna(0),
        f"{name}_reg_stats.png",
    )
    # print(json.dumps(opcode_stats, indent=2))


def main():
    do_decision_tree_analysis()

    # df = load_data()
    # do_stats_analysis(split_by_opt(df), "opt")
    # do_stats_analysis(split_by_compiler(df), "compiler")
    # do_stats_analysis(split_by_compiler_version(df), "version")


if __name__ == "__main__":
    main()
