# Copyright 2022, Zeropoint
# Author(s): Kevin Snow, Ryan Court, Yufei Du
import argparse
import json
import os
import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt
from collections import defaultdict
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support
import lightgbm as lgb
import seaborn as sns
import warnings
import glob
import ntpath
import networkx as nx
warnings.simplefilter(action='ignore', category=FutureWarning)

from static_opcode_features import StaticBinaryFeatures

class PassTell:

    def __init__(self, model_dir="passtell_model"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.models = None
    
    def train(self, dataset_filename, with_regvals):
        """
        Train a model for each pass with the data contained in the CSV file.
        The CSV file contains, for each function, the name, instructions and pass list.
        """
        results = []
        df = pd.read_csv(dataset_filename, index_col=False)
        for pass_name, df in self._split_dataset_by_passes(df):
            samples = self._get_pass_features(df, with_regvals=with_regvals)
            model, pass_result = self._train_pass(samples, pass_name)
            self._save_model(model, list(samples.columns), re.sub('[^0-9a-zA-Z]+', '_', pass_name))
            results.append(pass_result)
            #break #### TEMP FOR TESTING
        df = pd.DataFrame(results)
        pd.set_option('display.max_rows', None)
        print(df)
        df.to_csv(os.path.join(self.model_dir, "pass_classification_results.csv"))

    def get_all_files(self, dir):
        """ Returns list of (filepath, project_name)"""
        isFile = os.path.isfile(dir)
        isDirectory = os.path.isdir(dir)
        if not isFile and not isDirectory:
            return
        if not isDirectory:
            yield (dir,ntpath.basename(dir))
            return
        subfolders = [ f.path for f in os.scandir(dir) if f.is_dir() ]
        for subfolder in subfolders:
            for root, dirs, files in os.walk(subfolder):
                for file in files:
                    yield (os.path.join(root, file), os.path.basename(os.path.normpath(subfolder)) )

    def predict(self, binary_filename, model_filter=[], output_filename="passtell_results.csv"):
        # files = self.get_all_files(binary_filename)
        # Load each Pass model
        self._load_models(model_filter)
        findings = []
        cnt_bin = 0
        cnt_func = 0
        for binary_filename,project_name in self.get_all_files(binary_filename):
            # Generate the CSV for the target binary
            sbf = StaticBinaryFeatures(
                binary_filename,
                debug=False,
                include_regs=False,
                normalize_registers=False,
                max_imms=-1,
            )
            funcs = sbf.functions(max_insts=None, min_insts=10)
            if len(funcs.keys()) == 0:
                continue
            cnt_bin += 1
            cnt_func += len(funcs.keys())
            print(f"BINS: {cnt_bin} FUNCS: {cnt_func}")
            # continue
            for hash in funcs.keys():
                insts = funcs[hash]["insts"]
                funcs[hash]["function"] = json.dumps([inst[1] for inst in insts])
                del funcs[hash]["insts"]
            funcs = [func for hash,func in funcs.items()]
            df = pd.DataFrame(funcs)
            func_table = self._prepare_table(df)
            print("Passtell analyzing:", binary_filename)
            #print(df)
            # return
            # df = pd.read_csv(binary_filename, index_col=False)
            # Get the stats for the entire binary (but don't truncate uncommon values)
            samples = self._get_pass_features(df, with_regvals=False, should_truncate=False)
            # Enumerate each pass model, match features of `samples` to the model, and classify
            # Track list of positive `1` classifications for each pass and function            
            for pass_name in self.models.keys():
                if len(model_filter) > 0 and pass_name not in model_filter:
                    continue
                model = self.models[pass_name]["model"]
                feature_names = self.models[pass_name]["feature_names"]
                samples = samples.reindex(samples.columns.union(feature_names, sort=False), axis=1, fill_value=0.0)
                pass_df = pd.DataFrame(columns=feature_names)
                pass_df = pd.concat([pass_df, samples], join="inner")
                pass_df["label"] = pass_name
                _, features, _ = self._format_samples(pass_df)
                results = model.predict(features)
                funcs = []
                for idx, has_pass in enumerate(results):
                    if not has_pass:
                        continue
                    findings.append({
                        "function_name": df.iloc[idx]["name"],
                        "src_filename": ntpath.basename(df.iloc[idx]["srcfile"]),
                        "lineno": df.iloc[idx]["lineno"],
                        "project_name": project_name,
                        "binary_name": ntpath.basename(binary_filename),
                        "reason": pass_name,
                    })
                    func_table[df.iloc[idx]["name"]]["pass"].append(pass_name)
            findings_df = pd.DataFrame(findings)
            print(findings_df)
            findings_df.to_csv(output_filename, index=False)
            pd.DataFrame(list(func_table.values())).to_csv(output_filename[:-4] + "_by_func.csv", index=False)
            groups = self._find_connected_funcs(func_table, 0.7)
            with open(output_filename[:-4] + "_groups_stripped_0.7.json", 'w') as file:
                json.dump(groups, file)
            groups = self._find_connected_funcs(func_table, 0.9)
            with open(output_filename[:-4] + "_groups_stripped_0.9.json", 'w') as file:
                json.dump(groups, file)
            groups = self._find_connected_funcs(func_table, 0.0)
            with open(output_filename[:-4] + "_groups_stripped_0.0.json", 'w') as file:
                json.dump(groups, file)
    
    def _prepare_table(self, df):
        func_table = {}
        for _, row in df.iterrows():
            entry = {}
            entry["name"] = row["name"]
            entry["targets"] = row["targets"]
            entry["pass"] = []
            func_table[entry["name"]] = entry
        return func_table
    
    def _gen_call_graph(self, func_table):
        G = nx.DiGraph()
        for name in func_table:
            for callee in func_table[name]["targets"]:
                G.add_edge(name, callee)
    
    def _find_connected_funcs(self, func_table, pass_thres = 0.7):
        groups = []
        func_processed_list = []
        for name in func_table:
            if name in func_processed_list:
                continue
            func_processed_list.append(name)
            group = [name]
            funcs_processed = [name]
            group += self._find_connected_funcs_recur(func_table, name, func_table[name]["pass"], pass_thres, funcs_processed)
            print(funcs_processed)
            # # Only check connected functions
            # for callee in func_table[name]["targets"]:
            #     if not callee in func_table:
            #         continue
            #     passes_callee = func_table[callee]["pass"]
            #     passes_caller = func_table[name]["pass"]
            #     common_passes = []
            #     for p in passes_callee:
            #         if p in passes_caller:
            #             common_passes.append(p)
            #     if len(common_passes) / len(passes_caller) > pass_thres:
            #         group.append(callee)
            if len(group) > 1:
                groups.append(group)
        
        return self._merge_connected_subgroups(groups)
    
    def _find_connected_funcs_recur(self, func_table: dict, caller: str, passes_orig_caller: list, pass_thres: float, funcs_processed: list):
        group = []
        for callee in func_table[caller]["targets"]:
            if not callee in func_table or callee in funcs_processed:
                continue
            funcs_processed.append(callee)
            passes_callee = func_table[callee]["pass"]
            common_passes = []
            for p in passes_orig_caller:
                if p in passes_callee:
                    common_passes.append(p)
            if len(common_passes) / len(passes_orig_caller) > pass_thres:
                group.append(callee)
                group += self._find_connected_funcs_recur(func_table, callee, passes_orig_caller, pass_thres, funcs_processed)
        return group
    
    def _merge_connected_subgroups(self, groups: dict):
        changed = True
        merged_heads = []
        while changed:
            changed = False
            for group_a in groups:
                for func_a in group_a[1:]:
                    for group_b in groups:
                        if group_b[0] == func_a:
                            for func_b in group_b:
                                if not func_b in group_a:
                                    group_a.append(func_b)
                                    if not func_b in merged_heads:
                                        merged_heads.append(func_b)
                                    changed = True
        groups_stripped = []
        for group in groups:
            if not group[0] in merged_heads:
                groups_stripped.append(group)
        return groups_stripped




    def _load_models(self, model_filter=[]):
        if self.models is not None:
            return
        models = {}
        for model_filename in glob.glob(os.path.join(self.model_dir, "*.model")):
            pass_name = os.path.splitext(ntpath.basename(model_filename))[0]
            if len(model_filter) > 0 and pass_name not in model_filter:
                continue
            model, feature_names = self._load_model(pass_name)
            feature_names.remove("label")
            models[pass_name] = {"model": model, "feature_names": feature_names}
        self.models = models

    def _train_pass(self, samples, pass_name):
        """
        Train with 75% of the provided data, leaving the remaining 25% for analysis
        of the model performance.
        """
        labels, features, feature_labels = self._format_samples(samples)
        (
            train_features,
            test_features,
            train_labels,
            test_labels,
        ) = train_test_split(features, labels, test_size=0.25, random_state=42)
        rf = lgb.LGBMClassifier(
            n_jobs = -1,
            objective = "binary",
            num_leaves = 63,
            learning_rate = 0.05,
            feature_fraction = 0.9,
            bagging_fraction = 0.8,
            min_data_in_leaf = 30,
            random_state = 123,
        )
        rf.fit(train_features, train_labels)
        
        predictions = rf.predict(test_features)
        np.set_printoptions(precision=2)
        precision, recall, f1, _ = precision_recall_fscore_support(
            predictions, test_labels, average="weighted"
        )
        precision = round(precision * 100, 2)
        recall = round(recall * 100, 2)
        f1 = round(f1 * 100, 2)
        print(f"LightGBM Precision: {precision}%, Recall: {recall}%, F1: {f1}%, Pass: {pass_name}")

        # Feature importance analysis
        max_top_feats = 25
        top_feats = pd.DataFrame(sorted(zip(rf.feature_importances_, features.columns)), columns=['Value','Feature']).sort_values(by="Value", ascending=False).head(n=max_top_feats)
        plt.figure(figsize=(20, 10))
        sns.barplot(x="Value", y="Feature", data=top_feats)
        plt.title(f"Top {max_top_feats} Features for Pass `{pass_name}`")
        plt.tight_layout()
        plt.savefig(
            os.path.join(
                self.model_dir,
                f"{re.sub('[^0-9a-zA-Z]+', '_', pass_name)}.png"
        ))
        
        result = {
            "#Train": len(train_features),
            "#Test": len(test_features),
            "Prec": precision,
            "Recall": recall,
            "F1": f1,
            "Pass": pass_name,
        }
        for i in range(0,15):
            result[f"TopFeat{str(i+1).zfill(2)}"] = top_feats.iloc[i]["Feature"]
            result[f"_TopFeat{str(i+1).zfill(2)}"] = top_feats.iloc[i]["Value"]
        return rf, result

    def _save_model(self, model, feature_names, filename):
        import joblib
        with open(os.path.join(self.model_dir, filename+".json"), 'w') as outfile:
            json.dump(feature_names, outfile)
        joblib.dump(model, os.path.join(self.model_dir, filename+".model"))
    
    def _load_model(self, pass_name):
        import joblib
        with open(os.path.join(self.model_dir, pass_name+".json"), 'rb') as f:
            feature_names = json.load(f)
        with open(os.path.join(self.model_dir, pass_name+".model"), 'rb') as f:
            model = joblib.load(f)
        return model, feature_names
  
    def _format_samples(self, data):
        data = data.reindex(sorted(data.columns), axis=1)
        labels = np.array(data["label"])
        features = data.drop("label", axis=1)
        features = pd.get_dummies(features)
        feature_labels = list(features.columns)
        return labels, features, feature_labels

    def _get_pass_stats(self, df, with_regvals):
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
            "inst_2grams": defaultdict(int),
            "has_inst_2grams": defaultdict(int),
            "has_inst_3grams": defaultdict(int),
            "has_inst_4grams": defaultdict(int),
            "opcode_2grams": defaultdict(int),
            "has_opcode_2grams": defaultdict(int),
            "regval": defaultdict(int),
            "has_regval": defaultdict(int),
        }
        for index, row in df.iterrows():
            has_regval = set()
            has_opcode = set()
            has_reg = set()
            has_inst = set()
            has_inst_2grams = set()
            has_opcode_2grams = set()
            # insts = row.insts.split(" ; ")
            if with_regvals:
                regvals = json.loads(row.regs.replace("'", '"'))
                for inst_info, regset in regvals.items():
                    for reg, regval in regset.items():
                        stats["regval"][f"{reg}:{regval}"] += 1
                        has_regval.add(f"{reg}:{regval}")
            insts = json.loads(row.function.replace("'", '"'))
            for i, inst in enumerate(insts):
                if len(insts) > i + 1:
                    inst_2gram = f"{inst} : {insts[i+1]}"
                    opcode_2gram = f"{inst.split(' ')[0]} : {insts[i+1].split(' ')[0]}"
                    stats["inst_2grams"][inst_2gram] += 1
                    stats["opcode_2grams"][opcode_2gram] += 1
                    has_inst_2grams.add(inst_2gram)
                    has_opcode_2grams.add(opcode_2gram)
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
            for regval in has_regval:
                stats["has_regval"][regval] += 1
            for inst_2gram in has_inst_2grams:
                stats["has_inst_2grams"][inst_2gram] += 1
            for opcode_2gram in has_opcode_2grams:
                stats["has_opcode_2grams"][opcode_2gram] += 1
        for name in stats.keys():
            stats[name] = dict(
                sorted(stats[name].items(), key=lambda item: item[1], reverse=True)
            )
        return stats
    
    def _get_pass_features(self, df, with_regvals=False, should_truncate=True):
        """
        Decide the feature set based on the top features seen in the Dataframe.
        Return a DataFrame with the formatted features per each function.
        """
        global_stats = self._get_pass_stats(df, with_regvals)
        opcode_labels = list(global_stats["has_opcode"].keys())
        reg_labels = list(global_stats["has_reg"].keys())
        
        inst_labels = list(global_stats["has_inst"].keys())
        ngrams_labels = list(global_stats["has_inst_2grams"].keys())
        ngrams3_labels = list(global_stats["has_inst_3grams"].keys())
        ngrams4_labels = list(global_stats["has_inst_4grams"].keys())
        opcode_ngrams_labels = list(global_stats["has_opcode_2grams"].keys())
        regval_labels = list(global_stats["has_regval"].keys())
        if should_truncate:
            inst_labels = inst_labels[:1000]
            ngrams_labels = ngrams_labels[:1000]
            ngrams3_labels = ngrams3_labels[:1000]
            ngrams4_labels = ngrams4_labels[:1000]
            opcode_ngrams_labels = opcode_ngrams_labels[:1000]
            regval_labels = regval_labels[:1000]
        cols = set()
        samples = []
        for index, row in df.iterrows():
            if "label" in row:
                sample = {
                    "label": row.label,
                }
            else:
                sample = {}
            # insts = row.insts.split(" ; ")
            insts = json.loads(row.function.replace("'", '"'))
            sample[f"START {insts[0]}"] = 1.0
            sample[f"END {insts[-1]}"] = 1.0
            for i, inst in enumerate(insts):
                if len(insts) > i + 1:
                    ngram = f"{inst} : {insts[i+1]}"
                    if ngram in ngrams_labels:
                        sample[ngram.replace(":", "|")] = 1.0
                    ngram = f"{inst.split(' ')[0]} : {insts[i+1].split(' ')[0]}"
                    if ngram in opcode_ngrams_labels:
                        sample[ngram.replace(":", "|")] = 1.0
                if len(insts) > i + 2:
                    ngram = f"{inst} : {insts[i+1]} : {insts[i+2]}"
                    if ngram in ngrams3_labels:
                        sample[ngram.replace(":", "|")] = 1.0
                if len(insts) > i + 3:
                    ngram = f"{inst} : {insts[i+1]} : {insts[i+2]} : {insts[i+3]}"
                    if ngram in ngrams4_labels:
                        sample[ngram.replace(":", "|")] = 1.0
                if inst in inst_labels:
                    # if inst in top_opt_insts:
                    sample[inst] = 1.0
                parts = inst.split(" ")
                opcode = parts[0]
                if opcode in opcode_labels:
                    # if opcode in top_opt_opcodes[:20]:
                    sample[opcode] = 1.0
                for operand in parts[1:]:
                    if not operand.startswith("%"):
                        continue
                    reg = operand[1:]
                    if reg in reg_labels:
                        # if reg in top_opt_regs:
                        sample[reg] = 1.0
            if with_regvals:
                regvals = json.loads(row.regs.replace("'", '"'))
                for inst_info, regset in regvals.items():
                    for reg, regval in regset.items():
                        if f"{reg}:{regval}" in regval_labels:
                            sample[f"{reg}={regval}"] = 1.0
            samples.append(sample)
        samples = pd.DataFrame(samples).fillna(0.0)
        cols.update(samples.columns)
        for colname in cols:
            if colname in samples.columns:
                continue
            samples[colname] = 0.0
        return samples
    
    def _split_dataset_by_passes(self, df, min_count=5000):
        """
        Yields a DataFrame for each Pass that has a 50/50 split of samples with and
        without that pass. For function duplicates, only keep one of their samples.
        """
        # First get the counts of each pass on unique functions
        pass_sets = defaultdict(int)
        labels = defaultdict(int)
        labels_unique = defaultdict(int)
        hashes = set()
        df_uniq = df.drop_duplicates("hash", keep="first")
        for index, row in df.iterrows():
            passes = json.loads(row.passes.replace("'", '"'))
            for label in passes:
                labels[label] += 1
            if row.hash in hashes:
                continue
            hashes.add(row.hash)
            for label in passes:
                labels_unique[label] += 1
            pass_sets[", ".join(sorted(passes))] += 1
        # Now yield a DataFrame for each pass with a 50/50 split of
        # funtions with/without the pass.
        total_samples = len(hashes)
        for pass_name, cnt in sorted(labels_unique.items(), key=lambda item: item[1], reverse=True):
            # Ignore passes with less
            # than `min_count` samples with/without the pass
            # if cnt < min_count or total_samples - cnt < min_count:
            #     continue
            df_true = df_uniq[df_uniq["passes"].str.contains(f"'{pass_name}'", na=False)].sample(frac=1).reset_index(drop=True).head(min_count)
            df_true['label'] = True
            df_false = df_uniq[~df_uniq["passes"].str.contains(f"'{pass_name}'", na=False)].sample(frac=1).reset_index(drop=True).head(min_count)
            df_false['label'] = False
            num_samples = min(len(df_true.index), len(df_false.index))
            if num_samples < 10:
                print(f"Skipping pass `{pass_name}`, which only has {num_samples} samples.")
                continue
            yield (pass_name, pd.concat([df_true.head(num_samples), df_false.head(num_samples)]).sample(frac=1).reset_index(drop=True))


if __name__ == "__main__":
    """
    Usage:
      # Create models for a large pre-processed dataset of function passes
      passtell --train_csv big_ryan_data.csv

      # Predict passes applied to each function in a given binary
      # Appends results to the specified CSV file including Filename,FunctionName,Passes
      passtell --tell my_binary --output results.csv

    Format for training csv (column, example value):
        hash      7a531a04da3aed52db9598516dd12cf1
        name      get_password
        program   Apache
        function  "['push %r15', 'push %r14', ]"
        opt       2
        passes    "['Simplify the CFG', 'SROA', ]"
        regs      "{'4206464-push %r15': {}, '4206466-push %r14': {'eip': 2, 'esp': -8}}"
        coverage  0.26
    
    Only `hash`, `function`, `passes`, `regs` used for training.
    For "tell" mode, these columns are used:
      hash, name, program(filename), function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--train_csv",
        dest="train_csv",
        help="CSV dataset of functions labeled with their passes",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--tell",
        dest="tell",
        help="binary file to identify passes within",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--tell_deadstore",
        dest="tell_deadstore",
        help="binary file to identify passes within",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--tell_output",
        dest="tell_output",
        help="the csv filename to output when using tell mode",
        default="passtell_results.csv",
        type=str,
    )
    parser.add_argument(
        "--dynamic",
        dest="dynamic",
        help="use dynamic register value features",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--model_dir",
        dest="model_dir",
        help="model directory",
        default="passtell_model",
        type=str,
    )
    args = parser.parse_args()
    if args.train_csv is not None:
        pt = PassTell(model_dir=args.model_dir)
        pt.train(args.train_csv, args.dynamic)
    elif args.tell is not None:
        #bin_features = extract_debug_symbols(args.tell)
        pt = PassTell(model_dir=args.model_dir)
        pt.predict(args.tell, output_filename=args.tell_output)
    elif args.tell_deadstore is not None:
        #bin_features = extract_debug_symbols(args.tell)
        pt = PassTell(model_dir=args.model_dir)
        pt.predict(args.tell_deadstore, model_filter=["Dead_Store_Elimination"], output_filename=args.tell_output)

