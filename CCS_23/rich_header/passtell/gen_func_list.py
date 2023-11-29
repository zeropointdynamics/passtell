from pathlib import Path
import json
import subprocess
import argparse
from tqdm import tqdm

FILE_LIST = ["/usr/lib", "/usr/lib64", "/home/yufei/Documents/test_code/encrypt_server_demo/libhydrogen/build_O0"]

def getFuncList(filePath: Path):
    result = subprocess.run(["objdump", "-d", filePath.as_posix()], capture_output=True)
    funcList = []
    for line in result.stdout.decode().split('\n'):
        if ">:" in line:
            funcList.append(line.split('<')[1].split('>:')[0])
    return funcList

def processPath(path: Path):
    output = {}
    if path.is_dir():
        for subp in tqdm(path.rglob("**/*.a")):
            funcs = getFuncList(subp)
            if len(funcs) > 0:
                output[subp.name] = funcs
    else:
        funcs = getFuncList(path)
        if len(funcs) > 0:
            output[path.name] = funcs
    return output

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "output_json",
        type=Path,
    )
    parser.add_argument(
        "--paths",
        type=str,
        nargs="+",
        required=False,
        default=FILE_LIST,
    )

    args = parser.parse_args()

    output = {}
    for path in args.paths:
        subDict = processPath(Path(path))
        for lib in subDict:
            if lib in output:
                print("Warning: conflicting library ", lib)
                i = 0
                while lib + "_" + str(i) in output:
                    i += 1
                output[lib+"_"+str(i)] = subDict[lib]
            else:
                output[lib] = subDict[lib]
    with args.output_json.open('w') as file:
        json.dump(output, file)