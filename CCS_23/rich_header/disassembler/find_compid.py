import argparse
from pathlib import Path
import re

RE_PATTERN = r'([0-9A-Fa-f]{8}) (\[.+\]) (\S+) (.+)\b'

def loadData(txtPath: Path):
    with txtPath.open() as file:
        data = {}
        for line in file:
            result = re.findall(RE_PATTERN, line)
            if len(result) > 0:
                id = int(result[0][0], 16)
                version = result[0][1:]
                data[id] = version
    # Sort data by key
    data = dict(sorted(data.items()))
    return data

def query(data: dict, id: int):
    output = ""
    if id in data:
        # output += "Exact match: "
        for entry in data[id]:
            output += entry + " "
        output = output[:-1]
    else:
        prev = -1
        curr = -1
        for compID in data:
            curr = compID
            if compID > id:
                break
            prev = compID
        if prev == curr:
            # No match
            output = "UNKNOWN: No match"
        elif prev == -1:
            # Too old
            output = "UNKNOWN: Too old"
        else:
            if not data[prev][0] == data[curr][0]:
                # Can't agree on the compiler type
                output = "UNKNOWN: Type mismatch"
            elif data[prev][1] == data[curr][1]:
                # Easy match
                output = data[prev][0] + " " + data[prev][1]
            else:
                # Could be either
                output = data[prev][0] + " " + data[prev][1] + " OR " + data[curr][1]
    return output



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "compid_txt",
        help="The comp ID database in TXT format",
        type=Path,
    )
    parser.add_argument(
        "compid",
        help="The comp ID to query",
        type=lambda x: int(x,16),
    )
    args = parser.parse_args()

    data = loadData(args.compid_txt)
    print(query(data, args.compid))