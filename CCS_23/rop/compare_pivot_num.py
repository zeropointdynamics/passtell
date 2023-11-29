import argparse
from csv import DictReader
from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        help="Path to the csv file",
        type=Path,
    )
    args = parser.parse_args()

    with args.path.open() as file:
        reader = DictReader(file)
        neg = 0
        pos = 0
        total = 0
        for row in reader:
            total += 1
            if int(row['gain_rop_STACK_PIVOT_REG_NUM_gain']) > 0:
                pos += 1
            if int(row['gain_rop_STACK_PIVOT_REG_NUM_gain']) < 0:
                neg += 1
    print('Total: ', total, '; negative: ', neg, '; positive: ', pos)