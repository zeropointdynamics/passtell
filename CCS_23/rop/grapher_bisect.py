import argparse
import json
import pandas as pd
from matplotlib import figure
from pathlib import Path
from tqdm import tqdm

def genGraphs(csvPath: Path, distJsonPath: Path, outPath: Path):
    # Read gadget info from the CSV
    df = pd.read_csv(csvPath)

    configs = csvPath.stem.split('_') + ['diff']
    iteration = configs[1]

    # Read pass distribution
    with distJsonPath.open() as file:
        distDict = json.load(file)[iteration]
    dist_keys = list(distDict.keys())
    dist_values = []
    projects = []
    for passName in distDict:
        projects = list(set(projects) | set(distDict[passName]))
        dist_values.append(0)
        for projName in distDict[passName]:
            dist_values[-1] += distDict[passName][projName]
    
    # If the pass never modified any function in any project, then
    # just skip it
    if len(projects) == 0:
        return
    
    df = df[df['project_name'].isin(projects)]

    df_useful = df[['rop_STACK_PIVOT_USEFUL_0', 'rop_STACK_PIVOT_USEFUL_1', 'gain_rop_STACK_PIVOT_USEFUL_gain']]
    df_reg = df[['rop_STACK_PIVOT_REG_NUM_0', 'rop_STACK_PIVOT_REG_NUM_1', 'gain_rop_STACK_PIVOT_REG_NUM_gain']]
    df_total_ratio = df[['rop_STACK_PIVOT_TOTAL_RATIO_0', 'rop_STACK_PIVOT_TOTAL_RATIO_1', 'gain_rop_STACK_PIVOT_TOTAL_RATIO_gain']]
    df_semantic_ratio = df[['rop_STACK_PIVOT_SEMANTIC_RATIO_0', 'rop_STACK_PIVOT_SEMANTIC_RATIO_1', 'gain_rop_STACK_PIVOT_SEMANTIC_RATIO_gain']]
    df_size_ratio = df[['rop_STACK_PIVOT_PAGE_RATIO_0', 'rop_STACK_PIVOT_PAGE_RATIO_1', 'gain_rop_STACK_PIVOT_PAGE_RATIO_gain']]
    df_distance = df[['rop_STACK_PIVOT_MAX_DISTANCE_0', 'rop_STACK_PIVOT_MAX_DISTANCE_1', 'gain_rop_STACK_PIVOT_MAX_DISTANCE_gain']]
    df_percentage = df[['rop_STACK_PIVOT_PAGE_PERCENTAGE_0', 'rop_STACK_PIVOT_PAGE_PERCENTAGE_1',
    'gain_rop_STACK_PIVOT_PAGE_PERCENTAGE_gain']]
    configs = csvPath.stem.split('_') + ['diff']

    avg_stats = [df['gain_rop_STACK_PIVOT_PAGE_RATIO_gain'].mean(), 
        df['gain_rop_STACK_PIVOT_MAX_DISTANCE_gain'].dropna().mean(), 
        df['gain_rop_STACK_PIVOT_PAGE_PERCENTAGE_gain'].dropna().mean()]

    # Initialize figure
    fig = figure.Figure(facecolor='white', figsize=(16,16))
    # fig.rcParams['savefig.facecolor']='white'
    ax = fig.subplots(2, 2)

    # Pass distributions
    title = "Pass(es) added in iteration " + configs[1]
    ax[0][0].set_title(title)
    bars = ax[0][0].barh(dist_keys, dist_values)
    ax[0][0].bar_label(bars, padding=1)

    # Ratio of stack pivot / binary size (in pages)
    title = "Iteration " + configs[0] + ' vs ' + configs[1] + ', Stack pivot / code size (pages)'
    ax[0][1].set_title(title)
    bp_dict = ax[0][1].boxplot(df_size_ratio, labels=configs)
    # Label the values
    # Modified from: https://stackoverflow.com/questions/18861075/overlaying-the-numeric-value-of-median-variance-in-boxplots
    for line in bp_dict['medians']:
        # get position data for median line
        x, y = line.get_xydata()[1] # top of median line
        # overlay median value
        ax[0][1].text(x, y, '%.3f' % y,
            horizontalalignment='center') # draw above, centered
    for line in bp_dict['whiskers']:
        x, y = line.get_xydata()[0] # bottom of left line
        ax[0][1].text(x,y, '%.3f' % y,
            horizontalalignment='center', # centered
            verticalalignment='top')      # below
        x, y = line.get_xydata()[1] # bottom of right line
        ax[0][1].text(x,y, '%.3f' % y,
            horizontalalignment='center', # centered
                verticalalignment='top')      # below

    # Distance between stack pivots
    df_distance = df_distance.dropna() # Drop NaN values
    title = "Iteration " + configs[0] + ' vs ' + configs[1] + ', max distance between stack pivots,\nonly including binaries with at least 2 stack pivots\nUnit: page (4KB)'
    ax[1][0].set_title(title)
    bp_dict = ax[1][0].boxplot(df_distance, labels=configs)
    # Label the values
    # Modified from: https://stackoverflow.com/questions/18861075/overlaying-the-numeric-value-of-median-variance-in-boxplots
    for line in bp_dict['medians']:
        # get position data for median line
        x, y = line.get_xydata()[1] # top of median line
        # overlay median value
        ax[1][0].text(x, y, '%.1f' % y,
            horizontalalignment='center') # draw above, centered
    for line in bp_dict['whiskers']:
        x, y = line.get_xydata()[0] # bottom of left line
        ax[1][0].text(x,y, '%.1f' % y,
            horizontalalignment='center', # centered
            verticalalignment='top')      # below
        x, y = line.get_xydata()[1] # bottom of right line
        ax[1][0].text(x,y, '%.1f' % y,
            horizontalalignment='center', # centered
                verticalalignment='top')      # below
    
    # Percentage of pages with stack pivot
    df_percentage = df_percentage.dropna() # Drop NaN values
    title = "Iteration " + configs[0] + ' vs ' + configs[1] + ', percentage of pages that contain \nat least one stack pivot'
    ax[1][1].set_title(title)
    bp_dict = ax[1][1].boxplot(df_percentage, labels=configs)
    # Label the values
    # Modified from: https://stackoverflow.com/questions/18861075/overlaying-the-numeric-value-of-median-variance-in-boxplots
    for line in bp_dict['medians']:
        # get position data for median line
        x, y = line.get_xydata()[1] # top of median line
        # overlay median value
        ax[1][1].text(x, y, '%.3f' % y,
            horizontalalignment='center') # draw above, centered
    for line in bp_dict['whiskers']:
        x, y = line.get_xydata()[0] # bottom of left line
        ax[1][1].text(x,y, '%.3f' % y,
            horizontalalignment='center', # centered
            verticalalignment='top')      # below
        x, y = line.get_xydata()[1] # bottom of right line
        ax[1][1].text(x,y, '%.3f' % y,
            horizontalalignment='center', # centered
                verticalalignment='top')      # below

    fig.savefig(outPath.as_posix())

    return avg_stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "in_dir",
        help="build directory",
        type=Path,
    )
    parser.add_argument(
        "out_dir",
        help="output directory",
        type=Path,
    )
    args = parser.parse_args()

    # Set distribution JSON path
    distPath = args.in_dir.joinpath('dist_projects.json')
    avg_density = []
    avg_distance = []
    avg_percent = []
    # Parse all csv files
    for csvPath in tqdm(list(args.in_dir.rglob('*.csv'))):
        avg_stats = genGraphs(csvPath, distPath, args.out_dir.joinpath(csvPath.stem + '.png'))
        if avg_stats is None:
            continue
        avg_density.append({csvPath.stem:avg_stats[0]})
        avg_distance.append({csvPath.stem:avg_stats[1]})
        avg_percent.append({csvPath.stem:avg_stats[2]})
    # Sort stats
    avg_density = sorted(avg_density, key=lambda entry: list(entry.values())[0], reverse=True)
    avg_distance = sorted(avg_distance, key=lambda entry: list(entry.values())[0], reverse=True)
    avg_percent = sorted(avg_percent, key=lambda entry: list(entry.values())[0], reverse=True)
    # Write stats
    with args.out_dir.joinpath('stats.json').open('w') as file:
        avg_out = {"avg_density":avg_density, "avg_distance":avg_distance, "avg_percent": avg_percent}
        json.dump(avg_out, file)