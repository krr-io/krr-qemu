import os
import argparse

import constants

import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt


def generate_graphs(path):
    file_name = path.split("/")[-1].split(".")[0]

    info_list = file_name.split("-")
    test_name = info_list[0]
    test = info_list[1]
    metric = info_list[2]

    metric2y = {
        constants.THROUGHPUT: "Throughput (MB/s)",
        constants.OPSPS: "Throughput (ops/s)",
        constants.LATENCY: "Latency (micros/op)",
        constants.REDIS_TP: "Throughput (req/s)",
        constants.AVG_LAT: "Average Latency (ms)"
    }

    print("Generating graph for {}".format(file_name))

    df = pd.read_csv(path)

    result_df = pd.DataFrame({"cores": [], "mode": [], "value": []})

    palette = {'kernel_rr': 'orange', 'baseline': 'green', 'whole_system_rr': 'blue'}
    
    for mode in palette.keys():
        for core in constants.CPU_NUMS:
            df_data = df[(df["mode"] == mode) & (df["cores"] == int(core))]

            value = df_data["value"].mean()

            row = [int(core), mode, value]
            result_df.loc[len(result_df)] = row

    result_df.sort_values('cores', inplace=True)
    result_df['cores'] = result_df['cores'].astype(str)

    ax = sns.lineplot(x='cores', y='value', hue='mode', data=result_df, linewidth=3, palette=palette)
    sns.despine()
    sns.set(font_scale=5)
    plt.xticks(result_df['cores'].unique())

    sns.set_theme(style='white', font_scale=1.1)

    plt.xlabel('CPU Number', fontsize=18, fontweight='normal')
    plt.ylabel(metric2y[metric], fontsize=18, fontweight='normal')
    ax.get_legend().remove()

    # plt.title('{}({})'.format(test_name, test), fontsize=12)
    plt.legend(title='Mode', loc='best')
    plt.tight_layout()
    plt.gca().set_ylim(bottom=0)
    # plt.savefig('{}/{}.pdf'.format(constants.DATA_DIR, file_name), format="pdf", dpi=600)
    plt.savefig('{}/{}.png'.format(constants.DATA_DIR, file_name), dpi=600)

    plt.clf()
    plt.close('all')


parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

parser.add_argument("--graphtest", default="all")
parser.add_argument("--graphonly", default="false")

args = parser.parse_args()
graph_test = args.graphtest

if __name__ == "__main__":
    for file in os.listdir(constants.DATA_DIR):
        if not file.endswith(".csv"):
            continue

        if graph_test == "all" or graph_test in file:
            generate_graphs("{}/{}".format(constants.DATA_DIR, file))
