import os
import argparse

import constants

import pandas as pd
from pandas.api.types import is_numeric_dtype
import seaborn as sns
import matplotlib.pyplot as plt

graphdir = ""

metric2y = {
    constants.THROUGHPUT: "Throughput (MB/s)",
    constants.OPSPS: "Throughput (ops/s)",
    constants.LATENCY: "Latency (micros/op)",
    constants.REDIS_TP: "Throughput (req/s)",
    constants.AVG_LAT: "Average Latency (ms)",
    "time": "Time (sec)"
}


def filter_valid_data(df, test):

    for index, row in df.iterrows():
        try:
            val = float(row["value"])
            if test == constants.THROUGHPUT and val > 100:
                raise Exception("Value {} is wrong".format(val))
        except:
            print("drop invalid value: {}".format(row["value"]))
            df.drop(index, inplace=True)


def check_valid_data(df, test):
    for index, row in df.iterrows():
        try:
            if test == constants.THROUGHPUT and float(row["value"]) > 100:
                raise Exception("Value {} is wrong".format(row["value"]))
        except Exception as e:
            raise Exception("Failed compare: {}".format(row["value"]))


def plug_single_graph(path):
    file_name = path.split("/")[-1].split(".")[0]
    file_dir = "/".join(path.split("/")[:-1])

    info_list = file_name.split("-")
    test_name = info_list[0]
    test = info_list[1]
    metric = info_list[2]

    df = pd.read_csv(path)

    palette = {'mean': 'orange', 'median': 'green', 'std': 'blue'}
    df_data = df[(df["mode"] == "whole_system_rr")]

    filter_valid_data(df_data, metric)

    df_data['cores'] = pd.to_numeric(df['cores'], errors='coerce')
    df_data['value'] = pd.to_numeric(df['value'], errors='coerce')

    # check_valid_data(df_data, metric)

    res_df = pd.DataFrame({"cores": [], "type": [], "value": []})
    
    for core in constants.CPU_NUMS:
        d = df_data[(df_data["cores"] == int(core))]
        # print(d["value"])

        mean_row = [int(core), "mean", d["value"].mean()]
        print(mean_row)

        res_df.loc[len(res_df)] = mean_row

        res_df.loc[len(res_df)] = [int(core), "median", d["value"].median()]
        # print()
        res_df.loc[len(res_df)] = [int(core), "std", d["value"].std()]


    ax = sns.lineplot(x='cores', y='value', hue="type", data=res_df, linewidth=3, palette=palette)
    # ax = sns.swarmplot(data=df_data, x='cores', y='value', size=3)
    # sns.despine()
    # sns.set_theme(style='white', font_scale=1.1)

    plt.xlabel('Whole_system_rr-{}'.format(metric2y[metric]), fontsize=18, fontweight='normal')
    # plt.ylabel(metric2y[metric], fontsize=18, fontweight='normal')
    # # ax.get_legend().remove()

    # plt.legend(title='Mode', loc='best')
    # plt.tight_layout()
    # plt.gca().set_ylim(bottom=0)
    ax.set_ylim(bottom=0)
    plt.savefig('{}/{}-temporary.png'.format(file_dir, file_name), dpi=600)

    plt.clf()
    plt.close('all')


def generate_bypass_graphs(path):
    file_name = path.split("/")[-1].split(".")[0]
    file_dir = "/".join(path.split("/")[:-1])

    df = pd.read_csv(path)




def generate_graphs(path):
    file_name = path.split("/")[-1].split(".")[0]
    file_dir = "/".join(path.split("/")[:-1])

    info_list = file_name.split("-")
    test_name = info_list[0]
    test = info_list[1]
    metric = info_list[2]

    print("Generating graph for {}".format(file_name))

    df = pd.read_csv(path)

    result_df = pd.DataFrame({"cores": [], "mode": [], "value": []})
    
    for mode in constants.palette.keys():
        for core in constants.CPU_NUMS:
            df_data = df[(df["mode"] == mode) & (df["cores"] == int(core))]

            # Now we get mean of all trials on this setup
            value = df_data["value"].mean()

            row = [int(core), mode, value]
            result_df.loc[len(result_df)] = row

    result_df.sort_values('cores', inplace=True)
    result_df['cores'] = result_df['cores'].astype(str)

    df['cores'] = df['cores'].astype(str)

    sns.set(style="whitegrid")
    # with sns.color_palette("Set2"):
    ax = sns.catplot(
        x='cores', y='value', hue='mode',
        data=result_df, palette=constants.palette,
        kind="point", aspect=1, errwidth=1
    )

    # ax = sns.lineplot(
    #     x='cores', y='value', hue='mode',
    #     data=df, linewidth=3, palette=palette,
    #     errorbar=lambda x: (x.min(), x.max()),
    #     err_style="bars", dashes=False
    # )
    sns.despine()
    sns.set(font_scale=20)

    sns.set_theme(style='white', font_scale=1.1)

    plt.xticks(result_df['cores'].unique(), fontsize=20)
    plt.yticks(fontsize=15)
    plt.xlabel('CPU Number', fontsize=18, fontweight='normal')
    plt.ylabel(metric2y[metric], fontsize=18, fontweight='normal')
    ax._legend.remove()

    plt.legend(title='Mode', loc='best')
    plt.tight_layout()
    plt.gca().set_ylim(bottom=0)
    # plt.savefig('{}/{}.pdf'.format(file_dir, file_name), format="pdf", dpi=600)
    plt.savefig('{}/{}.png'.format(file_dir, file_name), dpi=600)

    plt.clf()
    plt.close('all')


parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

parser.add_argument("--graphtest", default="all")
parser.add_argument("--graphdir", default=constants.DATA_DIR)

args = parser.parse_args()
graph_test = args.graphtest
graphdir = args.graphdir

if __name__ == "__main__":
    for file in os.listdir(graphdir):
        if not file.endswith(".csv"):
            continue

        if graph_test == "all" or graph_test in file:
            generate_graphs("{}/{}".format(graphdir, file))
