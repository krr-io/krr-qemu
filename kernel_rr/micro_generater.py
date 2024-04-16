import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

import constants


def add_text_top(ax):
    for p in ax.patches:
        # Get information for each bar
        height = p.get_height() # Height of the bar
        x = p.get_x() + p.get_width() / 2 # X position
        # Add text annotation
        bar_color = p.get_facecolor()
        label = f'{height:.2f}'.rstrip('0').rstrip('.') if '.' in f'{height:.2f}' else f'{height:.0f}'
        ax.text(x, height + 60, label, ha='center', fontsize=10, rotation=0, color=bar_color)


def aggregate(modes, df):
    result_df = pd.DataFrame({"test": [], "mode": [], "value": []})

    for mode in modes:
        for benchmark in df.test.unique():
            df_data = df[(df["test"] == benchmark) & (df["mode"] == mode)]
            value = df_data["value"].median()
            row = [benchmark, mode, value]
            result_df.loc[len(result_df)] = row

    return result_df


def gen_bar_chart(file_name, result_df, hue, x_col, y_col, x_label, y_label):
    plt.figure(figsize=(10, 6)) 
    ax = sns.barplot(
        y=y_col, x=x_col, hue=hue,
        data=result_df, palette=constants.palette, dodge=True
    )
    sns.despine()

    ax.tick_params(axis='x', labelsize=14)
    ax.tick_params(axis='y', labelsize=14)

    add_text_top(ax)

    sns.set_theme(style='white', font_scale=1.5)
    # plt.title('System call time measurement')
    plt.ylabel(y_label, fontsize=16)
    plt.xlabel(x_label, fontsize=16)
    # plt.yscale('log')
    plt.xticks(rotation=45) # Rotate the x-axis labels for better readability
    # plt.legend(title='Year')

    plt.legend(title='Mode', fontsize='x-small', title_fontsize='x-small', loc='best', markerscale=0.8)
    plt.tight_layout()
    # plt.savefig('{}/{}.pdf'.format("test_data", file_name), format="pdf", dpi=600)
    plt.savefig('{}/{}.png'.format("/home/projects/kernel-rr-dev/test_data", file_name), dpi=600)

    plt.clf()
    plt.close('all')


def generate_for_bypass_compare():
    file_name = "rocksdb-fillseq-compare"

    path = "{}/{}.csv".format("/home/projects/kernel-rr-dev/test_data", file_name)

    df = pd.read_csv(path)

    gen_bar_chart(file_name, df, "mode", "benchmark", "value", 'Benchmark', "Throughput(ops/s)")


def generate_for_microbench():
    file_name = "micro_syscall_large"

    print("Generating graph for {}".format(file_name))

    path = "{}/{}.csv".format("/home/projects/kernel-rr-dev/test_data", file_name)

    df = pd.read_csv(path)

    result_df = aggregate(constants.palette.keys(), df)

    gen_bar_chart(file_name, result_df, "mode", "test", "value", 'System call', "Time(ns)")


def generate_for_smp_microbench():
    file_name = "micro_smp"

    print("Generating graph for {}".format(file_name))

    path = "{}/{}.csv".format("test_data", file_name)

    df = pd.read_csv(path)

    tests = ["a", "b", "c", "d"]

    for test in tests:
        test_df = df.loc[df["test"]==test]

        print(test_df.loc[df["mode"]=="kernel_rr"])

        ax = sns.barplot(y='value', x='threads', hue='mode', data=test_df, palette=constants.palette)
        sns.despine()

        ax.tick_params(axis='x', labelsize=14)
        ax.tick_params(axis='y', labelsize=14)
        sns.set_theme(style='white', font_scale=1.5)

        ax.get_legend().remove()

        add_text_top(ax)
        # # plt.title('System call time measurement')
        plt.ylabel('Time(sec)', fontsize=16)
        plt.xlabel('Thread & Core Number', fontsize=16)
        # # plt.yscale('log')
        # plt.xticks(rotation=45) # Rotate the x-axis labels for better readability
        # # plt.legend(title='Year')

        plt.legend(title='Mode', fontsize='x-small', title_fontsize='x-small', loc='best', markerscale=0.8)
        plt.tight_layout()

        # plt.savefig('{}/{}-{}.pdf'.format("/home/projects/kernel-rr-dev/test_data", file_name, test), format="pdf", dpi=600)
        plt.savefig('{}/{}-{}.png'.format("/home/projects/kernel-rr-dev/test_data", file_name, test), dpi=600)

        plt.clf()
        plt.close('all')


generate_for_bypass_compare()

# generate_for_smp_microbench()
