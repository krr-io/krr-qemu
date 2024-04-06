import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt



def generate_for_microbench():
    file_name = "micro_smp"

    print("Generating graph for {}".format(file_name))

    path = "{}/{}.csv".format("test_data", file_name)

    df = pd.read_csv(path)

    palette = {'kernel_rr': 'orange', 'baseline': 'green', 'whole_system_rr': 'blue'}

    ax = sns.barplot(y='value', x='test', hue='mode', data=df, palette=palette, dodge=True)
    sns.despine()

    ax.tick_params(axis='x', labelsize=14)
    ax.tick_params(axis='y', labelsize=14)
    
    sns.set_theme(style='white', font_scale=1.5)
    # plt.title('System call time measurement')
    plt.ylabel('Time(sec)', fontsize=16)
    plt.xlabel('System call', fontsize=16)
    # plt.yscale('log')
    plt.xticks(rotation=45) # Rotate the x-axis labels for better readability
    # plt.legend(title='Year')

    plt.legend(title='Mode', fontsize='x-small', title_fontsize='x-small', loc='best', markerscale=0.8)
    plt.tight_layout()
    plt.savefig('{}/{}.pdf'.format("test_data", file_name), format="pdf", dpi=600)
    # plt.savefig('{}/{}.png'.format("test_data", file_name), dpi=600)

    plt.clf()
    plt.close('all')


def generate_for_smp_microbench():
    file_name = "micro_smp"

    print("Generating graph for {}".format(file_name))

    path = "{}/{}.csv".format("test_data", file_name)

    df = pd.read_csv(path)

    palette = {'kernel_rr': 'orange', 'baseline': 'green', 'whole_system_rr': 'blue'}

    tests = ["a", "b", "c", "d"]

    for test in tests:
        test_df = df.loc[df["test"]==test]

        print(test_df.loc[df["mode"]=="kernel_rr"])

        ax = sns.barplot(y='value', x='threads', hue='mode', data=test_df, palette=palette)
        sns.despine()

        ax.tick_params(axis='x', labelsize=14)
        ax.tick_params(axis='y', labelsize=14)
        sns.set_theme(style='white', font_scale=1.5)

        ax.get_legend().remove()

        for p in ax.patches:
            # Get information for each bar
            height = p.get_height() # Height of the bar
            x = p.get_x() + p.get_width() / 2 # X position
            # Add text annotation
            bar_color = p.get_facecolor()
            label = f'{height:.2f}'.rstrip('0').rstrip('.') if '.' in f'{height:.2f}' else f'{height:.0f}'
            ax.text(x, height + 10, label, ha='center', fontsize=10, rotation=90, color=bar_color)

        # # plt.title('System call time measurement')
        plt.ylabel('Time(sec)', fontsize=16)
        plt.xlabel('Thread & Core Number', fontsize=16)
        # # plt.yscale('log')
        # plt.xticks(rotation=45) # Rotate the x-axis labels for better readability
        # # plt.legend(title='Year')

        plt.legend(title='Mode', fontsize='x-small', title_fontsize='x-small', loc='best', markerscale=0.8)
        plt.tight_layout()

        plt.savefig('{}/{}-{}.pdf'.format("test_data", file_name, test), format="pdf", dpi=600)
        # plt.savefig('{}/{}-{}.png'.format("test_data", file_name, test), dpi=600)

        plt.clf()
        plt.close('all')


generate_for_smp_microbench()
