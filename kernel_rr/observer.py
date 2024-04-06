import os
import traceback
import pandas as pd
import subprocess
import argparse

import seaborn as sns
import matplotlib.pyplot as plt
import time
import signal
import psutil


DATA_DIR = "test_data"


REDIS_TP = "redisthroughput"
AVG_LAT = "avg_latency"
THROUGHPUT = "throughput"
OPSPS = "opsps"
LATENCY = "latency"


ROCKS_DB_BP_TEST_NAME = "rocksdb_kernel_bypass"
ROCKS_DB_NBP_TEST_NAME = "rocksdb"
REDIS_TEST_NAME = "redis"

mode = "kernel_rr"
test_name = ROCKS_DB_NBP_TEST_NAME

modes = {"kernel_rr": 0, "baseline": 1, "whole_system_rr": 2}

metrics = {
    ROCKS_DB_BP_TEST_NAME: (THROUGHPUT, OPSPS, LATENCY)
}

benchmarks = {
    ROCKS_DB_BP_TEST_NAME: ("fillseq", "fillrandom", "readseq", "readrandom"),
    ROCKS_DB_NBP_TEST_NAME: ("fillseq", "fillrandom", "readseq", "readrandom")
}

cpu_nums = ["1", "2", "4", "8", "16"]
current_cpu_num = 1
replace_old = False

replace_trial = 0

def get_file_name(benchmark, metric):
    return "test_data/{}-{}-{}.csv".format(test_name, benchmark, metric)


def init_csv_file(benchmark, metric):
    with open(get_file_name(benchmark, metric), 'w') as f:
        f.write("cores,mode,value,trial")


def append_file(benchmark, metric, value):
    file = get_file_name(benchmark, metric)

    if not os.path.exists(file):
        init_csv_file(benchmark, metric)

    df = pd.read_csv(file)

    cores = int(current_cpu_num)

    print("cores={} mode={}, value={}".format(cores, mode, value))

    if "trial" not in df.columns:
        df["trial"] = 1

    if "count" in df.columns:
        df.drop("count", axis=1, inplace=True)

    if replace_trial > 0:
        condition = (df['cores'] == cores) & (df['mode'] == mode) & (df['trial'] == replace_trial)

        if not df[condition].empty:
            existing_value = df.loc[condition, "value"]

            print(
                "Value exists [{} {}, {}], modifying to {}".format(
                    current_cpu_num, mode, existing_value, value
                )
            )
            df.loc[condition, "value"] = float(value)  
        else:
            row = [cores, mode, value, 1]
            df.loc[len(df)] = row
    else:
        trial = 1
        condition = (df['cores'] == cores) & (df['mode'] == mode)

        if 'trial' in df.columns:
            trial = df.loc[condition, "trial"].max() + 1

        print("adding trial {}".format(trial))

        row = [cores, mode, value, trial]
        df.loc[len(df)] = row

    df.to_csv(file, index=False)


def generate_rocksdb_bp(buffer):
    tp = 0
    ops_ps = 0
    latency = 0
    item_list = buffer.split()

    print("Getting the data")

    try:
        fillseq = "fillseq" in buffer
        fillrandom = "fillrandom" in buffer
        readseq = "readseq" in buffer
        readrandom = "readrandom" in buffer

        readwhilewriting = "readwhilewriting" in buffer

        if fillseq or fillrandom:
            tp = item_list[6]
            ops_ps = item_list[4]
            latency = item_list[2]

            bm = "unknown"
            if fillseq:
                bm = "fillseq"
            elif fillrandom:
                bm = "fillrandom"
            
            append_file(bm, THROUGHPUT, tp)
        elif readseq or readrandom:
            ops_ps = item_list[4]
            latency = item_list[2]

            if readrandom:
                bm = "readrandom"
            elif readseq:
                bm = "readseq"

        elif readwhilewriting:
            bm = "readwhilewriting"
            tp = item_list[6]
            ops_ps = item_list[4]
            latency = item_list[2]

        append_file(bm, OPSPS, ops_ps)
        append_file(bm, LATENCY, latency)

    except Exception as e:
        print("{} {}: {}".format(traceback.format_exc(), e, item_list))


def generate_redis(buffer, benchmark, latency=False):
    if "throughput" in buffer:
        item_list = buffer.split(":")[2].split()
        tp = item_list[0]

        append_file(benchmark, REDIS_TP, tp)

    if latency:
        item_list = buffer.split()
        avg_lat = item_list[0]
        append_file(benchmark, AVG_LAT, avg_lat)


def generate_values_rocksdb(buffer):
    if test_name in (ROCKS_DB_BP_TEST_NAME, ROCKS_DB_NBP_TEST_NAME):
        generate_rocksdb_bp(buffer)


def get_data_redis():
    with open("./rr-result.txt", "r", encoding='ISO-8859-1') as f:
        content = f.read()
        bm = ""
        if "GET" in content:
            bm = "get"
        elif "SET" in content:
            bm="set"

        lines = content.split("\n")

        for index, line in enumerate(lines):
            if "avg" in line:
                generate_redis(lines[index+1], bm, True)
            else:
                generate_redis(line, bm, False)

def get_data_rocksdb():
    with open("./rr-result.txt", "r", encoding='ISO-8859-1') as f:
        lines = f.readlines()
        for line in lines:
            generate_values_rocksdb(line)

def get_data():
    if test_name in (ROCKS_DB_BP_TEST_NAME, ROCKS_DB_NBP_TEST_NAME):
        get_data_rocksdb()
    elif test_name == REDIS_TEST_NAME:
        get_data_redis()

# init_csv_file()

qemu_binary = "../build/qemu-system-x86_64"

def test_run(cpu_num):
    global current_cpu_num
    
    current_cpu_num = cpu_num

    extra_dev = ""
    extra_arg = ""
    disk_image = os.environ["KRR_DISK"]
    ivshmem = "-object memory-backend-file,size=65536M,share,mem-path=/dev/shm/ivshmem,id=hostmem -device ivshmem-plain,memdev=hostmem"

    if mode == "kernel_rr":
        kernel_image = os.environ["KRR_SMP_IMG"]

        if cpu_num == "1":
            kernel_image = os.environ["KRR_UNI_IMG"]

    elif mode == "baseline" or mode == "whole_system_rr":
        kernel_image = os.environ["BL_IMG"]

    if mode == "whole_system_rr":
        extra_arg = "-whole-system 1"

    if test_name == ROCKS_DB_BP_TEST_NAME:
        extra_dev = " -drive file=../build/nvm.img,if=none,id=nvm -device nvme,serial=deadbeef,drive=nvm"

    qemu_base_cmd = """
    {qemu_binary} -kernel {kernel_image} \
    -accel kvm -smp {cpu_num} -cpu host -no-hpet -m 8G -append \
    "root=/dev/sda rw init=/lib/systemd/systemd tsc=unstable console=ttyS0" \
    -hda {disk_image} \
    {ivshmem} -vnc :00 -D rec.log {extra_dev} -exit-record 1 {extra_arg}
    """.format(
        qemu_binary=qemu_binary, kernel_image=kernel_image,
        disk_image=disk_image, cpu_num=cpu_num,
        ivshmem=ivshmem, extra_dev=extra_dev,
        extra_arg=extra_arg,
    )

    print("QEMU CMD: {}".format(qemu_base_cmd))

    os.system("rm -f /dev/shm/ivshmem")
    os.system("modprobe -r kvm_intel;modprobe -r kvm;modprobe kvm_intel;modprobe kvm")

    process = subprocess.Popen(
        qemu_base_cmd,
        shell=True,
        close_fds=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print("Started process {}".format(process.pid))
    rc = 0
    cnt = 0

    while True:
        if process.poll() is not None:
            if process.returncode == 10:
                out, err = process.communicate()
                print("Output: {}".format(out))
                rc = process.returncode
                break

        time.sleep(1)
        cnt += 1

        if not psutil.pid_exists(process.pid):
            return -1

        if cnt > 260:
            print("Timeout kill")
            os.system("kill -9 $(pgrep qemu)")
            return -1

    print("return code {}".format(rc))

    get_data()

    return 0


def generate_graphs(path):
    file_name = path.split("/")[-1].split(".")[0]

    info_list = file_name.split("-")
    test_name = info_list[0]
    test = info_list[1]
    metric = info_list[2]

    metric2y = {
        THROUGHPUT: "Throughput (MB/s)",
        OPSPS: "Throughput (ops/s)",
        LATENCY: "Latency (micros/op)",
        REDIS_TP: "Throughput (req/s)",
        AVG_LAT: "Average Latency (ms)"
    }

    print("Generating graph for {}".format(file_name))

    df = pd.read_csv(path)

    df.sort_values('cores', inplace=True)
    df['cores'] = df['cores'].astype(str)

    palette = {'kernel_rr': 'orange', 'baseline': 'green', 'whole_system_rr': 'blue'}

    ax = sns.lineplot(x='cores', y='value', hue='mode', data=df, linewidth=3, palette=palette)
    sns.despine()
    sns.set(font_scale=5)
    plt.xticks(df['cores'].unique())

    sns.set_theme(style='white', font_scale=1.1)

    plt.xlabel('CPU Number', fontsize=18, fontweight='normal')
    plt.ylabel(metric2y[metric], fontsize=18, fontweight='normal')
    ax.get_legend().remove()

    # plt.title('{}({})'.format(test_name, test), fontsize=12)
    plt.legend(title='Mode', loc='best')
    plt.tight_layout()
    plt.gca().set_ylim(bottom=0)
    plt.savefig('{}/{}.pdf'.format(DATA_DIR, file_name), format="pdf", dpi=600)
    # plt.savefig('{}/{}.png'.format(DATA_DIR, file_name), dpi=600)

    plt.clf()
    plt.close('all')


parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

parser.add_argument("--mode", default="kernel_rr")
parser.add_argument("--graph", default="false")
parser.add_argument("--test", default=ROCKS_DB_BP_TEST_NAME)
parser.add_argument("--graphtest", default="all")
parser.add_argument("--parseonly", default="false")
parser.add_argument("--startfrom", default="1")
parser.add_argument("--graphonly", default="false")
parser.add_argument("--cpus", default=",".join(cpu_nums))
parser.add_argument("--replace", default="false")
parser.add_argument("--replacetrial", default=0)
args = parser.parse_args()

mode = args.mode
test_name = args.test
graph_test = args.graphtest
cpu_nums = args.cpus.split(",")
replace_trial = int(args.replacetrial)

if args.replace == "true":
    replace_old = True

if args.parseonly == "true":
    get_data()
else:
    if args.graphonly != "true":
        print("mode={} test={}".format(mode, test_name))
        for cpu_num in cpu_nums[cpu_nums.index(args.startfrom):]:
            while test_run(cpu_num) < 0:
                print("Timeout try again")

    if args.graph == "true" or args.graphonly == "true":
        for file in os.listdir(DATA_DIR):
            if not file.endswith(".csv"):
                continue

            if graph_test == "all" or graph_test in file:
                generate_graphs("{}/{}".format(DATA_DIR, file))
