import asyncio
import os
import traceback
import pandas as pd
import subprocess
import argparse

import time
import signal
import psutil

import constants

from qemu.qmp import QMPClient


REDIS_TP = "redisthroughput"
AVG_LAT = "avg_latency"
THROUGHPUT = "throughput"
OPSPS = "opsps"
LATENCY = "latency"

mode = "kernel_rr"
test_name = constants.ROCKS_DB_NBP_TEST_NAME

modes = {"kernel_rr": 0, "baseline": 1, "whole_system_rr": 2}

metrics = {
    constants.ROCKS_DB_BP_TEST_NAME: (THROUGHPUT, OPSPS, LATENCY)
}

benchmarks = {
    constants.ROCKS_DB_BP_TEST_NAME: ("fillseq", "fillrandom", "readseq", "readrandom"),
    constants.ROCKS_DB_NBP_TEST_NAME: ("fillseq", "fillrandom", "readseq", "readrandom")
}

benchmark = "fillseq"

cpu_nums = ["1", "2", "4", "8"]
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

    print("cores={} mode={}, value={}, file={}".format(cores, mode, value, file))

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

        if not df[condition].empty:
            if 'trial' in df.columns:
                trial = df.loc[condition, "trial"].max() + 1

        row = [cores, mode, value, trial]

        print("adding row {}".format(row))

        df.loc[len(df)] = row

    df.to_csv(file, index=False)


def generate_rocksdb_bp(buffer):
    tp = 0
    ops_ps = 0
    latency = 0
    item_list = buffer.split()

    if benchmark not in buffer:
        return

    print("Getting the data")

    buffer = buffer[buffer.find(benchmark):]

    try:
        if benchmark in buffer:
            ops_idx = item_list.index("ops/sec;") - 1
            lat_idx = item_list.index("micros/op") - 1

            ops_ps = item_list[ops_idx]
            latency = item_list[lat_idx]

            append_file(benchmark, OPSPS, ops_ps)
            append_file(benchmark, LATENCY, latency)

            return True

    except Exception as e:
        print("{} {}: {}".format(traceback.format_exc(), e, item_list))
        
    return False

def generate_kernel_build(buffer):
    buffer = buffer.replace("'", "")
    print(buffer)
    item_list = buffer.split()
    i = 0

    for index, item in enumerate(item_list):
        if "SEC" in item:
            i = index + 1
            break

    val = float(item_list[i])

    append_file(test_name, "time", val)


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
    if test_name in (constants.ROCKS_DB_BP_TEST_NAME, constants.ROCKS_DB_NBP_TEST_NAME):
        return generate_rocksdb_bp(buffer)


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
        fetched = False
        for line in lines:
            if generate_values_rocksdb(line):
                fetched = True
        
        if not fetched:
            raise Exception("Failed to fetch data")

def get_data_kernel_build():
    with open("./rr-result.txt", "r", encoding='ISO-8859-1') as f:
        line = f.read()
        generate_kernel_build(line)

def get_data(cpu_num=None):
    global current_cpu_num
    if cpu_num:
        current_cpu_num = cpu_num

    if test_name in (constants.ROCKS_DB_BP_TEST_NAME, constants.ROCKS_DB_NBP_TEST_NAME):
        get_data_rocksdb()
    elif test_name == constants.REDIS_TEST_NAME:
        get_data_redis()
    elif test_name == constants.KERNEL_BUILD_TEST_NAME:
        get_data_kernel_build()


# init_csv_file()

qemu_binary = "../build/qemu-system-x86_64"
socket_path = "./test.sock"


async def end_record():
    try:
        qmp_client = QMPClient('test-rr')

        await qmp_client.connect(socket_path)

        with qmp_client.listener() as listener:
            res = await qmp_client.execute('rr-end-record')
            print(res)
            # if res["status"] == "failed":
            #     print("end record failed: {}".format(res))
            # elif res["status"] == "completed":
            #     print("end record finished")

        await qmp_client.disconnect()
    except Exception as e:
        print("Failed to end record {}".format(str(e)))


def gen_script(cpu_num):
    current_cpu_num = cpu_num

    extra_dev = ""
    extra_arg = ""
    disk_image = os.environ["KRR_DISK"]

    if test_name == constants.KERNEL_BUILD_TEST_NAME:
        disk_image = os.environ["KBUILD_DISK"]

    elif test_name == constants.REDIS_TEST_NAME:
        disk_image = os.environ["REDIS_DISK"]

    ivshmem = "-object memory-backend-file,size=32768M,share,mem-path=/dev/shm/ivshmem,id=hostmem -device ivshmem-plain,memdev=hostmem"

    if mode == "kernel_rr":
        kernel_image = os.environ["KRR_SMP_IMG"]

        if cpu_num == "1":
            kernel_image = os.environ["KRR_UNI_IMG"]

    elif mode == "baseline" or mode == "whole_system_rr":
        kernel_image = os.environ["BL_IMG"]

    if mode == "whole_system_rr":
        extra_arg += "-whole-system 1 "

    if mode == "baseline":
        extra_arg += "-ignore-record 1 "

    if test_name == constants.ROCKS_DB_BP_TEST_NAME:
        extra_dev = " -drive file=../build/nvm.img,if=none,id=nvm -device nvme,serial=deadbeef,drive=nvm"

    if test_name == constants.REDIS_TEST_NAME:
        extra_dev = " -netdev tap,id=net0,ifname=tap0,script=no,downscript=no -device e1000,netdev=net0"

    if test_name == constants.ROCKS_DB_NBP_TEST_NAME:
        extra_dev = " -drive file=../build/nkbypass.img,id=nvm,if=none -device nvme,serial=deadbeef,drive=nvm"

        if mode == "kernel_rr":
            extra_arg += "-whole-system 1 "

    qemu_base_cmd = """
    {qemu_binary} -kernel {kernel_image} \
    -accel kvm -smp {cpu_num} -cpu host -no-hpet -m 8G -append \
    "root=/dev/sda rw init=/lib/systemd/systemd tsc=reliable console=ttyS0 noavx benchmark={benchmark}" \
    -hda {disk_image} \
    {ivshmem} -vnc :00 -D rec.log {extra_dev} -exit-record 1 \
    -qmp unix:{socket_path},server=on,wait=off -checkpoint-interval 0 {extra_arg}
    """.format(
        qemu_binary=qemu_binary, kernel_image=kernel_image,
        benchmark=benchmark,
        disk_image=disk_image, cpu_num=cpu_num,
        ivshmem=ivshmem, extra_dev=extra_dev,
        socket_path=socket_path,
        extra_arg=extra_arg,
    )

    return qemu_base_cmd


def test_run(cpu_num):
    qemu_base_cmd = gen_script(cpu_num)

    print("QEMU CMD: {}".format(qemu_base_cmd))

    os.system("rm -f /dev/shm/ivshmem")
    os.system("modprobe -r kvm_intel;modprobe -r kvm;modprobe kvm_intel;modprobe kvm")
    os.system("sync")
    os.system("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null")
    os.system("rm -f /dev/shm/record")

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
    time.sleep(1)

    t = 360
    if mode == "baseline":
        t = 1000000

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

        if cnt > t:
            if os.path.exists("/dev/shm/record"):
                print("Record started, still wait")
                cnt = 0
                continue

            print("Timeout and end record")
            asyncio.run(end_record())
            time.sleep(1)
            os.system("kill $(pgrep qemu)")
            time.sleep(1)
            return -1

    print("return code {}".format(rc))

    try:
        get_data()
    except Exception as e:
        print("{}".format(str(e)))
        return -1

    return 0


parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

parser.add_argument("--mode", default="kernel_rr")
parser.add_argument("--test", default=constants.ROCKS_DB_BP_TEST_NAME)
parser.add_argument("--parseonly", default="false")
parser.add_argument("--startfrom", default="1")
parser.add_argument("--cpus", default=",".join(cpu_nums))
parser.add_argument("--replace", default="false")
parser.add_argument("--replacetrial", default=0)
parser.add_argument("--benchmark", default="fillseq")
parser.add_argument("--gen_script_only", default="false")
args = parser.parse_args()

mode = args.mode
test_name = args.test
benchmark = args.benchmark
cpu_nums = args.cpus.split(",")
replace_trial = int(args.replacetrial)

if args.replace == "true":
    replace_old = True


if args.gen_script_only == "true":
    cmd = gen_script(args.startfrom)
    print("cmd write to file scrpt.sh")

    try:
        os.remove("./script.sh")
    except:
        pass

    with open("./script.sh", 'w') as f:
        f.write(cmd)
    
    exit(0)

if args.parseonly == "true":
    get_data(args.startfrom)
else:
    print("mode={} test={}".format(mode, test_name))
    for cpu_num in cpu_nums[cpu_nums.index(args.startfrom):]:
        while test_run(cpu_num) < 0:
            print("Try again")
