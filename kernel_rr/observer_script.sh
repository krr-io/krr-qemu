#!/bin/bash
mode=${1}
test=${2}
benchmark=${3}
basedir=${4}

shift
shift
shift

env_vars="KRR_SMP_IMG=${basedir}/bzImageRR KRR_UNI_IMG=${basedir}/bzImageRR \
  KRR_DISK=${basedir}/rootfs-bypass.qcow2 BL_IMG=${basedir}/bzImageNative \
  KBUILD_DISK=${basedir}/rootfs-kbuild.qcow2 "

missing_duration=100
file="/dev/shm/record"
result="./rr-result.txt"

mkdir -p test_data

exec_qemu() {
  cpu_num=$1

  rm -f ./script

  env $env_vars python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark} --gen_script_only="true" --startfrom=$cpu_num

  sleep 1
  rm -f /dev/shm/ivshmem
  modprobe -r kvm_intel;modprobe -r kvm;modprobe kvm_intel;modprobe kvm
  sync
  echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
  rm -f $file
  rm -f $result

  cat ./script.sh
  bash ./script.sh &

  timer=0

  sleep 5

  rr_set_cpu_aff

  while true; do
    if pgrep qemu > /dev/null; then
      true
    else
      if [ -f "$result" ]; then
        echo "Test finished, result is here"
        return 0
      else
        echo "Process ends, but result is missing"
        return 1
      fi
    fi

    if [ $mode == "baseline" ];then
      sleep 1
      continue
    fi

    if [ -f "$file" ]; then
        # If the file exists, reset the timer
        timer=0
    else
        # If the file does not exist, increment the timer
        ((timer++))
        if [ $timer -ge $missing_duration ]; then
            echo "File has been missing for $missing_duration seconds. Killing qemu process."
            # Kill the qemu process
            kill -9 $(pgrep qemu)
            # Reset the timer after action
            timer=0
            return 1
        fi
        sleep 1
    fi
  done
}

echo ${test} $benchmark

for i in 1 2 4 8 16 32;
do
  while true; do
    exec_qemu $i
    if [ $? -eq 0 ]; then
        echo "The function returned 0 - success."
        env $env_vars python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark} --parseonly="true" --startfrom=$i
        python_exit=$?
        if [ $python_exit -ne 0 ]; then
            echo "Python script failed with exit code $python_exit, try again."
        else
            break
        fi
    else
        echo "The function returned non-0 - failure."
        sleep 5
    fi
  done

  #python3 get_cost.py $mode $i $benchmark
  echo "Done trial $i"
done
