#!/bin/bash
mode=${1}
test=${2}
benchmark=${3}

shift
shift
shift

env_vars="KRR_SMP_IMG=/home/silver/bzImage KRR_UNI_IMG=/home/silver/uni-guest/bzImage \
  KRR_DISK=/home/silver/rootfs-bypass.qcow2 BL_IMG=/home/silver/normal-guest/bzImage \
  KBUILD_DISK=/home/silver/rootfs-kbuild.qcow2 "

missing_duration=60
file="/dev/shm/record"
result="./rr-result.txt"

exec_qemu() {
  cpu_num=$1

  rm -f ./script

  env $env_vars python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark} --gen_script_only="true" --startfrom=$cpu_num

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
            pkill qemu
            # Reset the timer after action
            timer=0
            return 1
        fi
        sleep 1
    fi
  done
}

for i in 1 2 4 8;
do
  while true; do
    exec_qemu $i
    if [ $? -eq 0 ]; then
        echo "The function returned 0 - success."
        break
    else
        echo "The function returned non-0 - failure."
        sleep
    fi
  done

  env $env_vars python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark} --parseonly="true" --startfrom=$cpu_num

  echo "Done trial $i"
done
