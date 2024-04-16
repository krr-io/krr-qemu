#!/bin/bash
mode=${1}
test=${2}
benchmark=${3}

shift
shift
shift

cmd="KRR_SMP_IMG=/home/silver/bzImage KRR_UNI_IMG=/home/silver/uni-guest/bzImage \
  KRR_DISK=/home/silver/rootfs-bypass.qcow2 BL_IMG=/home/silver/normal-guest/bzImage \
  KBUILD_DISK=/home/silver/rootfs-kbuild.qcow2 "

for i in 1 2 4 8;
do
  rm -f ./script

  KRR_SMP_IMG=/home/silver/bzImage KRR_UNI_IMG=/home/silver/uni-guest/bzImage \
  KRR_DISK=/home/silver/rootfs-bypass.qcow2 BL_IMG=/home/silver/normal-guest/bzImage \
  KBUILD_DISK=/home/silver/rootfs-kbuild.qcow2 \
  python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark} --gen_script_only="true" --startfrom=$i

  cat ./script.sh
  bash ./script.sh

  KRR_SMP_IMG=/home/silver/bzImage KRR_UNI_IMG=/home/silver/uni-guest/bzImage \
  KRR_DISK=/home/silver/rootfs-bypass.qcow2 BL_IMG=/home/silver/normal-guest/bzImage \
  KBUILD_DISK=/home/silver/rootfs-kbuild.qcow2 \
  python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark} --parseonly="true"

  echo "Done trial $i"
done
