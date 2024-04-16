!/bin/bash
mode=${1}
test=${2}
benchmark=${3}

shift
shift
shift

cmd="KRR_SMP_IMG=/home/silver/bzImage KRR_UNI_IMG=/home/silver/uni-guest/bzImage \
  KRR_DISK=/home/silver/rootfs-bypass.qcow2 BL_IMG=/home/silver/normal-guest/bzImage \
  KBUILD_DISK=/home/silver/rootfs-kbuild.qcow2 \
  python3 observer.py --mode=${mode} --test=${test} --benchmark=${benchmark}"

for i in `seq 3 3`;
do
  bash ${cmd} --gen_script_only="true"

  bash ./script.sh

  bash ${cmd} --parseonly="true"

  echo "Done trial $i"
done