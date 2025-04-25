#!/bin/bash
if [ $# -ne 2 ]; then
    echo "Usage: $0 <vmlinux path> <KRR qemu path>"
    echo "Example: $0 /root/vmlinux /root/qemu-tcg-kvm/"
    exit 1
fi

vmlinux=$1
prefix=$2

gdb $vmlinux -ex 'python import sys; sys.argv = ["'${prefix}'/kernel_rr/rr_gen_replay_symbols.py", "'${prefix}'/include/sysemu/kernel-rr.h"]' -ex 'source '${prefix}'kernel_rr/rr_gen_replay_symbols.py' -ex 'quit'

