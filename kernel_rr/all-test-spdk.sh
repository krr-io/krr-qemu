#!/bin/bash

# Parse command-line arguments
test=${1}
basedir=${2:-"/users/sishuaig"}  # Default to /users/sishuaig if not provided
iterations=${3:-5}               # Default to 5 iterations if not provided
schemes_arg=${4:-"baseline,kernel_rr,whole_system_rr"}  # Default to baseline,kernel_rr,whole_system_rr if not provided

# Convert comma-separated schemes argument to an array
IFS=',' read -r -a schemes <<< "$schemes_arg"

echo "Testing on $schemes_arg"

# Loop through the array
for scheme in "${schemes[@]}"
do
    # Set the branch variable based on the scheme
    case $scheme in
        "baseline")
            branch="native"
            ;;
        "kernel_rr")
            branch="rr-para"
            ;;
        "whole_system_rr")
            branch="all-rr"
            ;;
        *)
            echo "Unknown scheme: $scheme"
            continue
            ;;
    esac

    # Output the current scheme and its corresponding branch
    echo "Scheme: $scheme, Branch: $branch"
    cd ${basedir}/kernel-rr-linux/;git checkout $branch;sh replace.sh

    for testmode in rocksdb rocksdb_kernel_bypass; do
        for benchmark in readseq seekrandom readrandom fillseq fillrandom deleteseq appendrandom;
        do
            for i in $(seq 1 $iterations);
            do
                cd ${basedir}/qemu-tcg-kvm/kernel_rr/;bash observer_script_spdk.sh $scheme $testmode $benchmark $basedir
                if [ -f "/dev/shm/quit" ]; then
                        echo "Ending test..."
                        exit 0
                fi
            done
        done
    done
done
