#!/bin/bash

# Define the array
schemes=("baseline" "kernel_rr")
#schemes=("kernel_rr")

test=${1}
basedir="/users/sishuaig"

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

    for benchmark in readrandom readseq readwhilewriting readwhilescanning seekrandom;
    do
        for i in 1 2 3 4 5;
        do
            cd ${basedir}/qemu-tcg-kvm/kernel_rr/;bash observer_script.sh $scheme $test $benchmark
            if [ -f "/dev/shm/quit" ]; then
                    echo "Ending test..."
                    exit 0
            fi
        done
    done
done
