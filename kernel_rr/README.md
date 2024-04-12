# Kernel RR

## Removed features for kernel RR

1. Since we replay in TCG now, temporarily disabled xsaves and xsavec (which are not supported in TCG) features in KVM for compatibility of TCG, so the guest would use xsaveopt;

2. Disabled kvmclock device in QEMU;

3. Disabled KVM pvclock, by removing KVM_FEATURE_CLOCKSOURCE and KVM_FEATURE_CLOCKSOURCE2 features exposed to guest in KVM, so that the KVM won't update the guest memory, this is for us to do memory verification;

4. Set the CPU_BASED_RDTSC_EXITING bit for VMX so that the RDTSC would be trapped to hypervisor.



## Generating graph
```
python3 gratph_generator.py --graphtest=<e.g., rocksdb-readwhilewriting> --graphdir=<parent dir of the csv files>
```
