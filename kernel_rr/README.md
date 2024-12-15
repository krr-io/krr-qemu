# KRR (Kernel RR)

## Removed features for kernel RR

1. Since we replay in TCG now, temporarily disabled xsaves and xsavec (which are not supported in TCG) features in KVM for compatibility of TCG, so the guest would use xsaveopt;

2. Disabled kvmclock device in QEMU;

3. Disabled KVM pvclock, by removing KVM_FEATURE_CLOCKSOURCE and KVM_FEATURE_CLOCKSOURCE2 features exposed to guest in KVM, so that the KVM won't update the guest memory, this is for us to do memory verification;

4. Set the CPU_BASED_RDTSC_EXITING bit for VMX so that the RDTSC would be trapped to hypervisor.


## Use KRR for Replay
Using KRR for replay doesn't need KVM's support since it's purely userspace (QEMU TCG), what you need is just an initial snapshot and event trace.

1. First, get the code of kernel RR QEMU code:
```
git clone -b rr-paravirt https://github.com/rssys/qemu-tcg-kvm.git
```

2. Compile:
```
cd qemu-tcg-kvm
mkdir build
cd build
../configure --target-list=x86_64-softmmu
make -j
```

3. Replay prepare:
As an example, my replay snapshot is named as "test1".

First, make sure you have these 4 files under your `build` directory from last step:
- test1: the snapshot file storing VM's initial memory state;
- kernel_rr.log: main event trace;
- kernel_rr_dma.log: Disk DMA data;
- kernel_rr_network.log: Network data.

You also need the original disk image file you used for record, it's not going to be actually read in replay, it's just for consistent hardware configuration between record and replay.

4. Replay:
Execute basic command:
```
../build/qemu-system-x86_64 -accel tcg -smp 1 -cpu Broadwell -no-hpet -m 2G -hda <disk image> -device ivshmem-plain,memdev=hostmem -object memory-backend-file,size=1024M,share,mem-path=/dev/shm/ivshmem,id=hostmem -kernel-replay test1 -singlestep -D rec.log -replay-log-bound start=0 -monitor stdio -vnc :0
```
And it will automatically start replaying.

In the command: `-kernel-replay` is the name of your snapshot file;

At the end, it displays something below as a summary of the replay:
```
Replay executed in 8.308527 seconds
=== Event Stats ===
Interrupt: 1207
Syscall: 2196
Exception: 392
CFU: 1103
GFU: 502
Random: 0
IO Input: 75672
RDTSC: 35249
Strnlen: 0
RDSEED: 0
PTE: 4349
Inst Sync: 0
DMA Buf Size: 0
Total Replay Events: 120681
Time(s): 0.00
```

### Use gdb to debug replay:
If you wanna debug it using gdb, you should firstly have the `vmlinux` of the same kernel used by the guest.

1. Simply add `-S -s` options into the QEMU replay commandline above, this will start a gdb-server insdie QEMU.
2. In another command line, execute 
```
gdb vmlinux
```
3. In gdb console, execute:
```
target remote :1234
```
This will connect to the gdb-server.

4. Then you can just use gdb commands just like debugging a regular program.

### Log out instructions
Using following parameter could log out instructions & associated registers from N1th to N2th instruction.
```
-replay-log-bound start=N1,end=N2
```
The log file is specified by `-D logfile`.
