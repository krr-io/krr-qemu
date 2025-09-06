specific_ss.add(when: 'CONFIG_SOFTMMU', if_true: files('kernel_rr.c', 'mem_log.c', 'dma.c', 'network.c', 'verifier.c', 'replay_debugging.c'))
read_event = executable('krr-trace-helper', 'krr_trace_helper.c',
                       dependencies: [glib],
                       install: true,
                       build_by_default: true)
