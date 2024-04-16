DATA_DIR = "test_data"


REDIS_TP = "redisthroughput"
AVG_LAT = "avg_latency"
THROUGHPUT = "throughput"
OPSPS = "opsps"
LATENCY = "latency"


ROCKS_DB_BP_TEST_NAME = "rocksdb_kernel_bypass"
ROCKS_DB_NBP_TEST_NAME = "rocksdb"
REDIS_TEST_NAME = "redis"
KERNEL_BUILD_TEST_NAME = "kernel_build"

mode = "kernel_rr"
test_name = ROCKS_DB_NBP_TEST_NAME


CPU_NUMS = ["1", "2", "4", "8", "16"]

palette = {'kernel_rr': '#cc29df', 'baseline': '#28ca69', 'whole_system_rr': '#2868de'}

