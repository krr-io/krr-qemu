import os
import gzip
import csv
import sys

def read_rr_cost_file(file_path):
    rr_cost_data = {}
    with open(file_path, 'r') as file:
        for line in file:
            if ':' in line:
                key, value = line.split(':')
                rr_cost_data[key.strip()] = float(value.strip())
            elif '=' in line:
                key, value = line.split('=')
                rr_cost_data[key.strip()] = float(value.strip())
    return rr_cost_data

def get_file_size(file_path):
    return os.path.getsize(file_path)

def compress_file(file_path):
    compressed_file_path = f"{file_path}.gz"
    with open(file_path, 'rb') as f_in, gzip.open(compressed_file_path, 'wb') as f_out:
        f_out.writelines(f_in)
    return compressed_file_path

def get_compressed_file_size(file_path):
    compressed_file_path = compress_file(file_path)
    return get_file_size(compressed_file_path)

def write_to_csv(data, csv_file_path):
    headers = list(data.keys())
    rows = [data.values()]
    
    with open(csv_file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <benchmark>")
        sys.exit(1)
    
    benchmark_name = sys.argv[1]
    rr_cost_file_path = 'rr-cost.txt'
    kernel_rr_log_files = [
        'kernel_rr.log',
        'kernel_rr_dma.log',
        'kernel_rr_network.log'
    ]
    
    rr_cost_data = read_rr_cost_file(rr_cost_file_path)
    
    rr_cost_data = {'benchmark': benchmark_name, **rr_cost_data}
    
    for log_file in kernel_rr_log_files:
        rr_cost_data[f"{log_file}_size_bytes"] = get_file_size(log_file)
        rr_cost_data[f"{log_file}_compressed_size_bytes"] = get_compressed_file_size(log_file)
    
    csv_file_path = 'rr_cost_data.csv'
    write_to_csv(rr_cost_data, csv_file_path)

    print(f"Data has been written to {csv_file_path}")
