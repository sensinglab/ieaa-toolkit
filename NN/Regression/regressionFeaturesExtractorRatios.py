import os
import sys
import pandas as pd
import concurrent.futures
from scapy.all import PcapReader, Dot11, Dot11ProbeReq, Dot11Elt
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

DISTRIBUTIONS_DIR = './Distributions'
OUTPUT_DATASET = 'regression_dataset_ratios.csv'
OUTPUT_REPORT = 'regression_dataset_report_ratios.txt'
INTERVAL_SEC = 300

MAX_CORES = os.cpu_count() or 4

INPUT_SCENARIOS = []

for file in os.listdir(DISTRIBUTIONS_DIR):
    if file.endswith('.pcap'):
        base_name = file[:-5]
        
        pcap_path = os.path.join(DISTRIBUTIONS_DIR, file)
        csv_path = os.path.join(DISTRIBUTIONS_DIR, f"{base_name}_5min_intervals.csv")

        if os.path.exists(csv_path):
            INPUT_SCENARIOS.append({
                'pcap': pcap_path,
                'csv': csv_path
            })
        else:
            print(f"[Warning] Found {file} but missing its matching _5min_intervals.csv. Skipping.")

total_scenarios = len(INPUT_SCENARIOS)
print(f"Auto-Scanned Directory: Found {total_scenarios} valid Scenario pairs.")
if not INPUT_SCENARIOS:
    print("Exiting: No valid PCAP/CSV pairs found.")
    sys.exit(0)

def fingerprint_getter(frame):
    ie = frame.getlayer(Dot11Elt)
    array_v = []

    while ie:
        if ie.ID in [1, 50, 127, 191, 70, 107, 59]:
            array_v.extend([ie.ID, ie.len])
            array_v.extend(ie.info)
        elif ie.ID == 3:
            array_v.append(ie.ID)
        elif ie.ID == 45:
            array_v.extend([ie.ID, ie.len])
            for i, c in enumerate(ie.info):
                if i != 4:
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        elif ie.ID == 221:
            array_v.extend([ie.ID, ie.len])
            for i, c in enumerate(ie.info):
                if i != 5 and i != 7:
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        ie = ie.payload
    
    return hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:]


def process_single_scenario(scenario):
    pcap_path = scenario['pcap']
    csv_path = scenario['csv']
    scenario_name = os.path.basename(pcap_path)
    
    extracted_rows = []
    intervals = {}
    last_seen_macs = {}

    try:
        df_truth = pd.read_csv(csv_path, sep=';', header=None)
        true_counts = (df_truth.notna() & (df_truth != '')).sum(axis=0).to_dict()

        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if not pkt.haslayer(Dot11ProbeReq):
                    continue

                mac = pkt.addr2
                time_val = float(pkt.time)
                
                try:
                    seq = pkt[Dot11].SC >> 4
                except:
                    seq = 0

                is_new_burst = True
                
                if mac in last_seen_macs:
                    last_pkt = last_seen_macs[mac]
                    time_diff = time_val - last_pkt['time']
                    seq_diff = (seq - last_pkt['seq']) % 4096 
                    
                    if time_diff <= 3.0 and seq_diff <= 15:
                        is_new_burst = False

                last_seen_macs[mac] = {'time': time_val, 'seq': seq}

                interval_idx = int(time_val // INTERVAL_SEC)
                
                if interval_idx not in intervals:
                    intervals[interval_idx] = {
                        'macs': set(),
                        'fingerprints': set(),
                        'packet_count': 0,
                        'burst_count': 0
                    }

                intervals[interval_idx]['packet_count'] += 1
                intervals[interval_idx]['macs'].add(mac)
                intervals[interval_idx]['fingerprints'].add(fingerprint_getter(pkt))
                
                if is_new_burst:
                    intervals[interval_idx]['burst_count'] += 1

        for idx, data in intervals.items():
            true_device_count = true_counts.get(idx, 0)
            
            row = {
                'Interval_ID': idx,
                'Total_Packets': data['packet_count'],
                'Total_Bursts': data['burst_count'],
                'Unique_MACs': len(data['macs']),
                'Unique_Fingerprints': len(data['fingerprints']),
                'Packets_Per_Burst': data['packet_count'] / data['burst_count'],
                'Packets_Per_MAC': data['packet_count'] / max(1, len(data['macs'])),
                'Packets_Per_Fingerprint': data['packet_count'] / max(1, len(data['fingerprints'])),
                'Bursts_Per_MAC': data['burst_count'] / max(1, len(data['macs'])),
                'Bursts_Per_Fingerprint': data['burst_count'] / max(1, len(data['fingerprints'])),
                'MACs_Per_Fingerprint': len(data['macs']) / max(1, len(data['fingerprints'])),
                'Target_Device_Count': true_device_count
            }
            extracted_rows.append(row)
            
    except Exception as e:
        print(f"Error processing {scenario_name}: {e}")
        
    return extracted_rows, scenario_name

all_extracted_rows = []

print(f"\nStarting Multiprocessing with {MAX_CORES} CPU Cores...")

with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_CORES) as executor:
    future_to_scenario = {executor.submit(process_single_scenario, scenario): scenario for scenario in INPUT_SCENARIOS}
    
    completed_count = 0
    for future in concurrent.futures.as_completed(future_to_scenario):
        completed_count += 1
        try:
            rows, scenario_name = future.result()
            all_extracted_rows.extend(rows)
            print(f"[{completed_count}/{total_scenarios}] Completed: {scenario_name}")
        except Exception as exc:
            scenario_name = os.path.basename(future_to_scenario[future]['pcap'])
            print(f"[{completed_count}/{total_scenarios}] FAILED: {scenario_name} generated an exception: {exc}")

if all_extracted_rows:
    df_dataset = pd.DataFrame(all_extracted_rows)
    df_dataset.to_csv(OUTPUT_DATASET, index=False)
    print(f"\nRegression dataset saved to '{OUTPUT_DATASET}' with shape: {df_dataset.shape} (Rows, Columns)")
    
    distribution = df_dataset['Target_Device_Count'].value_counts().sort_index()
    
    with open(OUTPUT_REPORT, 'w') as f:        
        f.write(f"{'True Device Count':<20} | {'Number of Intervals (Rows)':<25}\n")
        f.write("-" * 50 + "\n")
        
        for target_val, count in distribution.items():
            percentage = (count / len(df_dataset)) * 100
            f.write(f"{target_val:<20} | {count:<10} ({percentage:.1f}%)\n")
            
        f.write("-" * 50 + "\n")
        f.write(f"Total Usable Training Rows : {len(df_dataset)}\n")
        f.write(f"Minimum Crowd Size Seen    : {df_dataset['Target_Device_Count'].min()}\n")
        f.write(f"Maximum Crowd Size Seen    : {df_dataset['Target_Device_Count'].max()}\n")
        f.write(f"Average Crowd Size         : {df_dataset['Target_Device_Count'].mean():.2f}\n")
        
    print(f"Distribution report successfully saved to '{OUTPUT_REPORT}'\n")
else:
    print("\nFailure: No data was extracted.")