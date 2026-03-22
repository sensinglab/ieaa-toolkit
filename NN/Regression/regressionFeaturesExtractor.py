import os
import sys
import pandas as pd
from scapy.all import PcapReader, Dot11ProbeReq, Dot11Elt
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

DISTRIBUTIONS_DIR = './Distributions'
OUTPUT_DATASET = 'regression_dataset.csv'
OUTPUT_REPORT = 'regression_dataset_report.txt'
INTERVAL_SEC = 300

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

# Processing
all_extracted_rows = []

for idx_scenario, scenario in enumerate(INPUT_SCENARIOS, 1):
    pcap_path = scenario['pcap']
    csv_path = scenario['csv']
    
    print(f"\n[{idx_scenario}/{total_scenarios}] Starting Scenario Processing...")
    
    if not os.path.exists(pcap_path) or not os.path.exists(csv_path):
        print(f"  - Skipping Scenario: Missing .pcap or .csv file!")
        continue

    print(f"  - Reading Ground Truth from {csv_path}...")
    df_truth = pd.read_csv(csv_path, sep=';', header=None)
    # Count how many non-empty cells exist in each column (interval)
    true_counts = (df_truth.notna() & (df_truth != '')).sum(axis=0).to_dict()

    print(f"  - Processing packets from {pcap_path}...")
    intervals = {}

    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if not pkt.haslayer(Dot11ProbeReq):
                continue

            interval_idx = int(pkt.time // INTERVAL_SEC)
            
            if interval_idx not in intervals:
                intervals[interval_idx] = {
                    'macs': set(),
                    'fingerprints': set(),
                    'packet_count': 0
                }

            intervals[interval_idx]['packet_count'] += 1
            intervals[interval_idx]['macs'].add(pkt.addr2)
            intervals[interval_idx]['fingerprints'].add(fingerprint_getter(pkt))

    print(f"  - Compiling features...")
    for idx, data in intervals.items():
        true_device_count = true_counts.get(idx, 0) # Default to 0 if not found
        
        row = {
            'Interval_ID': idx,
            'Total_Packets': data['packet_count'],
            'Unique_MACs': len(data['macs']),
            'Unique_Fingerprints': len(data['fingerprints']),
            'Packets_Per_Fingerprint': data['packet_count'] / max(1, len(data['fingerprints'])),
            'Target_Device_Count': true_device_count
        }
        all_extracted_rows.append(row)

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