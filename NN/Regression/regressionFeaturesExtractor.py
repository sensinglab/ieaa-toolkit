import os
import sys
import pandas as pd
import concurrent.futures
from scapy.all import PcapReader, Dot11ProbeReq, Dot11Elt
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

DISTRIBUTIONS_DIR = './Distributions'
OUTPUT_DATASET = 'regression_dataset_fing_20|20_300.csv'
OUTPUT_REPORT = 'regression_dataset_fing_20|20_300_report.txt'
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
        # 100% Stable standard IEs (No masking required)
        if ie.ID in [1, 45, 50, 59, 70, 107, 127, 191]:
            array_v.extend([ie.ID, ie.len])
            array_v.extend(ie.info)

        # Vendor Specific (221)
        elif ie.ID == 221:
            array_v.extend([ie.ID, ie.len])
            
            is_epigram = False

            if len(ie.info) >= 3:
                if ie.info[0] == 0x00 and ie.info[1] == 0x90 and ie.info[2] == 0x4C:
                    is_epigram = True
            
            for i, c in enumerate(ie.info):
                # Epigram (00:90:4C) - Mask Index 8: 2nd, 3rd bits (0x60) -> Inverse: 0x9F
                if is_epigram and i == 8:
                    array_v.append(c & 0x9F)
                    
                # Epigram (00:90:4C) - Mask Index 9: 4th bit (0x10) -> Inverse: 0xEF
                elif is_epigram and i == 9:
                    array_v.append(c & 0xEF)
                
                else:
                    array_v.append(c)
                    
        ie = ie.payload
    
    return hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:]

def process_single_scenario(scenario):
    pcap_path = scenario['pcap']
    csv_path = scenario['csv']
    scenario_name = os.path.basename(pcap_path)
    
    extracted_rows = []
    intervals = {}

    try:
        # Read Ground Truth
        df_truth = pd.read_csv(csv_path, sep=';', header=None)
        true_counts = (df_truth.notna() & (df_truth != '')).sum(axis=0).to_dict()

        # Read Packets
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

        # Compile Features
        for idx, data in intervals.items():
            true_device_count = true_counts.get(idx, 0)
            
            row = {
                'Interval_ID': idx,
                'Total_Packets': data['packet_count'],
                'Unique_MACs': len(data['macs']),
                'Unique_Fingerprints': len(data['fingerprints']),
                'Packets_Per_Fingerprint': data['packet_count'] / max(1, len(data['fingerprints'])),
                'Target_Device_Count': true_device_count
            }
            extracted_rows.append(row)
            
    except Exception as e:
        print(f"Error processing {scenario_name}: {e}")
        
    return extracted_rows, scenario_name

all_extracted_rows = []

print(f"\nStarting Multiprocessing with {MAX_CORES} CPU Cores...")

# Create a pool of workers
with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_CORES) as executor:
    # Submit all scenarios to the workers
    future_to_scenario = {executor.submit(process_single_scenario, scenario): scenario for scenario in INPUT_SCENARIOS}
    
    completed_count = 0
    # Process results exactly as they finish
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