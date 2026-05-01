import os
import sys
import pandas as pd
import joblib
import concurrent.futures
from scapy.all import PcapReader, Dot11ProbeReq, Dot11Elt

DISTRIBUTIONS_DIR = './Distributions'
OUTPUT_DATASET = 'regression_dataset_class.csv'
OUTPUT_REPORT = 'regression_dataset_class_report.txt'
CLASSIFIER_MODEL_PATH = '/home/kali/Detection_Testing/NN/Classification/wifi_device_classifier.pkl'
INTERVAL_SEC = 300

allowed_ids = {
    1: 'IE_SupportedRates',
    3: 'IE_DSSSParameterSet',
    45: 'IE_HTCapabilities',
    50: 'IE_ExtendedSupportedRates',
    59: 'IE_SupportedOperatingClasses',
    70: 'IE_RMEnabledCapabilities',
    107: 'IE_Interworking',
    127: 'IE_ExtendedCapabilities',
    191: 'IE_VHTCapabilities',
    221: 'IE_VendorSpecific'
}

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

def parse_packet_to_dict(pkt):
    row = {'MAC': pkt.addr2}
    ie = pkt.getlayer(Dot11Elt)
    
    while ie:
        if ie.ID in [1, 3, 45, 50, 59, 70, 107, 191]:
            col_name = allowed_ids[ie.ID]
            row[col_name] = ie.info.hex()
        elif ie.ID == 221:
            if len(ie.info) >= 3:
                oui = ie.info[:3].hex()
                col_name = f'IE_Vendor_{oui}'
                row[col_name] = row.get(col_name, "") + ie.info[3:].hex()
        ie = ie.payload
    return row

def process_single_scenario(scenario):
    classifier_model = joblib.load(CLASSIFIER_MODEL_PATH)
    expected_cols = classifier_model.named_steps['preprocessor'].feature_names_in_

    pcap_path = scenario['pcap']
    csv_path = scenario['csv']
    scenario_name = os.path.basename(pcap_path)
    
    extracted_rows = []
    intervals = {}

    try:
        df_truth = pd.read_csv(csv_path, sep=';', header=None)
        true_counts = (df_truth.notna() & (df_truth != '')).sum(axis=0).to_dict()

        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if not pkt.haslayer(Dot11ProbeReq): 
                    continue
                
                mac = pkt.addr2
                time_val = float(pkt.time)

                interval_idx = int(time_val // INTERVAL_SEC)
                if interval_idx not in intervals:
                    intervals[interval_idx] = {'packets': [], 'macs': set()}

                intervals[interval_idx]['packets'].append(parse_packet_to_dict(pkt))
                intervals[interval_idx]['macs'].add(mac)

        for idx, data in intervals.items():
            df_interval = pd.DataFrame(data['packets'])
            total_packets = len(df_interval)
            
            df_clean = df_interval.drop_duplicates(subset=[c for c in df_interval.columns if c != 'MAC'])
            X_raw = df_clean.drop(columns=['MAC'], errors='ignore')

            unique_classes = 0
            if not X_raw.empty:
                X_aligned = X_raw.reindex(columns=expected_cols)

                for col in X_aligned.columns:
                    if any(num_pattern in col for num_pattern in ["IE_HTCapabilities_", "IE_ExtCap_", "Sequence_Number"]):
                        X_aligned[col] = pd.to_numeric(X_aligned[col]).fillna(-1)
                    else:
                        X_aligned[col] = X_aligned[col].fillna('MISSING').astype(str)

                predictions = classifier_model.predict(X_aligned)
                unique_classes = len(set(predictions))

            row = {
                'Interval_ID': idx,
                'Total_Packets': total_packets,
                'Unique_MACs': len(data['macs']),
                'Unique_Classes': unique_classes,
                'Packets_Per_Class': total_packets / max(1, unique_classes),
                'Target_Device_Count': true_counts.get(idx, 0)
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