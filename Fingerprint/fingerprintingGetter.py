from scapy.all import Dot11Elt, Dot11ProbeReq, rdpcap
import os
import sys
import argparse
import csv

sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

def frame_processing(frame):
    ie = frame.getlayer(Dot11Elt)
    array_v = []

    # Original
    # while ie:
    #     if ie.ID in [1, 50, 59, 70, 107, 191]:  # Supported Rates, Extended Supported Rates, Supported Operating Classes, RM Enabled Capabilities, Interworking, VHT Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         array_v.extend(ie.info)
    #     elif ie.ID == 3:                        # DS Parameter Set
    #         array_v.append(ie.ID)
    #     elif ie.ID == 45:                       # HT Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 4:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 127:                      # Extended Capabilities
    #         array_v.append(ie.ID)
    #         for c in ie.info:
    #             array_v.append(c)
    #     elif ie.ID == 221:                      # Vendor Specific
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if(i != 5 and i != 7):
    #                 array_v.append(c)
    #             else:
    #                 array_v.append(ord('0'))
    #     ie = ie.payload

    # s/DV
    # while ie:
    #     if ie.ID in [1, 50, 59, 70, 107, 191]:  # Supported Rates, Extended Supported Rates, Supported Operating Classes, RM Enabled Capabilities, Interworking, VHT Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         array_v.extend(ie.info)
    #     elif ie.ID == 3:                        # DS Parameter Set
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 0:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 45:                       # HT Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 1:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 127:                      # Extended Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i in [0, 2, 3, 5, 7, 8, 9]:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 221:                      # Vendor Specific
    #         array_v.extend([ie.ID, ie.len])
    #         # Microsoft: 00:50:F2 | Epigram: 00:90:4C | Wi-Fi Alliance: 50:6F:9A
    #         is_microsoft = False

    #         if len(ie.info) >= 3:
    #             if ie.info[0] == 0x00 and ie.info[1] == 0x50 and ie.info[2] == 0xF2:
    #                 is_microsoft = True
            
    #         for i, c in enumerate(ie.info):
    #             if is_microsoft and i == 5:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     ie = ie.payload

    # s/DV e PV
    # while ie:
    #     if ie.ID in [1, 59, 70, 107, 191]:      # Supported Rates, Supported Operating Classes, RM Enabled Capabilities, Interworking, VHT Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         array_v.extend(ie.info)
    #     elif ie.ID == 3:                        # DS Parameter Set
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 0:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 45:                       # HT Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 1:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 50:                       # Extended Supported Rates
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i in [0, 1, 2, 3]:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 127:                      # Extended Capabilities
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i in [0, 2, 3, 4, 5, 6, 7, 8, 9]:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 221:                      # Vendor Specific
    #         array_v.extend([ie.ID, ie.len])
    #         # Microsoft: 00:50:F2 | Epigram: 00:90:4C | Wi-Fi Alliance: 50:6F:9A
    #         is_microsoft = False
    #         is_epigram = False
    #         is_wifi_alliance = False

    #         if len(ie.info) >= 3:
    #             if ie.info[0] == 0x00 and ie.info[1] == 0x50 and ie.info[2] == 0xF2:
    #                 is_microsoft = True
    #             elif ie.info[0] == 0x00 and ie.info[1] == 0x90 and ie.info[2] == 0x4C:
    #                 is_epigram = True
    #             elif ie.info[0] == 0x50 and ie.info[1] == 0x6F and ie.info[2] == 0x9A:
    #                 is_wifi_alliance = True
            
    #         for i, c in enumerate(ie.info):
    #             if is_microsoft and i == 5:
    #                 array_v.append(ord('0'))
    #             elif is_epigram and i in [8, 9]:
    #                 array_v.append(ord('0'))
    #             elif is_wifi_alliance and i == 6:
    #                 array_v.append(ord('0'))
    #             else:
    #                 array_v.append(c)
    #     ie = ie.payload

    # Equilibrada
    # while ie:
    #     if ie.ID in [1, 50, 107, 191]:
    #         array_v.extend([ie.ID, ie.len])
    #         array_v.extend(ie.info)
    #     elif ie.ID == 45:
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 1:
    #                 # 2nd bit is 0x40. Inverse mask is 0xBF (10111111)
    #                 array_v.append(c & 0xBF)
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 127:
    #         array_v.extend([ie.ID, ie.len])
    #         for i, c in enumerate(ie.info):
    #             if i == 3:
    #                 # 6th bit is 0x04. Inverse mask is 0xFB (11111011)
    #                 array_v.append(c & 0xFB)
    #             else:
    #                 array_v.append(c)
    #     elif ie.ID == 221:
    #         array_v.extend([ie.ID, ie.len])
    #         is_microsoft = False
    #         is_epigram = False

    #         if len(ie.info) >= 3:
    #             if ie.info[0] == 0x00 and ie.info[1] == 0x50 and ie.info[2] == 0xF2:
    #                 is_microsoft = True
    #             elif ie.info[0] == 0x00 and ie.info[1] == 0x90 and ie.info[2] == 0x4C:
    #                 is_epigram = True
            
    #         for i, c in enumerate(ie.info):
    #             # Microsoft (00:50:F2) - Index 5: 8th bit
    #             if is_microsoft and i == 5:
    #                 # 8th bit is 0x01. Inverse mask is 0xFE (11111110)
    #                 array_v.append(c & 0xFE)
    #             elif is_epigram and i == 8:
    #                 # 2nd (0x40) + 3rd (0x20) = 0x60. Inverse mask is 0x9F (10011111)
    #                 array_v.append(c & 0x9F)
    #             elif is_epigram and i == 9:
    #                 # 4th bit is 0x10. Inverse mask is 0xEF (11101111)
    #                 array_v.append(c & 0xEF)
    #             else:
    #                 array_v.append(c)
                    
    #     ie = ie.payload

    # Testagem
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
    
    footprint_mac = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper()
    return footprint_mac

def parse_placement_summary(summary_file):
    pcaps = set()
    if not os.path.exists(summary_file):
        raise FileNotFoundError(f"Summary file not found: {summary_file}")
        
    with open(summary_file, 'r', encoding='utf-8') as f:
        start_reading = False
        for line in f:
            if line.startswith('------------------------------------------------------------'):
                start_reading = True
                continue
            if start_reading:
                parts = line.strip().split()
                if parts:
                    pcaps.add(parts[0])
    return list(pcaps)

def extract_device_id(filename):
    base = os.path.basename(filename)
    if base.endswith('.pcap'):
        base = base[:-5]
    if '-ch' in base:
        return base.split('-ch')[0]
    elif '-' in base:
        return base.split('-')[0]
    return base

def load_metadata(csv_path):
    metadata = {}
    if not csv_path or not os.path.exists(csv_path):
        print("Warning: Metadata CSV not found or not provided. Fields will be 'Unknown'.")
        return metadata

    with open(csv_path, mode='r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            dev_id = row.get('Device ID', '').strip()
            if dev_id:
                metadata[dev_id] = {
                    'Device OS': row.get('Device OS', 'Unknown'),
                    'Device OS version': row.get('Device OS version', 'Unknown'),
                    'Device vendor': row.get('Device vendor', 'Unknown'),
                    'Device model': row.get('Device model', 'Unknown')
                }
    return metadata

def get_fingerprints(pcaps_list, metadata, output_file, output_chunks_file):
    global_fingerprints = {}
    chunked_fingerprints = {}  # Structure: {chunk_idx: {device_id: set(fps)}}

    for pcap_file in pcaps_list:
        full_path = os.path.join("/home/kali/Detection_Testing/DataCH1", pcap_file)
        
        try:
            packets = rdpcap(full_path)
        except Exception as e:
            print(f"Error reading {full_path}: {e}")
            continue
        
        probe_reqs = [pkt for pkt in packets if pkt.haslayer(Dot11ProbeReq)]
        if not probe_reqs:
            print(f"No Probe Requests found in {pcap_file}.")
            continue

        device_id = extract_device_id(pcap_file)
        print(f"Loaded {len(probe_reqs)} packets from {pcap_file} (Mapped to Device ID: {device_id})")

        if device_id not in global_fingerprints:
            global_fingerprints[device_id] = set()

        # Find t=0 for this specific file
        pcap_start_time = float(probe_reqs[0].time)

        for pkt in probe_reqs:
            fp = frame_processing(pkt)
            
            # Global Tracking
            global_fingerprints[device_id].add(fp)
            
            # Chunk Tracking (5 minutes = 300 seconds)
            ts_norm = float(pkt.time) - pcap_start_time
            chunk_idx = int(ts_norm / 300)
            
            if chunk_idx not in chunked_fingerprints:
                chunked_fingerprints[chunk_idx] = {}
            if device_id not in chunked_fingerprints[chunk_idx]:
                chunked_fingerprints[chunk_idx][device_id] = set()
                
            chunked_fingerprints[chunk_idx][device_id].add(fp)

    # ---------------------------------------------------------
    # GENERATE GLOBAL REPORT (Original File)
    # ---------------------------------------------------------
    print("\nOrganizing Global data by Device Model and generating report...")
    models_grouping_global = {}
    for dev_id, fps in global_fingerprints.items():
        meta = metadata.get(dev_id, {'Device OS': 'Unknown', 'Device OS version': 'Unknown', 'Device vendor': 'Unknown', 'Device model': 'Unknown'})
        model = meta['Device model']

        if model not in models_grouping_global:
            models_grouping_global[model] = {'all_unique_fps': set(), 'devices': []}
        
        models_grouping_global[model]['all_unique_fps'].update(fps)
        models_grouping_global[model]['devices'].append((dev_id, meta, fps))

    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Device ID', 'Device OS', 'Device OS version', 'Device vendor', 'Device model', 'Fingerprints', 'Nº FP'])

        for model in sorted(models_grouping_global.keys()):
            model_data = models_grouping_global[model]
            total_fps_for_model = len(model_data['all_unique_fps'])
            sorted_devices = sorted(model_data['devices'], key=lambda x: x[0])
            
            for idx, (dev_id, meta, fps) in enumerate(sorted_devices):
                fps_str = ", ".join(sorted(list(fps)))
                num_fp_display = total_fps_for_model if idx == 0 else ""
                writer.writerow([dev_id, meta['Device OS'], meta['Device OS version'], meta['Device vendor'], model, fps_str, num_fp_display])
            writer.writerow([])
            
    print(f"Global Report successfully saved to {output_file}")

    # ---------------------------------------------------------
    # GENERATE CHUNKED REPORT (New File)
    # ---------------------------------------------------------
    print("Organizing 5-Minute Chunk data and generating report...")
    with open(output_chunks_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Time Window', 'Device ID', 'Device OS', 'Device OS version', 'Device vendor', 'Device model', 'Fingerprints', 'Nº FP'])

        for chunk_idx in sorted(chunked_fingerprints.keys()):
            time_window = f"{chunk_idx * 5}-{(chunk_idx + 1) * 5} min"
            
            # Group devices by model within this specific chunk
            models_grouping_chunk = {}
            for dev_id, fps in chunked_fingerprints[chunk_idx].items():
                meta = metadata.get(dev_id, {'Device OS': 'Unknown', 'Device OS version': 'Unknown', 'Device vendor': 'Unknown', 'Device model': 'Unknown'})
                model = meta['Device model']

                if model not in models_grouping_chunk:
                    models_grouping_chunk[model] = {'all_unique_fps': set(), 'devices': []}
                
                models_grouping_chunk[model]['all_unique_fps'].update(fps)
                models_grouping_chunk[model]['devices'].append((dev_id, meta, fps))

            for model in sorted(models_grouping_chunk.keys()):
                model_data = models_grouping_chunk[model]
                total_fps_for_model = len(model_data['all_unique_fps'])
                sorted_devices = sorted(model_data['devices'], key=lambda x: x[0])
                
                for idx, (dev_id, meta, fps) in enumerate(sorted_devices):
                    fps_str = ", ".join(sorted(list(fps)))
                    num_fp_display = total_fps_for_model if idx == 0 else ""
                    writer.writerow([time_window, dev_id, meta['Device OS'], meta['Device OS version'], meta['Device vendor'], model, fps_str, num_fp_display])
                writer.writerow([])
            
            # Separator between chunks
            writer.writerow(['---', '---', '---', '---', '---', '---', '---', '---'])

    print(f"Chunked Report successfully saved to {output_chunks_file}")


parser = argparse.ArgumentParser(description="Extract fingerprints based on placement summary and output grouped CSV tables.")
parser.add_argument('--summary', default=None, required=True, help='Path to the placement_summary.txt file.')
parser.add_argument('--meta', default=None, required=False, help='Path to the devices metadata CSV file.')
parser.add_argument('--output', default='fingerprints_report.csv', required=False, help='Output CSV filename for global data.')
parser.add_argument('--output_chunks', default='chunked_fingerprints_report.csv', required=False, help='Output CSV filename for 5-minute chunked data.')
args = parser.parse_args()

pcaps_list = parse_placement_summary(args.summary)
if not pcaps_list:
    raise ValueError("No PCAP files could be extracted from the summary file.")

metadata_dict = load_metadata(args.meta)

get_fingerprints(pcaps_list, metadata_dict, args.output, args.output_chunks)