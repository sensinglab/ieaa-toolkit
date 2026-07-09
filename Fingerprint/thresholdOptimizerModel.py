import os
import glob
import binascii
import csv
from scapy.all import rdpcap, Dot11Elt, Dot11ProbeReq
import sys

sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

# --- CONFIGURATION ---
PCAP_FOLDER = "/home/kali/Detection_Testing/NN/Data70(2)"
META_FILE = "/home/kali/Detection_Testing/Fingerprint/devices_metadata.csv"
CHUNK_SIZE_SEC = 300  # 5 minutes

GRID_INTRA_FLIP = [0.0, 0.05, 0.10, 0.15, 0.20]
GRID_MAX_DEV_UNSTABLE = [0.0, 0.05, 0.10, 0.15, 0.20]
GRID_COMMON_IE = [0.70]

ie_names = {
    1: "Supported Rates", 50: "Extended Supported Rates", 3: "DS Parameter Set",
    45: "HT Capabilities", 127: "Extended Capabilities", 191: "VHT Capabilities",
    70: "RM Enabled Capabilities", 107: "Interworking", 59: "Supported Operating Classes"
}

def extract_device_id(filename):
    base = os.path.basename(filename)
    if base.endswith('.pcap'): base = base[:-5]
    if '-ch' in base: return base.split('-ch')[0]
    elif '-' in base: return base.split('-')[0]
    return base

def load_metadata(csv_path):
    metadata = {}
    with open(csv_path, mode='r', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f, delimiter=';'):
            dev_id = row.get('Device ID', '').strip()
            if dev_id: metadata[dev_id] = row.get('Device model', 'Unknown')
    return metadata

def load_all_packets_by_model(pcap_files, metadata):
    print(("[1] Loading PCAPs and aligning all devices to start at t=0..."))
    model_packets = {}
    
    for pcap_path in pcap_files:
        dev_id = extract_device_id(pcap_path)
        model = metadata.get(dev_id, f"Unknown_Model_{dev_id}")
        
        try: packets = rdpcap(pcap_path)
        except: continue
        
        probe_reqs = [pkt for pkt in packets if pkt.haslayer(Dot11ProbeReq)]
        if not probe_reqs: continue
            
        pcap_start_time = float(probe_reqs[0].time)
        
        if model not in model_packets: 
            model_packets[model] = []
            
        for frame in probe_reqs:
            ts_norm = float(frame.time) - pcap_start_time
                
            raw_ies = []
            ie = frame.getlayer(Dot11Elt)
            while ie:
                if ie.ID in ie_names or ie.ID == 221:
                    raw_ies.append((ie.ID, ie.len, bytes(ie.info) if ie.info else b""))
                ie = ie.payload
                
            model_packets[model].append((ts_norm, raw_ies))
                
    return model_packets

def get_dynamic_rules(model_packets, intra_thresh, model_unstable_thresh, common_thresh):
    ie_payloads = {name: {m: [] for m in model_packets.keys()} for name in ie_names.values()}
    
    for model, packets in model_packets.items():
        for ts, pkt_ies in packets:
            found_in_pkt = {name: None for name in ie_payloads.keys()}
            for ie_id, ie_len, ie_info in pkt_ies:
                if ie_id in ie_names:
                    found_in_pkt[ie_names[ie_id]] = bin(int(binascii.hexlify(ie_info), 16))[2:].zfill(len(ie_info) * 8) if ie_info else ""
                elif ie_id == 221 and len(ie_info) >= 3:
                    oui_hex = binascii.hexlify(ie_info[:3]).decode('utf-8').upper()
                    vendor_name = f"Vendor [{oui_hex[0:2]}:{oui_hex[2:4]}:{oui_hex[4:6]}]"
                    if vendor_name not in ie_payloads: ie_payloads[vendor_name] = {m: [] for m in model_packets.keys()}
                    found_in_pkt[vendor_name] = bin(int(binascii.hexlify(ie_info), 16))[2:].zfill(len(ie_info) * 8)
            
            for name, b_str in found_in_pkt.items():
                if b_str is not None: ie_payloads[name][model].append(b_str)

    model_count = len(model_packets)
    dynamic_masks = {} 
    ies_to_drop = set()
    
    for ie_name, model_dict in ie_payloads.items():
        active_models = {m: p for m, p in model_dict.items() if len(p) > 0}
        presence_rate = len(active_models) / model_count if model_count > 0 else 0
        if presence_rate == 0: continue
            
        max_bits = max(len(p) for payloads in active_models.values() for p in payloads) if active_models else 0
        accepted_bits = 0
        volatile_bits = []
        
        for bit_idx in range(max_bits):
            models_unstable = 0
            maj_bits = []
            for model, payloads in active_models.items():
                bits_at_idx = [int(p[bit_idx]) if bit_idx < len(p) else 0 for p in payloads]
                zeros, ones = bits_at_idx.count(0), bits_at_idx.count(1)
                total = zeros + ones
                if (min(zeros, ones) / total) > intra_thresh: models_unstable += 1
                maj_bits.append(1 if ones > zeros else 0)
                
            if (models_unstable / len(active_models)) > model_unstable_thresh:
                volatile_bits.append(bit_idx)
            elif len(set(maj_bits)) > 1:
                accepted_bits += 1
                
        if presence_rate >= common_thresh and accepted_bits == 0:
            ies_to_drop.add(ie_name)
        else:
            byte_masks = {}
            for b_idx in volatile_bits:
                byte_idx = b_idx // 8
                bit_pos = b_idx % 8 
                if byte_idx not in byte_masks: byte_masks[byte_idx] = 0xFF 
                byte_masks[byte_idx] &= ~(1 << (7 - bit_pos))
            
            key = next((k for k, v in ie_names.items() if v == ie_name), ie_name)
            dynamic_masks[key] = byte_masks
            
    return ies_to_drop, dynamic_masks

def apply_dynamic_fingerprint(pkt_ies, ies_to_drop, dynamic_masks):
    array_v = []
    for ie_id, ie_len, ie_info in pkt_ies:
        ie_name = ie_names.get(ie_id)
        if ie_name in ies_to_drop: continue
        
        is_vendor = (ie_id == 221)
        vendor_name = ""
        if is_vendor and len(ie_info) >= 3:
            oui_hex = binascii.hexlify(ie_info[:3]).decode('utf-8').upper()
            vendor_name = f"Vendor [{oui_hex[0:2]}:{oui_hex[2:4]}:{oui_hex[4:6]}]"
            if vendor_name in ies_to_drop: continue
        
        mask_dict = dynamic_masks.get(vendor_name if is_vendor else ie_id, {})
        array_v.extend([ie_id, ie_len])
        for i, c in enumerate(ie_info):
            array_v.append(c & mask_dict[i]) if i in mask_dict else array_v.append(c)
                
    return hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper()

def evaluate_thresholds(model_packets):
    results = []
    total_combinations = len(GRID_INTRA_FLIP) * len(GRID_MAX_DEV_UNSTABLE) * len(GRID_COMMON_IE)
    
    print((f"[2] Evaluating {total_combinations} combinations (Grid Search)..."))
    
    for t_intra in GRID_INTRA_FLIP:
        for t_dev in GRID_MAX_DEV_UNSTABLE:
            for t_common in GRID_COMMON_IE:
                ies_to_drop, dynamic_masks = get_dynamic_rules(model_packets, t_intra, t_dev, t_common)
                
                chunks = {}
                
                for model, packets in model_packets.items():
                    for ts, pkt_ies in packets:
                        chunk_idx = int(ts / CHUNK_SIZE_SEC)
                        
                        if chunk_idx not in chunks:
                            chunks[chunk_idx] = {'models': set(), 'fps': set(), 'model_fps': {}, 'fp_models': {}}
                            
                        chunks[chunk_idx]['models'].add(model)
                        fp = apply_dynamic_fingerprint(pkt_ies, ies_to_drop, dynamic_masks)
                        chunks[chunk_idx]['fps'].add(fp)
                        
                        if model not in chunks[chunk_idx]['model_fps']: chunks[chunk_idx]['model_fps'][model] = set()
                        chunks[chunk_idx]['model_fps'][model].add(fp)
                        
                        if fp not in chunks[chunk_idx]['fp_models']: chunks[chunk_idx]['fp_models'][fp] = set()
                        chunks[chunk_idx]['fp_models'][fp].add(model)
                
                chunk_scores = []
                chunk_fps = []
                chunk_models = []
                chunk_m1 = []
                chunk_m2 = []
                
                for chunk_idx, data in chunks.items():
                    num_models = len(data['models'])
                    num_fps = len(data['fps'])
                    
                    if num_models > 0:
                        error_pct = abs(num_fps - num_models) / num_models
                        chunk_scores.append(error_pct)
                        
                        chunk_fps.append(num_fps)
                        chunk_models.append(num_models)
                        
                        frag = sum(len(fps) - 1 for fps in data['model_fps'].values() if len(fps) > 1)
                        coll = sum(len(models) - 1 for models in data['fp_models'].values() if len(models) > 1)
                        chunk_m1.append(frag)
                        chunk_m2.append(coll)

                avg_score = (sum(chunk_scores) / len(chunk_scores)) * 100 if chunk_scores else 0
                avg_fps = sum(chunk_fps) / len(chunk_fps) if chunk_fps else 0
                avg_models = sum(chunk_models) / len(chunk_models) if chunk_models else 0
                avg_m1 = sum(chunk_m1) / len(chunk_m1) if chunk_m1 else 0
                avg_m2 = sum(chunk_m2) / len(chunk_m2) if chunk_m2 else 0
                
                results.append({
                    'Intra': t_intra, 'DevUns': t_dev, 'Common': t_common,
                    'Avg_FPs': avg_fps, 'Avg_Models': avg_models, 
                    'Avg_M1': avg_m1, 'Avg_M2': avg_m2, 'Score_MAPE': avg_score
                })
                
    return sorted(results, key=lambda x: x['Score_MAPE'])

# --- RUN EXECUTION ---
pcap_files = glob.glob(os.path.join(PCAP_FOLDER, "*.pcap"))
if not pcap_files:
    print(("No PCAPs found!"))
    exit(1)

metadata_dict = load_metadata(META_FILE)
model_packets = load_all_packets_by_model(pcap_files, metadata_dict)
best_results = evaluate_thresholds(model_packets)

print(("\n=== RESULTS ==="))
print(f"{'IntraFlip':<10} | {'MaxMdlUnst':<10} | {'CommonIE':<10} || {'Avg FPs/5m':<12} | {'Avg Models/5m':<15} | {'Avg M1':<8} | {'Avg M2':<8} | {'ERROR SCORE':<5}")
print("-" * 110)

for res in best_results:
    print(
        f"{res['Intra']:<10} | {res['DevUns']:<10} | {res['Common']:<10} || "
        f"{res['Avg_FPs']:<12.1f} | {res['Avg_Models']:<15.1f} | {res['Avg_M1']:<8.2f} | {res['Avg_M2']:<8.2f} | {res['Score_MAPE']:.2f}%"
    )