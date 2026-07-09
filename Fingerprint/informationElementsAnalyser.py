import sys
import datetime as dt
import os
import glob
import binascii
from simple_colors import *
from scapy.all import rdpcap, Dot11Elt, Dot11ProbeReq

sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

write_file = 0

if(len(sys.argv) < 2 ) :
    print("Sem os argumentos necessarios! Uso: python3 analyser.py <write/no-write>")
    exit(0)

write_to_file=str(sys.argv[1])
if(write_to_file == "write"):
    write_file = 1
elif (write_to_file == "no-write"):
    write_file = 0
else:
    print("Argumento 2 invalido! Escolher entre: 'write' ou 'no-write'.")
    exit(0)

if write_file: 
    file = open('/home/kali/Detection_Testing/Fingerprint/InformationElementsReport.txt', 'a')

dataAtual=dt.datetime.now().replace(second=0, microsecond=0)
if write_file: file.write("#################################### [" + str(dataAtual) + "] ######################################\n\n")

# ---------------------------------------------------------------------------------------
# 1. LOAD OUI DICTIONARY
# ---------------------------------------------------------------------------------------
OUI_DICT = {}
try:
    with open("/home/kali/Detection_Testing/wireshark-oui-list.txt", 'r') as f_oui:
        for line in f_oui:
            if '\t' in line:
                oui, manuf = line.split('\t', 1)
                OUI_DICT[oui.strip().upper()] = manuf.strip()
except FileNotFoundError:
    print(red("Error: wireshark-oui-list.txt not found. Vendor lookup will fail."))

# ---------------------------------------------------------------------------------------
# 2. LOAD DATA FROM PCAP FILES
# ---------------------------------------------------------------------------------------
print(cyan("\n[1] Loading PCAP files and extracting IEs..."))
pcap_files = glob.glob("/home/kali/Detection_Testing/NN/Data70/*.pcap")

# Data structure: ie_payloads[ie_name][device_id] = [list of binary strings]
ie_payloads = {}
device_count = 0

# Mapping IDs to readable names
ie_names = {
    1: "Supported Rates (1)", 50: "Extended Supported Rates (50)", 3: "DS Parameter Set (3)",
    45: "HT Capabilities (45)", 127: "Extended Capabilities (127)", 191: "VHT Capabilities (191)",
    70: "RM Enabled Capabilities (70)", 107: "Interworking (107)", 59: "Supported Operating Classes (59)"
}

# Ensure keys exist
for name in ie_names.values():
    ie_payloads[name] = {}

for pcap_path in pcap_files:
    device_id = os.path.basename(pcap_path)
    try:
        packets = rdpcap(pcap_path)
        device_count += 1
    except Exception as e:
        continue
    
    # Initialize device arrays
    for name in ie_payloads:
        ie_payloads[name][device_id] = []

    for frame in packets:
        if not frame.haslayer(Dot11ProbeReq):
            continue

        ie = frame.getlayer(Dot11Elt)
        
        # Track what we found in this packet
        found_in_pkt = {name: None for name in ie_payloads.keys()}

        while ie:
            if ie.ID in ie_names:
                name = ie_names[ie.ID]
                bin_str = bin(int(binascii.hexlify(ie.info), 16))[2:].zfill(len(ie.info) * 8) if ie.info else ""
                found_in_pkt[name] = bin_str
                
            elif ie.ID == 221 and ie.info and len(ie.info) >= 3:
                oui_hex = binascii.hexlify(ie.info[:3]).decode('utf-8').upper()
                oui_fmt = f"{oui_hex[0:2]}:{oui_hex[2:4]}:{oui_hex[4:6]}"
                
                # Added (221) to the Vendor Specific name representation
                vendor_name = f"Vendor [{oui_fmt}] (221)"
                
                if vendor_name not in ie_payloads:
                    ie_payloads[vendor_name] = {d: [] for d in [os.path.basename(p) for p in pcap_files]}
                if device_id not in ie_payloads[vendor_name]:
                    ie_payloads[vendor_name][device_id] = []
                    
                bin_str = bin(int(binascii.hexlify(ie.info), 16))[2:].zfill(len(ie.info) * 8)
                found_in_pkt[vendor_name] = bin_str
                
            ie = ie.payload
            
        # Append to device lists (Only if present in packet)
        for name, b_str in found_in_pkt.items():
            if b_str is not None:
                ie_payloads[name][device_id].append(b_str)

# ---------------------------------------------------------------------------------------
# 3. BIT-LEVEL ENTROPY & STABILITY ANALYSIS
# ---------------------------------------------------------------------------------------
print(cyan("[2] Analyzing Intra-Device Stability and Inter-Device Entropy...\n"))

# Thresholds
MAX_INTRA_DEVICE_FLIP_RATE = 0.15  # A bit flipping in >5% of packets for a single device is "unstable" for that device
MAX_DEVICES_WITH_UNSTABLE_BIT = 0.15 # If >15% of devices find this bit unstable, it is globally VOLATILE
COMMON_IE_THRESHOLD = 0.70  # If an IE is in >70% of devices, it's considered common enough to judge strictly

ie_analysis_results = {}

for ie_name, dev_dict in ie_payloads.items():
    # Filter out devices that never sent this IE
    active_devices = {d: payloads for d, payloads in dev_dict.items() if len(payloads) > 0}
    presence_rate = len(active_devices) / device_count if device_count > 0 else 0
    
    if presence_rate == 0:
        continue # Skip IEs never seen
        
    # Find max bit length for this IE to pad shorter payloads (length variation is a feature)
    max_bits = max(len(p) for payloads in active_devices.values() for p in payloads) if active_devices else 0
    
    bit_stats = [] # Will hold status of each bit index
    
    for bit_idx in range(max_bits):
        devices_finding_unstable = 0
        device_majority_bits = []
        
        for dev, payloads in active_devices.items():
            # Pad with zeros if payload is short
            bits_at_idx = [int(p[bit_idx]) if bit_idx < len(p) else 0 for p in payloads]
            
            zeros = bits_at_idx.count(0)
            ones = bits_at_idx.count(1)
            total = zeros + ones
            
            # 1. Check Intra-device Stability
            minority_rate = min(zeros, ones) / total
            if minority_rate > MAX_INTRA_DEVICE_FLIP_RATE:
                devices_finding_unstable += 1
                
            # Store majority bit to represent this device
            device_majority_bits.append(1 if ones > zeros else 0)
            
        unstable_ratio = devices_finding_unstable / len(active_devices)
        
        # Determine Bit Category
        if unstable_ratio > MAX_DEVICES_WITH_UNSTABLE_BIT:
            status = "VOLATILE"
        else:
            # 2. Check Inter-device Distinguishability
            # If every device has the same majority bit, it has 0 entropy.
            unique_vals = set(device_majority_bits)
            if len(unique_vals) > 1:
                status = "ACCEPTED" # Distinguishing
            else:
                status = "STATIC"   # Safe, but doesn't separate devices
                
        bit_stats.append({
            'idx': bit_idx,
            'status': status
        })
        
    ie_analysis_results[ie_name] = {
        'presence': presence_rate,
        'bits': bit_stats
    }

# ---------------------------------------------------------------------------------------
# 4. DECISION ENGINE & REPORT GENERATION
# ---------------------------------------------------------------------------------------

output_lines = []
output_lines.append("=====================================================================================")
output_lines.append("                    SMART FINGERPRINTING ALGORITHM CONFIGURATION                     ")
output_lines.append("=====================================================================================\n")

ies_to_drop = []
ies_to_keep = {}

for ie_name, data in sorted(ie_analysis_results.items(), key=lambda x: x[1]['presence'], reverse=True):
    presence = data['presence']
    bits = data['bits']
    
    accepted = sum(1 for b in bits if b['status'] == 'ACCEPTED')
    static = sum(1 for b in bits if b['status'] == 'STATIC')
    volatile = sum(1 for b in bits if b['status'] == 'VOLATILE')
    
    # DECISION RULE: If very common but 0 accepted bits -> DROP
    if presence >= COMMON_IE_THRESHOLD and accepted == 0:
        ies_to_drop.append((ie_name, presence, volatile))
    else:
        ies_to_keep[ie_name] = data

output_lines.append(red(">>> IEs TO COMPLETELY EXCLUDE FROM ALGORITHM <<<"))
output_lines.append("These IEs either carry no distinguishing power or are just random noise.\n")
for name, pres, vol in ies_to_drop:
    output_lines.append(f"  [X] {name} (Presence: {pres*100:.1f}%) -> {vol} Volatile bits, 0 Distinguishing bits.")

output_lines.append("\n\n" + green(">>> IEs TO INCLUDE & VOLATILE BITS TO MASK <<<"))
output_lines.append("Keep these IEs in your footprint logic. Use the indices below to append ord('0').\n")

for name, data in ies_to_keep.items():
    presence = data['presence']
    bits = data['bits']
    
    accepted = sum(1 for b in bits if b['status'] == 'ACCEPTED')
    volatile_bits = [b['idx'] for b in bits if b['status'] == 'VOLATILE']
    
    # Calculate Byte and Bit mappings for human readability, and Python Indices for the script
    python_indices_to_mask = set()
    human_readable_masks = {}
    
    for b_idx in volatile_bits:
        byte_idx = b_idx // 8
        bit_in_byte = (b_idx % 8) + 1 # 1-8 human readable
        
        python_indices_to_mask.add(byte_idx)
        
        if byte_idx not in human_readable_masks:
            human_readable_masks[byte_idx] = []
        human_readable_masks[byte_idx].append(f"{bit_in_byte}º bit")

    manuf_info = ""
    if "Vendor" in name:
        oui = name.split("[")[1].split("]")[0]
        manuf_info = f" ({OUI_DICT.get(oui, 'Unknown')})"

    output_lines.append(cyan(f"[{name}]{manuf_info} - Presence: {presence*100:.1f}% | Accepted Bits: {accepted}"))
    
    if len(python_indices_to_mask) == 0:
        output_lines.append("  -> Status: 100% Stable. Include completely. No masking required.\n")
    else:
        output_lines.append(f"  -> Python generator mask array: if i in {sorted(list(python_indices_to_mask))}: array_v.append(ord('0'))")
        output_lines.append(f"  -> Breakdown of masked bytes:")
        for byte_i, bits_list in sorted(human_readable_masks.items()):
            output_lines.append(f"       [Byte {byte_i + 1} / Python Index {byte_i}]: {', '.join(bits_list)}")
        output_lines.append("")


# Print to terminal
for line in output_lines:
    print(line)

# Write to file
if write_file:
    # Remove ANSI color codes for clean text file
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    for line in output_lines:
        file.write(ansi_escape.sub('', line) + "\n")
    file.write("#################################################################################################\n\n")
    file.close()