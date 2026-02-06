import sys
import datetime as dt
import os
import glob
import binascii
from collections import Counter
from simple_colors import *

# Scapy imports for PCAP processing
from scapy.all import rdpcap, Dot11Elt, Dot11ProbeReq

# User-specified T1HA0 import
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

write_file = 0
show_bytes_variation = 0
show_bits_variation = 0

if(len(sys.argv) < 3 ) :
    print("Sem os argumentos necessarios!")
    exit(0)

show_bytes_bits_vari = str(sys.argv[1])

if(show_bytes_bits_vari == "show-bits-variation"):
    show_bytes_variation = 1
    show_bits_variation = 1
elif (show_bytes_bits_vari == "show-bytes-variation"):
    show_bytes_variation = 1
    show_bits_variation = 0
elif (show_bytes_bits_vari == "no-variation"):
    show_bytes_variation = 0
else:
    print("Argumento 1 invalido! Escolher entre: 'no-variation' ou 'show-bytes-variation' ou 'show-bits-variation'.")
    exit(0)

write_to_file=str(sys.argv[2])

if(write_to_file == "write"):
    write_file = 1
elif (write_to_file == "no-write"):
    write_file = 0
else:
    print("Argumento 2 invalido! Escolher entre: 'write' ou 'no-write'.")
    exit(0)


if write_file: 
    file = open('/home/kali/Detection_Testing/InformationElementsReport.txt', 'a')

# Data e hora atual 
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
# 2. LOAD DATA FROM PCAP FILES (DEVICE CENTRIC)
# ---------------------------------------------------------------------------------------
print("Loading PCAP files from ./Data/ ...")

# This list will act as our "Database"
all_probe_requests = []

pcap_files = glob.glob("./Data/*.pcap")

for pcap_path in pcap_files:
    # Identify the device by its filename
    device_id = os.path.basename(pcap_path).split('-')[0]
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(red(f"Error reading {pcap_path}: {e}"))
        continue

    for frame in packets:
        if not frame.haslayer(Dot11ProbeReq):
            continue

        mac_address = frame.addr2

        # --- FOOTPRINT GENERATION ---
        ie = frame.getlayer(Dot11Elt)
        array_v = []
        
        extracted_ies = {
            1: "", 50: "", 3: "", 45: "", 127: "", 
            191: "", 70: "", 107: "", 59: ""
        }
        
        ie_tag_list = []
        vendor_ies_content = []

        curr_ie = ie
        while curr_ie:
            ie_tag_list.append(str(curr_ie.ID))
            
            # Save raw hex content
            if curr_ie.ID in extracted_ies:
                hex_content = binascii.hexlify(curr_ie.info).decode('utf-8').upper()
                extracted_ies[curr_ie.ID] = hex_content
            
            # --- Footprint Logic Start ---
            if(curr_ie.ID == 1):                 # Supported Rates
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 50):              # Extended Supported Rates
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 3):               # DS Parameter Set
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 45):              # HT Capabilities
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 127):             # Extended Capabilities
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 191):             # VHT Capabilities
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 70):              # RM Enabled Capabilities 
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 107):             # Interworking
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 59):              # Supported Operating Classes
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
            
            elif(curr_ie.ID == 221):             # Vendor Specific
                array_v.append(curr_ie.ID)
                array_v.append(curr_ie.len)
                for c in curr_ie.info:
                    array_v.append(c)
                
                hex_content = binascii.hexlify(curr_ie.info).decode('utf-8').upper()
                vendor_ies_content.append(hex_content)
            
            curr_ie = curr_ie.payload
        
        footprint = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper()
        
        ie_array_str = " ".join(ie_tag_list)

        # Build Data Row
        row = [
            footprint, 
            ie_array_str, 
            extracted_ies[1], 
            extracted_ies[50],
            extracted_ies[3],
            extracted_ies[45],
            extracted_ies[127],
            extracted_ies[191],
            extracted_ies[70],
            extracted_ies[107],
            extracted_ies[59]
        ]
        
        for v_content in vendor_ies_content:
            row.append(v_content)

        entry = {
            'Device_ID': device_id,
            'MAC_Address': mac_address,
            'Footprint': footprint,
            'IE_array': ie_array_str,
            'data_list': row 
        }
        all_probe_requests.append(entry)

# ---------------------------------------------------------------------------------------
# 3. ANALYSIS & REPORTING
# ---------------------------------------------------------------------------------------

print("\n--------------------------------------- Informacoes Gerais --------------------------------------------")
if write_file: file.write("\n--------------------------------------- Informacoes Gerais --------------------------------------\n")

total_probe_count = len(all_probe_requests)
print("[Numero total de Probe Requests (enderecos MAC aleatorios)]: " + str(total_probe_count) + "\n")
if write_file: file.write("[Numero total de Probe Requests (enderecos MAC aleatorios)]: " + str(total_probe_count) + "\n\n")

# Devices Count (Files)
unique_devices = set(x['Device_ID'] for x in all_probe_requests)
total_devices = len(unique_devices)
print("[Numero de Devices (Ficheiros) diferentes: " +  str(total_devices) + "]")
if write_file: file.write("[Numero de Devices (Ficheiros) diferentes: " +  str(total_devices) + "]\n")

# Global MAC Count (Just for context)
unique_macs = set(x['MAC_Address'] for x in all_probe_requests)
print("[Numero de enderecos MAC diferentes (Total Global): " +  str(len(unique_macs)) + "]")
if write_file: file.write("[Numero de enderecos MAC diferentes (Total Global): " +  str(len(unique_macs)) + "]\n")

# Footprints Count
unique_footprints = set(x['Footprint'] for x in all_probe_requests)
total_footprints = len(unique_footprints)
print("[Numero de Footprints diferentes: " +  str(total_footprints) + "]")
if write_file: file.write("[Numero de Footprints diferentes: " +  str(total_footprints) + "]\n")

# Helper to group by Device and Footprint
# Structure: { Device_ID: { Footprint: Count } }
device_footprint_counts = {}
for req in all_probe_requests:
    d = req['Device_ID']
    f = req['Footprint']
    if d not in device_footprint_counts:
        device_footprint_counts[d] = Counter()
    device_footprint_counts[d][f] += 1

# Devices with only one Footprint
device_one_footprint = [d for d, f_counts in device_footprint_counts.items() if len(f_counts) == 1]
print("[Devices com apenas uma Footprint: " +  str(len(device_one_footprint)) + "]")
if write_file: file.write("[Devices com apenas uma Footprint: " +  str(len(device_one_footprint)) + "]\n")

# Devices with multiple Footprints
device_multiple_footprints = [d for d, f_counts in device_footprint_counts.items() if len(f_counts) > 1]
print("[Devices com multiplas Footprints: " +  str(len(device_multiple_footprints)) + "]")
if write_file: file.write("[Devices com multiplas Footprints: " +  str(len(device_multiple_footprints)) + "]\n")

print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")

# ---------------------------------------------------------------------------------------
# Footprint Detail Section
# ---------------------------------------------------------------------------------------

print("------------------------------------- Devices (Ficheiros) Diferentes ---------------------------------")
if write_file: file.write("---------------------------------- Devices (Ficheiros) Diferentes -------------------------------\n\n")

print("[Devices com multiplas Footprints: " + str(len(device_multiple_footprints)) + "]\n")
if write_file: file.write("[Devices com multiplas Footprints: " + str(len(device_multiple_footprints)) + "]\n\n")

for device_id in device_multiple_footprints:
    f_counts = device_footprint_counts[device_id]
    footprints = list(f_counts.keys())
    
    footprints_string = " ".join(footprints) + " "
    
    print(cyan(str(device_id)) + "| " + str(len(footprints)) + " footprints diferentes | " + str(footprints_string))
    if write_file: file.write(str(device_id) + "| " + str(len(footprints)) + " footprints diferentes | " + str(footprints_string) + "\n")

print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")

# ---------------------------------------------------------------------------------------
# Information Elements Used Section
# ---------------------------------------------------------------------------------------

print("----------------------------------- Information Elements Utilizados ----------------------------------")
if write_file: file.write("--------------------------------- Information Elements Utilizados -------------------------------\n")

for device_id in device_multiple_footprints:
    # Get all entries for this Device
    dev_entries = [x for x in all_probe_requests if x['Device_ID'] == device_id]
    
    fi_counter = Counter()
    for entry in dev_entries:
        fi_counter[(entry['Footprint'], entry['IE_array'])] += 1
    
    sorted_fi = sorted(fi_counter.items(), key=lambda item: item[1], reverse=True)

    print(cyan(str("[" + device_id + "]: ")))
    if write_file: file.write(str("[" + device_id + "]: ") + "\n")
    
    for (ftp, ie_arr), count in sorted_fi:
        print("\t" + str(ftp) + ": " + str(ie_arr) + "| Contagem: " + str(count))
        if write_file: file.write("\t" + str(ftp) + ": " + str(ie_arr) + "| Contagem: " + str(count) + "\n")

    print("")
    if write_file: file.write("\n")

print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")


# ---------------------------------------------------------------------------------------
# VARIATION ANALYSIS (DEVICE CENTRIC)
# ---------------------------------------------------------------------------------------

DEFINITELY_NUMBER_MESSAGES = 20
REASONABLE_NUMBER_MESSAGES = 10
DEFINITELY_PERCENTAGE_MIN = 25
DEFINITELY_PERCENTAGE_MAX = 50
REASONABLE_PERCENTAGE_MIN = 10
REASONABLE_PERCENTAGE_MAX = 25
GREEN_THREHSOLD = 10
YELLOW_THRESHOLD = 40
RED_THRESHOLD = 50

info_elements = ["Footprint","IE array", "Supported Rates", "Extended Supported Rates", "DS Parameter Set", "HT Capabilities", "Extended Capabilities", "VHT Capabilities", "RM Enabled Capabilities", "Interworking", "Supported Operating Classes"]

definitely_variable_bits = []
reasonable_variable_bits = []

Dict = {}

# Iterate over DEVICES with multiple footprints, not MACs
for device_id in device_multiple_footprints:
    
    # Get all packets belonging to this file/device
    dev_entries = [x for x in all_probe_requests if x['Device_ID'] == device_id]
    
    # Unique footprints within this device
    unique_footprint_map = {}
    footprint_counters = Counter()
    
    for entry in dev_entries:
        fp = entry['Footprint']
        footprint_counters[fp] += 1
        if fp not in unique_footprint_map:
            unique_footprint_map[fp] = entry['data_list']
    
    different_footprints = list(unique_footprint_map.values())
    different_footprints.sort(key=lambda x: (len(x[1]), x[1]))

    Dict[device_id] = {}

    variable_info_elements = []
    dictionary_list = []
    content_variation_elements = [[],[],[],[],[],[],[],[],[],[],[]]

    footprints_total_count = len(dev_entries)

    # Collect content variations
    for different_footprint in different_footprints:
        for a in range(2, 11):
            if a < len(different_footprint):
                if different_footprint[a] not in content_variation_elements[a] and different_footprint[a] != '' and different_footprint[a] != ' ':
                    content_variation_elements[a].append(different_footprint[a])

    # Removed the loop that pre-filled variable_info_elements to prevent desync
    # variable_info_elements will now be filled inside the analysis loops

    i = 0
    # Process Standard Elements
    for different_info_contents_list in content_variation_elements:
        
        info_element_index = content_variation_elements.index(different_info_contents_list)

        if len(different_info_contents_list) > 1:
            
            min_length = min(len(x) for x in different_info_contents_list)

            different_info_elem_content_truncated_list = []
            for content in different_info_contents_list:
                if len(content) > min_length:
                    truncated = content[:-(len(content)-min_length)]
                else:
                    truncated = content
                different_info_elem_content_truncated_list.append(truncated)
            
            # Only proceed if they are still different after truncation
            if len(set(different_info_elem_content_truncated_list)) > 1:
                
                # SYNC FIX: Add name here
                variable_info_elements.append(info_elements[info_element_index])

                # XOR Logic
                bits_number = "0" + str(int(min_length/2)*8) + "b"
                xor_list = []
                
                for x_val, y_val in zip(different_info_elem_content_truncated_list, different_info_elem_content_truncated_list[1:]):
                    convert_x = int(x_val, base=16)
                    convert_y = int(y_val, base=16)
                    xor = convert_x ^ convert_y
                    binary_xor = format(xor, bits_number)
                    xor_list.append(binary_xor)
                
                final_xor_l = list(format(0, bits_number))
                for xor_element in xor_list:
                    for xor_bit in range(len(xor_element)):
                        if str(xor_element[xor_bit]) == "1":
                            final_xor_l[xor_bit] = '1'
                final_xor = "".join(final_xor_l)

                bit_position = 1
                variable_bytes = []
                variable_bits = []
                variable_bits_count = []
                
                temp_def_var_bits = []
                temp_reas_var_bits = []

                for bit in range(len(final_xor)):
                    if(int(final_xor[bit]) == 1):
                        if( bit_position%8 != 0 ):
                            position_bit = bit_position%8
                            position_byte = bit_position//8 + 1
                        else:
                            position_bit = 8
                            position_byte = bit_position//8
                        
                        if position_byte not in variable_bytes:
                            variable_bytes.append(position_byte)
                        
                        variable_bits.append(str(position_byte) + "|" + str(position_bit))

                        zeros_counter = 0
                        ones_counter = 0

                        # Count Logic
                        for different_footprint in different_footprints:
                            fp_count = footprint_counters[different_footprint[0]]
                            val = different_footprint[i]
                            if val != '' and val != ' ':
                                if len(val) > min_length:
                                    truncated_temp = val[:-(len(val)-min_length)]
                                else:
                                    truncated_temp = val
                                
                                convert_temp = int(truncated_temp, base=16)
                                binary_temp = format(convert_temp, bits_number)

                                if binary_temp[bit_position-1] is not None:
                                    if str(binary_temp[bit_position-1]) == "0":
                                        zeros_counter += fp_count
                                    elif str(binary_temp[bit_position-1]) == "1":
                                        ones_counter += fp_count

                        bit0_calc = str(zeros_counter) + "/" + str(footprints_total_count)
                        bit0_percentage = round((zeros_counter/footprints_total_count)*100) if footprints_total_count > 0 else 0
                        bit1_calc = str(ones_counter) + "/" + str(footprints_total_count)
                        bit1_percentage = round((ones_counter/footprints_total_count)*100) if footprints_total_count > 0 else 0

                        variable_bits_count.append(str(position_byte) + "|" + str(position_bit) + "|" + str(bit0_calc) + "|" + str(bit0_percentage) + "|" + str(bit1_calc) + "|" + str(bit1_percentage))

                        b_str = str(position_byte) + "|" + str(position_bit)
                        
                        if ((bit0_percentage >= DEFINITELY_PERCENTAGE_MIN and bit0_percentage <= DEFINITELY_PERCENTAGE_MAX) or (bit1_percentage >= DEFINITELY_PERCENTAGE_MIN and bit1_percentage <= DEFINITELY_PERCENTAGE_MAX)) and (footprints_total_count > DEFINITELY_NUMBER_MESSAGES):
                            if b_str not in temp_def_var_bits:
                                temp_def_var_bits.append(b_str)
                        elif ((bit0_percentage >= REASONABLE_PERCENTAGE_MIN and bit0_percentage <= REASONABLE_PERCENTAGE_MAX) or (bit1_percentage >= REASONABLE_PERCENTAGE_MIN and bit1_percentage <= REASONABLE_PERCENTAGE_MAX)) and (footprints_total_count > REASONABLE_NUMBER_MESSAGES):
                             if b_str not in temp_reas_var_bits and b_str not in temp_def_var_bits:
                                temp_reas_var_bits.append(b_str)

                    bit_position += 1

                # Update Global Lists
                exists = 0
                for item in definitely_variable_bits:
                    if item[0] == info_elements[i]:
                        exists = 1
                        for vb in temp_def_var_bits:
                            if vb not in item[1]: item[1].append(vb)
                if exists == 0:
                    definitely_variable_bits.append([info_elements[i], temp_def_var_bits])

                exists = 0
                for item in reasonable_variable_bits:
                    if str(item[0]) == info_elements[i]:
                        exists = 1
                        for vb in temp_reas_var_bits:
                            if vb not in item[1]: item[1].append(vb)
                if exists == 0:
                    reasonable_variable_bits.append([info_elements[i], temp_reas_var_bits])

                # Build Dict
                Info_Element_Byte_Dict = {}
                for t in range(len(variable_bytes)):
                    bits_list = []
                    for b in range(len(variable_bits)):
                        byte_n = variable_bits[b].split('|')[0]
                        bit_n = variable_bits[b].split('|')[1]
                        if str(variable_bytes[t]) == str(byte_n):
                            for g in range(len(variable_bits_count)):
                                byte_n_n = variable_bits_count[g].split('|')[0]
                                bit_n_n = variable_bits_count[g].split('|')[1]
                                if (str(byte_n_n) == str(byte_n) and str(bit_n_n) == str(bit_n)):
                                    bits_list.append(variable_bits_count[g])
                    Info_Element_Byte_Dict["[" + str(variable_bytes[t]) + "º byte]"] = bits_list
                dictionary_list.append(Info_Element_Byte_Dict)
        
        i += 1

    # * * * * * * * * * * * * VENDOR SPECIFIC * * * * * * * * * * * * * #
    
    different_OUIs = []
    for different_footprint in different_footprints:
        for a in range(11, len(different_footprint)):
            val = different_footprint[a]
            if val != '' and val != ' ' and len(val) > 6:
                OUI_vend = val[0:2] + ":" + val[2:4] + ":" + val[4:6]
                if OUI_vend not in different_OUIs:
                    different_OUIs.append(OUI_vend)

    different_OUIs_content = [[] for _ in range(len(different_OUIs))]

    for different_footprint in different_footprints:
        for a in range(11, len(different_footprint)):
            val = different_footprint[a]
            if val != '' and val != ' ' and len(val) > 6:
                OUI_temp = val[0:2] + ":" + val[2:4] + ":" + val[4:6]
                if OUI_temp in different_OUIs:
                    idx = different_OUIs.index(OUI_temp)
                    if different_OUIs_content[idx].count(val) < 1:
                        different_OUIs_content[idx].append(val)

    for different_vendor_list in different_OUIs_content:
        idx = different_OUIs_content.index(different_vendor_list)
        OUI_vendor = different_OUIs[idx]

        if len(different_vendor_list) > 1:
            
            min_length = min(len(x) for x in different_vendor_list)
            
            different_vendor_content_truncated_list = []
            for content in different_vendor_list:
                if len(content) > min_length:
                    truncated = content[:-(len(content)-min_length)]
                else:
                    truncated = content
                different_vendor_content_truncated_list.append(truncated)
            
            # Only proceed if they are still different after truncation
            if len(set(different_vendor_content_truncated_list)) > 1:
                
                # SYNC FIX: Add name here
                variable_info_elements.append(OUI_vendor)

                # XOR Logic
                bits_number = "0" + str(int(min_length/2)*8) + "b"
                xor_list = []
                for x_val, y_val in zip(different_vendor_content_truncated_list, different_vendor_content_truncated_list[1:]):
                    convert_x = int(x_val, base=16)
                    convert_y = int(y_val, base=16)
                    xor = convert_x ^ convert_y
                    binary_xor = format(xor, bits_number)
                    xor_list.append(binary_xor)
                
                final_xor_l = list(format(0, bits_number))
                for xor_element in xor_list:
                    for xor_bit in range(len(xor_element)):
                        if str(xor_element[xor_bit]) == "1":
                            final_xor_l[xor_bit] = '1'
                final_xor = "".join(final_xor_l)

                bit_position = 1
                variable_bytes = []
                variable_bits = []
                variable_bits_count = []
                temp_def_var_bits_vend = []
                temp_reas_var_bits_vend = []

                for bit in range(len(final_xor)):
                    if(int(final_xor[bit]) == 1):
                        if( bit_position%8 != 0 ):
                            position_bit = bit_position%8
                            position_byte = bit_position//8 + 1
                        else:
                            position_bit = 8
                            position_byte = bit_position//8
                        
                        if position_byte not in variable_bytes:
                            variable_bytes.append(position_byte)
                        variable_bits.append(str(position_byte) + "|" + str(position_bit))

                        zeros_counter = 0
                        ones_counter = 0

                        for different_footprint in different_footprints:
                            fp_count = footprint_counters[different_footprint[0]]
                            for a in range(11, len(different_footprint)):
                                val = different_footprint[a]
                                if val != '' and val != ' ' and len(val) > 6:
                                    OUI_vend = val[0:2] + ":" + val[2:4] + ":" + val[4:6]
                                    if OUI_vend == OUI_vendor:
                                        if len(val) > min_length:
                                            truncated_temp = val[:-(len(val)-min_length)]
                                        else:
                                            truncated_temp = val
                                        
                                        convert_temp = int(truncated_temp, base=16)
                                        binary_temp = format(convert_temp, bits_number)

                                        if binary_temp[bit_position-1] is not None:
                                            if str(binary_temp[bit_position-1]) == "0":
                                                zeros_counter += fp_count
                                            elif str(binary_temp[bit_position-1]) == "1":
                                                ones_counter += fp_count
                        
                        bit0_calc = str(zeros_counter) + "/" + str(footprints_total_count)
                        bit0_percentage = round((zeros_counter/footprints_total_count)*100) if footprints_total_count else 0
                        bit1_calc = str(ones_counter) + "/" + str(footprints_total_count)
                        bit1_percentage = round((ones_counter/footprints_total_count)*100) if footprints_total_count else 0

                        variable_bits_count.append(str(position_byte) + "|" + str(position_bit) + "|" + str(bit0_calc) + "|" + str(bit0_percentage) + "|" + str(bit1_calc) + "|" + str(bit1_percentage))

                        b_str = str(position_byte) + "|" + str(position_bit)

                        if ((bit0_percentage >= DEFINITELY_PERCENTAGE_MIN and bit0_percentage <= DEFINITELY_PERCENTAGE_MAX) or (bit1_percentage >= DEFINITELY_PERCENTAGE_MIN and bit1_percentage <= DEFINITELY_PERCENTAGE_MAX)) and (footprints_total_count > DEFINITELY_NUMBER_MESSAGES):
                            if b_str not in temp_def_var_bits_vend:
                                temp_def_var_bits_vend.append(b_str)
                        elif ((bit0_percentage >= REASONABLE_PERCENTAGE_MIN and bit0_percentage <= REASONABLE_PERCENTAGE_MAX) or (bit1_percentage >= REASONABLE_PERCENTAGE_MIN and bit1_percentage <= REASONABLE_PERCENTAGE_MAX)) and (footprints_total_count > REASONABLE_NUMBER_MESSAGES):
                            if b_str not in temp_reas_var_bits_vend and b_str not in temp_def_var_bits_vend:
                                temp_reas_var_bits_vend.append(b_str)
                    
                    bit_position += 1

                exists = 0
                for item in definitely_variable_bits:
                    if str(item[0]) == str(OUI_vendor):
                        exists = 1
                        for vb in temp_def_var_bits_vend:
                            if vb not in item[1]: item[1].append(vb)
                if exists == 0:
                    definitely_variable_bits.append([OUI_vendor, temp_def_var_bits_vend])

                exists = 0
                for item in reasonable_variable_bits:
                    if str(item[0]) == str(OUI_vendor):
                        exists = 1
                        for vb in temp_reas_var_bits_vend:
                            if vb not in item[1]: item[1].append(vb)
                if exists == 0:
                    reasonable_variable_bits.append([OUI_vendor, temp_reas_var_bits_vend])
                
                Info_Element_Byte_Dict = {}
                for t in range(len(variable_bytes)):
                    bits_list = []
                    for b in range(len(variable_bits)):
                        byte_n = variable_bits[b].split('|')[0]
                        bit_n = variable_bits[b].split('|')[1]
                        if str(variable_bytes[t]) == str(byte_n):
                            for g in range(len(variable_bits_count)):
                                byte_n_n = variable_bits_count[g].split('|')[0]
                                bit_n_n = variable_bits_count[g].split('|')[1]
                                if (str(byte_n_n) == str(byte_n) and str(bit_n_n) == str(bit_n)):
                                    bits_list.append(variable_bits_count[g])
                    Info_Element_Byte_Dict["[" + str(variable_bytes[t]) + "º byte]"] = bits_list
                dictionary_list.append(Info_Element_Byte_Dict)
    
    for e in range(len(variable_info_elements)):
        Dict[device_id][variable_info_elements[e]] = dictionary_list[e]


# ---------------------------------------------------------------------------------------
# CONSTRUCT SUMMARIES (Def / Reas)
# ---------------------------------------------------------------------------------------

Definitely_InfoElem_Dict = {}
for item in definitely_variable_bits:
    elem = item[0]
    Definitely_InfoElem_Dict[elem] = {}
    def_bytes = []
    for bb in item[1]:
        byte = bb.split('|')[0]
        if byte not in def_bytes: def_bytes.append(byte)
    for b in def_bytes:
        bits = []
        for bb in item[1]:
            if bb.split('|')[0] == b: bits.append(bb.split('|')[1])
        Definitely_InfoElem_Dict[elem][b] = bits

Reasonable_InfoElem_Dict = {}
for item in reasonable_variable_bits:
    elem = item[0]
    Reasonable_InfoElem_Dict[elem] = {}
    res_bytes = []
    for bb in item[1]:
        byte = bb.split('|')[0]
        if byte not in res_bytes: res_bytes.append(byte)
    for b in res_bytes:
        bits = []
        for bb in item[1]:
            if bb.split('|')[0] == b:
                is_def = False
                if Definitely_InfoElem_Dict.get(elem) and Definitely_InfoElem_Dict[elem].get(b):
                    if bb.split('|')[1] in Definitely_InfoElem_Dict[elem][b]:
                        is_def = True
                if not is_def:
                    bits.append(bb.split('|')[1])
        if len(bits):
            Reasonable_InfoElem_Dict[elem][b] = bits


# ---------------------------------------------------------------------------------------
# PRINT REPORT
# ---------------------------------------------------------------------------------------

print("----------------------------------- Information Elements Diferentes ----------------------------------\n")
if write_file: file.write("-------------------------------- Information Elements Diferentes --------------------------------\n\n")

for device_id, info_element_dict in Dict.items():
    if isinstance(info_element_dict, str):
        pass
    else:
        print( cyan("[" + device_id + "]: ") + red(str(sorted(list(info_element_dict.keys()), reverse=True))) )
        if write_file: file.write("[" + device_id + "]: " + str(sorted(list(info_element_dict.keys()))) + "\n")
        
        for key in sorted(info_element_dict, reverse=True):
            val = info_element_dict[key]
            if isinstance(val, str):
                print("\t" + red(key + ": " + str(val)))
                if write_file: file.write("\t" + key + ": " + str(val) + "\n")
            else:
                byte_count = len(val)
                bit_count = sum(len(v) for v in val.values())
                print("\t" + red(key + ":") + magenta(" [Bytes diferentes: " + str(byte_count) + "] ") + "[Bits diferentes: " + str(bit_count) + "]")
                if write_file: file.write("\t" + key + ":" + " [Bytes diferentes: " + str(byte_count) + "] " + "[Bits diferentes: " + str(bit_count) + "]\n")

                if show_bytes_variation:
                    for byte_bit in val:
                        print("\t   " + magenta(byte_bit))
                        if write_file: file.write("\t   " + byte_bit + "\n")
                        
                        if show_bits_variation:
                            for bit_str in val[byte_bit]:
                                parts = bit_str.split('|')
                                bit_n = parts[1]
                                b0_p = int(parts[3])
                                b1_p = int(parts[5])
                                line_str = "0: " + str(b0_p) + "% (" + parts[2] + ") | 1: " + str(b1_p) + "% (" + parts[4] + ")"
                                
                                color_func = None
                                if (b0_p >= YELLOW_THRESHOLD and b0_p <= RED_THRESHOLD) or (b1_p >= YELLOW_THRESHOLD and b1_p <= RED_THRESHOLD):
                                    color_func = red
                                elif (b0_p >= GREEN_THREHSOLD and b0_p < YELLOW_THRESHOLD) or (b1_p >= GREEN_THREHSOLD and b1_p < YELLOW_THRESHOLD):
                                    color_func = yellow
                                else:
                                    color_func = lambda x: x 

                                print("\t        [" + str(bit_n) + "º bit]: " + color_func(line_str))
                                if write_file: file.write("\t        [" + str(bit_n) + "º bit]: " + line_str + "\n")
            
            print("")
            if write_file: file.write("\n")

print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")

print("----------------------------------- Definitely Variable Bytes/Bits -----------------------------------\n")
if write_file: file.write("----------------------------------- Definitely Variable Bytes/Bits ------------------------------\n\n")
# Parameters Print...
for info_element,bytes_bits in sorted(Definitely_InfoElem_Dict.items(), reverse=True):
    if len(bytes_bits):
        print(red("[" + str(info_element) + "]:"))
        if write_file: file.write("[" + str(info_element) + "]: \n")
        for byte in sorted(bytes_bits):
            print(red("  [" + str(byte) + "º byte]: "), end ="")
            if write_file: file.write("  [" + str(byte) + "º byte]: ")
            for count,bit in enumerate(sorted(bytes_bits[byte])):
                suffix = "º bit" if count == len(bytes_bits[byte]) -1 else "º bit, "
                print(str(bit) + suffix, end ="")
                if write_file: file.write(str(bit) + suffix)
            print("")
            if write_file: file.write("\n")
        print("")
        if write_file: file.write("\n")
print("")
if write_file: file.write("\n")

print("----------------------------------- Possibly Variable Bytes/Bits -------------------------------------\n")
if write_file: file.write("----------------------------------- Possibly Variable Bytes/Bits --------------------------------\n\n")
# Parameters Print...
for info_element,bytes_bits in sorted(Reasonable_InfoElem_Dict.items(), reverse=True):
    if len(bytes_bits):
        print(yellow("[" + str(info_element) + "]:"))
        if write_file: file.write("[" + str(info_element) + "]: \n")
        for byte in sorted(bytes_bits):
            print(yellow("  [" + str(byte) + "º byte]: "), end ="")
            if write_file: file.write("  [" + str(byte) + "º byte]: ")
            for count,bit in enumerate(sorted(bytes_bits[byte])):
                suffix = "º bit" if count == len(bytes_bits[byte]) -1 else "º bit, "
                print(str(bit) + suffix, end ="")
                if write_file: file.write(str(bit) + suffix)
            print("")
            if write_file: file.write("\n")
        print("")
        if write_file: file.write("\n")
print("")
if write_file: file.write("\n")

# ---------------------------------------------------------------------------------------
# Presence Rate
# ---------------------------------------------------------------------------------------

info_elements_IDs = ['1','50','3','45','127','191','70','107','59','221(1)','221(2)','221(3)','221(4)']
info_elements_presence_rate = [0]*13

print("--------------------------------- Information Elements Presence Rate ---------------------------------\n")
if write_file: file.write("--------------------------------- Information Elements Presence Rate ----------------------------\n\n")
print("[Numero total de Probe Requests (enderecos MAC aleatorios)]: " + str(total_probe_count) + "\n")

for req in all_probe_requests:
    info_IDs = req['IE_array'].split()
    for info_ID in info_IDs:
        if info_ID in info_elements_IDs:
             info_elements_presence_rate[info_elements_IDs.index(info_ID)] += 1

print("PRESENCE RATE: ")
if write_file: file.write("PRESENCE RATE: \n")
if total_probe_count != 0:
    for r in range(2, len(info_elements)):
        idx = r - 2
        if idx < len(info_elements_presence_rate):
            count = info_elements_presence_rate[idx]
            perc = round(((count/total_probe_count)*100),2)
            print("[" + str(info_elements[r]) + "]: " + str(count) + " | " + str(perc) + " %")
            if write_file: file.write("[" + str(info_elements[r]) + "]: " + str(count) + " | " + str(perc) + " %\n")

print("")
if write_file: file.write("\n")
print("------------------------------------------------------------------------------------------------------")
if write_file: file.write("-------------------------------------------------------------------------------------------------\n")

# ---------------------------------------------------------------------------------------
# Vendor Specific Analysis (DEVICE CENTRIC)
# ---------------------------------------------------------------------------------------

OUIs_count_Dict = {}
OUI_Types_count_Dict = {}

# Now checking Devices with multiple footprints, not MACs
for device_id in device_multiple_footprints:
    
    dev_entries = [x for x in all_probe_requests if x['Device_ID'] == device_id]
    
    unique_footprints_dev = set(x['Footprint'] for x in dev_entries)
    
    for ftp in unique_footprints_dev:
        ftp_count = device_footprint_counts[device_id][ftp]
        rep_row = next(x['data_list'] for x in dev_entries if x['Footprint'] == ftp)
        
        for a in range(11, len(rep_row)):
            val = rep_row[a]
            if val != '' and len(val) > 6:
                oui_fmt = val[0:2] + ":" + val[2:4] + ":" + val[4:6]
                type_hex = val[6:8]
                type_int = int(type_hex, 16)
                
                OUIs_count_Dict[oui_fmt] = OUIs_count_Dict.get(oui_fmt, 0) + ftp_count
                
                if OUI_Types_count_Dict.get(oui_fmt) is None:
                    OUI_Types_count_Dict[oui_fmt] = {}
                OUI_Types_count_Dict[oui_fmt][str(type_int)] = OUI_Types_count_Dict[oui_fmt].get(str(type_int), 0) + ftp_count

print("--------------------------------------- Vendor Specific Information ----------------------------------\n")
if write_file: file.write("--------------------------------------- Vendor Specific Information -----------------------------\n\n")
print("Vendor Specific mais comuns:\n")
if write_file: file.write("Vendor Specific mais comuns:\n\n")

if OUIs_count_Dict.items():
    for oui, oui_total_count in sorted(OUIs_count_Dict.items(), key=lambda x:x[1], reverse=True):
        
        manuf_name = OUI_DICT.get(oui.upper(), "Unknown")

        perc = round((oui_total_count/total_probe_count*100),1)
        print("[" + str(oui) + "]: Manufacturer: " + str(manuf_name) + " | Contagem: " + str(oui_total_count) + " | " + str(perc) + "%")
        if write_file: file.write("[" + str(oui) + "]: Manufacturer: " + str(manuf_name) + " | Contagem: " + str(oui_total_count) + " | " + str(perc) + "%\n")

        for oui_c, oui_type_and_count in OUI_Types_count_Dict.items():
            if oui_c == oui:
                for key in oui_type_and_count:
                    print("  [OUI Type: " + str(key) + "]: " + str(oui_type_and_count[key]))
                    if write_file: file.write("  [OUI Type: " + str(key) + "]: " + str(oui_type_and_count[key]) + "\n")
else:
    print("No Vendor Specific Information Elements captured.")
    if write_file: file.write("No Vendor Specific Information Elements captured. \n")

print("\n------------------------------------------------------------------------------------------------------\n")
if write_file: file.write("\n-------------------------------------------------------------------------------------------------\n\n")
if write_file: file.write("#################################################################################################\n\n")
if write_file: file.close()