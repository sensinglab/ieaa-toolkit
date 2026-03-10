from scapy.all import PcapReader, PacketList, Dot11ProbeReq, Dot11Elt
import subprocess
import pandas as pd

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

# Mapping based on IEEE 802.11 Standard and Wireshark Dissector (packet-ieee80211.c)
# Format: (Global_Bit_Start_Index, Bit_Width): "Feature Name"
EXT_CAP_MAP = {
    # Octet 1 (Bits 0-7)
    (0, 1): 'IE_ExtCap_20_40_Coexistence',
    (1, 1): 'IE_ExtCap_General_Link',
    (2, 1): 'IE_ExtCap_Extended_Channel_Switching',
    (3, 1): 'IE_ExtCap_GLK_GCR',
    (4, 1): 'IE_ExtCap_PSMP',
    (5, 1): 'IE_ExtCap_Reserved_b5',
    (6, 1): 'IE_ExtCap_S_PSMP',
    (7, 1): 'IE_ExtCap_Event',
    # Octet 2 (Bits 8-15)
    (8, 1): 'IE_ExtCap_Diagnostics',
    (9, 1): 'IE_ExtCap_Multicast_Diagnostics',
    (10, 1): 'IE_ExtCap_Location_Tracking',
    (11, 1): 'IE_ExtCap_FMS',
    (12, 1): 'IE_ExtCap_Proxy_ARP',
    (13, 1): 'IE_ExtCap_Colocated_Interference',
    (14, 1): 'IE_ExtCap_Civic_Location',
    (15, 1): 'IE_ExtCap_Geospatial_Location',
    # Octet 3 (Bits 16-23)
    (16, 1): 'IE_ExtCap_TFS',
    (17, 1): 'IE_ExtCap_WNM_Sleep_Mode',
    (18, 1): 'IE_ExtCap_TIM_Broadcast',
    (19, 1): 'IE_ExtCap_BSS_Transition',
    (20, 1): 'IE_ExtCap_QoS_Traffic_Capability',
    (21, 1): 'IE_ExtCap_AC_Station_Count',
    (22, 1): 'IE_ExtCap_Multiple_BSSID',
    (23, 1): 'IE_ExtCap_Timing_Measurement',
    # Octet 4 (Bits 24-31)
    (24, 1): 'IE_ExtCap_Channel_Usage',
    (25, 1): 'IE_ExtCap_SSID_List',
    (26, 1): 'IE_ExtCap_DMS',
    (27, 1): 'IE_ExtCap_UTC_TSF_Offset',
    (28, 1): 'IE_ExtCap_TPU_Buffer_STA',
    (29, 1): 'IE_ExtCap_TDLS_Peer_PSM',
    (30, 1): 'IE_ExtCap_TDLS_Channel_Switching',
    (31, 1): 'IE_ExtCap_Interworking',
    # Octet 5 (Bits 32-39)
    (32, 1): 'IE_ExtCap_QoS_Map',
    (33, 1): 'IE_ExtCap_EBR',
    (34, 1): 'IE_ExtCap_SSPN_Interface',
    (35, 1): 'IE_ExtCap_Reserved_b35',
    (36, 1): 'IE_ExtCap_MSGCF_Capability',
    (37, 1): 'IE_ExtCap_TDLS_Support',
    (38, 1): 'IE_ExtCap_TDLS_Prohibited',
    (39, 1): 'IE_ExtCap_TDLS_Channel_Switching_Prohibited',
    # Octet 6 (Bits 40-47)
    (40, 1): 'IE_ExtCap_Reject_Unadmitted_Frame',
    (41, 3): 'IE_ExtCap_Service_Interval_Granularity', # Width: 3 Bits (41, 42, 43)
    (44, 1): 'IE_ExtCap_Identifier_Location',
    (45, 1): 'IE_ExtCap_U_APSD_Coexistence',
    (46, 1): 'IE_ExtCap_WNM_Notification',
    (47, 1): 'IE_ExtCap_QAB_Capability',
    # Octet 7 (Bits 48-55)
    (48, 1): 'IE_ExtCap_UTF_8_SSID',
    (49, 1): 'IE_ExtCap_QMF_Activated',
    (50, 1): 'IE_ExtCap_QMF_Reconfiguration',
    (51, 1): 'IE_ExtCap_Robust_AV_Streaming',
    (52, 1): 'IE_ExtCap_Advanced_GCR',
    (53, 1): 'IE_ExtCap_Mesh_GCR',
    (54, 1): 'IE_ExtCap_SCS',
    (55, 1): 'IE_ExtCap_QLoad_Report',
    # Octets 8 & 9 combined (Bits 56-71)
    (56, 1): 'IE_ExtCap_Alternate_EDCA',
    (57, 1): 'IE_ExtCap_Unprotected_TXOP',
    (58, 1): 'IE_ExtCap_Protected_TXOP',
    (59, 1): 'IE_ExtCap_Reserved_b59',
    (60, 1): 'IE_ExtCap_Protected_QLoad_Report',
    (61, 1): 'IE_ExtCap_TDLS_Wider_Bandwidth',
    (62, 1): 'IE_ExtCap_Operating_Mode_Notification',
    (63, 2): 'IE_ExtCap_Max_Number_Of_MSDUs', # CROSSES BOUNDARY: Bits 63 & 64
    (65, 1): 'IE_ExtCap_Channel_Schedule_Management',
    (66, 1): 'IE_ExtCap_Geodatabase_Inband',
    (67, 1): 'IE_ExtCap_Network_Channel_Control',
    (68, 1): 'IE_ExtCap_White_Space_Map',
    (69, 1): 'IE_ExtCap_Channel_Availability_Query',
    (70, 1): 'IE_ExtCap_Fine_Timing_Responder',
    (71, 1): 'IE_ExtCap_Fine_Timing_Initiator',
    # Octet 10 (Bits 72-79)
    (72, 1): 'IE_ExtCap_FILS_Capability',
    (73, 1): 'IE_ExtCap_Extended_Spectrum_Management',
    (74, 1): 'IE_ExtCap_Future_Channel_Guidance',
    (75, 2): 'IE_ExtCap_Preassociation_Discovery', # Width: 2 Bits (75, 76)
    (77, 1): 'IE_ExtCap_Reserved_b77',
    (78, 1): 'IE_ExtCap_TWT_Requester',
    (79, 1): 'IE_ExtCap_TWT_Responder',
    # Octet 11 (Bits 80-87)
    (80, 1): 'IE_ExtCap_OBSS_Narrow_Bandwidth_RU', 
    (81, 1): 'IE_ExtCap_SAE_Hash_to_Element',      
    (82, 1): 'IE_ExtCap_SAE_Password_Identifier',  
    (83, 1): 'IE_ExtCap_b83',
    (84, 1): 'IE_ExtCap_b84',
    (85, 1): 'IE_ExtCap_b85',
    (86, 1): 'IE_ExtCap_b86',
    (87, 1): 'IE_ExtCap_b87',
    # Octet 12 (Bits 88-95)
    (88, 1): 'IE_ExtCap_b88',
    (89, 1): 'IE_ExtCap_b89',
    (90, 1): 'IE_ExtCap_b90',
    (91, 1): 'IE_ExtCap_b91',
    (92, 1): 'IE_ExtCap_b92',
    (93, 1): 'IE_ExtCap_b93',
    (94, 1): 'IE_ExtCap_b94',
    (95, 1): 'IE_ExtCap_b95',
    # Octet 13 (Bits 96-103)
    (96, 1): 'IE_ExtCap_b96',
    (97, 1): 'IE_ExtCap_b97',
    (98, 1): 'IE_ExtCap_b98',
    (99, 1): 'IE_ExtCap_b99',
    (100, 1): 'IE_ExtCap_b100',
    (101, 1): 'IE_ExtCap_b101',
    (102, 1): 'IE_ExtCap_b102',
    (103, 1): 'IE_ExtCap_b103',
    # Octet 14 (Bits 104-111)
    (104, 1): 'IE_ExtCap_b104',
    (105, 1): 'IE_ExtCap_b105',
    # Bits 106+ are reserved padding at the end of the element
}

def parse_extended_caps(info_bytes):
    caps = {}
    total_bits = len(info_bytes) * 8
    
    val = int.from_bytes(info_bytes, byteorder='little')

    for (bit_start, width), name in EXT_CAP_MAP.items():
        if bit_start < total_bits:
            mask = (1 << width) - 1
            
            extracted_val = (val >> bit_start) & mask
            
            caps[name] = int(extracted_val)
        else:
            caps[name] = -1

    return caps

def frame_processing(pkt):
    if pkt.haslayer(Dot11ProbeReq):

        row = {
            'MAC': pkt.addr2
        }

        elt = pkt[Dot11ProbeReq].payload
        while isinstance(elt, Dot11Elt):
            
            # Standard IDs
            if elt.ID in allowed_ids and elt.ID not in [45, 127, 221]:
                col_name = allowed_ids[elt.ID]
                row[col_name] = elt.info.hex()
            
            # HT Capabilities (ID 45)
            elif elt.ID == 45:
                col_name = allowed_ids[elt.ID]
                for k, v in elt.fields.items():
                        if k in ['ID', 'len']:
                            continue
                        else:
                            row[f"{col_name}_{k}"] = int(v)

            # Special Parsing for Extended Capabilities (ID 127)
            elif elt.ID == 127:
                ext_features = parse_extended_caps(elt.info)
                row.update(ext_features)

            # Vendor Specific (ID 221)
            elif elt.ID == 221:
                oui_str = ':'.join(f'{b:02x}' for b in elt.oui.to_bytes(3, 'big'))
                data_hex = elt.info.hex()
                col_name = f'IE_VendorSpecific_{oui_str}'

                if col_name in row:
                    row[col_name] = row[col_name] + "+" + data_hex
                else:
                    row[col_name] = data_hex

            elt = elt.payload

        return row

def replay_pcap_with_timing(pcap_file):
    interval_buckets = {}
    max_bucket_index = 0

    with PcapReader(pcap_file) as reader:
        for pkt in reader:
            bucket_index = int(pkt.time // 300)

            if bucket_index > max_bucket_index:
                max_bucket_index = bucket_index

            if bucket_index not in interval_buckets:
                interval_buckets[bucket_index] = PacketList(name=f"Interval {bucket_index}")
            
            interval_buckets[bucket_index].append(pkt)

    for i in range(0, max_bucket_index + 1):
        if i not in interval_buckets:
            interval_buckets[i] = PacketList(name=f"Interval {i} (Empty)")

    for _, pkt_list in sorted(interval_buckets.items()):
        rows = []

        for pkt in pkt_list:
            rows.append(frame_processing(pkt))
        
        df = pd.DataFrame(rows)

        object_cols = df.select_dtypes(include=['object']).columns
        df[object_cols] = df[object_cols].fillna('MISSING')

        numeric_cols = df.select_dtypes(include=['number']).columns
        df[numeric_cols] = df[numeric_cols].fillna(-1)

        df.to_csv("sniffedData.csv", index=False)

        subprocess.run(["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/DBSCAN/crowdingClusterer.py"])

    print("Finished replaying packets.")

replay_pcap_with_timing("/home/kali/Detection_Testing/NN/normal_dist_30.pcap")