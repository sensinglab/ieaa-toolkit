from scapy.all import Dot11ProbeReq, Dot11Elt, sniff
import sqlite3
import signal
import sys
import subprocess
import pandas as pd

PID_FILE = "/home/kali/Desktop/sniffer.pid"

sc_con = sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db', timeout=30)
sc_cur = sc_con.cursor()

PACKET_POWER_FILTRATION = sc_cur.execute("Select Power_Filtration from SensorConfiguration;").fetchone()[0]
SLIDING_WINDOW = sc_cur.execute("""SELECT Sliding_Window FROM SensorConfiguration""").fetchone()[0]
sc_con.close()

output_csv = 'sniffedData.csv'

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

EXT_CAP_MAP = {
    # Octet 1
    (0, 0, 1): 'IE_ExtCap_20_40_Coexistence',
    (0, 1, 1): 'IE_ExtCap_General_Link',
    (0, 2, 1): 'IE_ExtCap_Extended_Channel_Switching',
    (0, 3, 1): 'IE_ExtCap_GLK_GCR',
    (0, 4, 1): 'IE_ExtCap_PSMP',
    (0, 5, 1): 'IE_ExtCap_Reserved_Oct1_5',
    (0, 6, 1): 'IE_ExtCap_S_PSMP',
    (0, 7, 1): 'IE_ExtCap_Event',
    # Octet 2
    (1, 0, 1): 'IE_ExtCap_Diagnostics',
    (1, 1, 1): 'IE_ExtCap_Multicast_Diagnostics',
    (1, 2, 1): 'IE_ExtCap_Location_Tracking',
    (1, 3, 1): 'IE_ExtCap_FMS',
    (1, 4, 1): 'IE_ExtCap_Proxy_ARP',
    (1, 5, 1): 'IE_ExtCap_Colocated_Interference',
    (1, 6, 1): 'IE_ExtCap_Civic_Location',
    (1, 7, 1): 'IE_ExtCap_Geospatial_Location',
    # Octet 3
    (2, 0, 1): 'IE_ExtCap_TFS',
    (2, 1, 1): 'IE_ExtCap_WNM_Sleep_Mode',
    (2, 2, 1): 'IE_ExtCap_TIM_Broadcast',
    (2, 3, 1): 'IE_ExtCap_BSS_Transition',
    (2, 4, 1): 'IE_ExtCap_QoS_Traffic_Capability',
    (2, 5, 1): 'IE_ExtCap_AC_Station_Count',
    (2, 6, 1): 'IE_ExtCap_Multiple_BSSID',
    (2, 7, 1): 'IE_ExtCap_Timing_Measurement',
    # Octet 4
    (3, 0, 1): 'IE_ExtCap_Channel_Usage',
    (3, 1, 1): 'IE_ExtCap_SSID_List',
    (3, 2, 1): 'IE_ExtCap_DMS',
    (3, 3, 1): 'IE_ExtCap_UTC_TSF_Offset',
    (3, 4, 1): 'IE_ExtCap_TPU_Buffer_STA',
    (3, 5, 1): 'IE_ExtCap_TDLS_Peer_PSM',
    (3, 6, 1): 'IE_ExtCap_TDLS_Channel_Switching',
    (3, 7, 1): 'IE_ExtCap_Interworking',
    # Octet 5
    (4, 0, 1): 'IE_ExtCap_QoS_Map',
    (4, 1, 1): 'IE_ExtCap_EBR',
    (4, 2, 1): 'IE_ExtCap_SSPN_Interface',
    (4, 3, 1): 'IE_ExtCap_Reserved_Oct5_3',
    (4, 4, 1): 'IE_ExtCap_MSGCF_Capability',
    (4, 5, 1): 'IE_ExtCap_TDLS_Support',
    (4, 6, 1): 'IE_ExtCap_TDLS_Prohibited',
    (4, 7, 1): 'IE_ExtCap_TDLS_Channel_Switching_Prohibited',
    # Octet 6
    (5, 0, 1): 'IE_ExtCap_Reject_Unadmitted_Frame',
    (5, 1, 3): 'IE_ExtCap_Service_Interval_Granularity',
    (5, 4, 1): 'IE_ExtCap_Identifier_Location',
    (5, 5, 1): 'IE_ExtCap_U_APSD_Coexistence',
    (5, 6, 1): 'IE_ExtCap_WNM_Notification',
    (5, 7, 1): 'IE_ExtCap_QAB_Capability',
    # Octet 7
    (6, 0, 1): 'IE_ExtCap_UTF_8_SSID',
    (6, 1, 1): 'IE_ExtCap_QMF_Activated',
    (6, 2, 1): 'IE_ExtCap_QMF_Reconfiguration',
    (6, 3, 1): 'IE_ExtCap_Robust_AV_Streaming',
    (6, 4, 1): 'IE_ExtCap_Advanced_GCR',
    (6, 5, 1): 'IE_ExtCap_Mesh_GCR',
    (6, 6, 1): 'IE_ExtCap_SCS',
    (6, 7, 1): 'IE_ExtCap_QLoad_Report',
    # Octet 8
    (7, 0, 1): 'IE_ExtCap_Alternate_EDCA',
    (7, 1, 1): 'IE_ExtCap_Unprotected_TXOP',
    (7, 2, 1): 'IE_ExtCap_Protected_TXOP',
    (7, 3, 1): 'IE_ExtCap_Reserved_Oct8_3',
    (7, 4, 1): 'IE_ExtCap_Protected_QLoad_Report',
    (7, 5, 1): 'IE_ExtCap_TDLS_Wider_Bandwidth',
    (7, 6, 1): 'IE_ExtCap_Operating_Mode_Notification',
    (7, 7, 2): 'IE_ExtCap_Max_Number_Of_MSDUs',
    # Octet 9
    (8, 1, 1): 'IE_ExtCap_Channel_Schedule_Management',
    (8, 2, 1): 'IE_ExtCap_Geodatabase_Inband',
    (8, 3, 1): 'IE_ExtCap_Network_Channel_Control',
    (8, 4, 1): 'IE_ExtCap_White_Space_Map',
    (8, 5, 1): 'IE_ExtCap_Channel_Availability_Query',
    (8, 6, 1): 'IE_ExtCap_Fine_Timing_Responder',
    (8, 7, 1): 'IE_ExtCap_Fine_Timing_Initiator',
    # Octet 10
    (9, 0, 1): 'IE_ExtCap_FILS_Capability',
    (9, 1, 1): 'IE_ExtCap_Extended_Spectrum_Management',
    (9, 2, 1): 'IE_ExtCap_Future_Channel_Guidance',
    (9, 3, 2): 'IE_ExtCap_Preassociation_Discovery',
    (9, 5, 1): 'IE_ExtCap_Reserved_Oct10_5',
    (9, 6, 1): 'IE_ExtCap_TWT_Requester',
    (9, 7, 1): 'IE_ExtCap_TWT_Responder'
}

def parse_extended_caps(info_bytes):
    caps = {}
    bytes_list = list(info_bytes)
    
    for (byte_idx, bit_idx, width), name in EXT_CAP_MAP.items():
        
        if byte_idx < len(bytes_list):
            
            # Logic to extract multiple bits (integer) or single bit (0/1)
            # Create a mask of 'width' 1s (e.g., width 2 -> binary 11 -> decimal 3)
            mask = (1 << width) - 1
            
            # Shift right by the bit offset, then AND with mask
            val = (bytes_list[byte_idx] >> bit_idx) & mask
            
            caps[name] = int(val)
        else:
            # If the field is missing (packet too short), assume -1
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

        rows.append(row)

def signal_term_handler(signal, pkt):
    open(PID_FILE, "w").close()
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_term_handler)

filter_str = "(wlan type mgt subtype probe-req)"

if PACKET_POWER_FILTRATION != 0:
    filter_str += f" && radio [22] > {256 + PACKET_POWER_FILTRATION}"

while(True):
    rows = []

    sniff(
        count=0,
        timeout=SLIDING_WINDOW*60,
        filter=filter_str,
        prn=frame_processing,
        iface="wlan1",
        store=0,
        monitor=True)
    
    df = pd.DataFrame(rows)

    object_cols = df.select_dtypes(include=['object']).columns
    df[object_cols] = df[object_cols].fillna('MISSING')

    numeric_cols = df.select_dtypes(include=['number']).columns
    df[numeric_cols] = df[numeric_cols].fillna(-1)

    df.to_csv(output_csv, index=False)

    subprocess.Popen(
        ["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/DBSCAN/crowdingClassifier.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )