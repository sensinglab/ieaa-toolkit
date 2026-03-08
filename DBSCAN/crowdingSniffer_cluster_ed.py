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
    # 3: 'IE_DSSSParameterSet',
    45: 'IE_HTCapabilities',
    50: 'IE_ExtendedSupportedRates',
    59: 'IE_SupportedOperatingClasses',
    70: 'IE_RMEnabledCapabilities',
    107: 'IE_Interworking',
    127: 'IE_ExtendedCapabilities',
    191: 'IE_VHTCapabilities',
    221: 'IE_VendorSpecific'
}

def frame_processing(pkt):
    if pkt.haslayer(Dot11ProbeReq):

        row = {
            'MAC': pkt.addr2
        }

        elt = pkt[Dot11ProbeReq].payload
        while isinstance(elt, Dot11Elt):
            
            # Handle Standard Allowed IDs
            if elt.ID in allowed_ids and elt.ID != 221:
                col_name = allowed_ids[elt.ID]
                # Unified Format: Hex string of the payload
                row[col_name] = elt.info.hex()

            # Handle Vendor Specific (ID 221)
            elif elt.ID == 221:
                if len(elt.info) >= 3:
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

    # Fill Missing Categorical Values
    object_cols = df.select_dtypes(include=['object']).columns
    df[object_cols] = df[object_cols].fillna('MISSING')

    # Fill missing numeric cols (excluding Timestamp/Seq) with -1 if any exist
    numeric_cols = df.select_dtypes(include=['number']).columns
    df[numeric_cols] = df[numeric_cols].fillna(-1)

    df.to_csv(output_csv, index=False)

    subprocess.Popen(
        ["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/DBSCAN/crowdingClusterer.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )