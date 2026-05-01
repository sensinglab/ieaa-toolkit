from scapy.all import Dot11Elt, sniff
import sqlite3
import signal
import sys
import subprocess
import pandas as pd
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

PID_FILE = "/home/kali/Desktop/sniffer.pid"

sc_con = sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db', timeout=30)
sc_cur = sc_con.cursor()

PACKET_POWER_FILTRATION = sc_cur.execute("Select Power_Filtration from SensorConfiguration;").fetchone()[0]
SLIDING_WINDOW = sc_cur.execute("""SELECT Sliding_Window FROM SensorConfiguration""").fetchone()[0]
sc_con.close()

output_csv = 'sniffedData.csv'

def frame_processing(pkt):

    ie = pkt.getlayer(Dot11Elt)
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

    fingerprint = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:]

    try:
        seq = pkt.SC >> 4
    except:
        seq = 0

    return {
        'MAC': pkt.addr2, 
        'Time': float(pkt.time), 
        'Seq': seq, 
        'Fingerprint': fingerprint
    }

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

    df.to_csv(output_csv, index=False)

    subprocess.Popen(
        ["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/NN/Classification/crowdingRegressor.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )