from scapy.all import *
import sqlite3
import time
import sys
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

dr_con = sqlite3.connect('/home/kali/Desktop/MemoryDB/DeviceRecords.db', timeout=30)
dr_cur = dr_con.cursor()

dr_con.execute("PRAGMA journal_mode = WAL")
dr_con.execute("PRAGMA cache_size = -64000")  # 64MB cache

def frame_processing(frame):

    ie = frame.getlayer(Dot11Elt)
    array_v = []

    while ie:
        if(ie.ID == 1):                 # Supported Rates
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 50):              # Extended Supported Rates
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 3):               # DS Parameter Set
            array_v.append(ie.ID)
            #array_v.append(ie.len)
        
        elif(ie.ID == 45):              # HT Capabilities
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 127):             # Extended Capabilities
            array_v.append(ie.ID)
            #array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i != 0):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        elif(ie.ID == 191):             # VHT Capabilities
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 70):              # RM Enabled Capabilities 
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i not in range(6)):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        elif(ie.ID == 107):             # Interworking
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 59):              # Supported Operating Classes
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 221):             # Vendor Specific
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i != 5):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        ie = ie.payload
    
    footprint_mac = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper()
    putInToProbeRequestsDB(footprint_mac)
    #print("Probe Request | Footprint: " + footprint_mac)
    return

def putInToProbeRequestsDB(id):
    res = dr_cur.execute("SELECT * FROM Probe_Requests WHERE ID='" + id + "';")
    if res.fetchone():
        dr_cur.execute("UPDATE Probe_Requests SET Last_Time_Found=current_timestamp WHERE ID='" + id + "';")
    else:
        dr_cur.execute("INSERT INTO Probe_Requests VALUES( 'Probe Request' , '" + id + "' , current_timestamp , current_timestamp , 'Unknown');")
    dr_con.commit()

def replay_pcap_with_timing(pcap_file):
    packets = rdpcap(pcap_file)
    
    if not packets:
        print("No packets found in the PCAP file.")
        return

    print(f"Loaded {len(packets)} packets from {pcap_file}")

    previous_time = 0.0
    
    for pkt in packets:
        current_time = pkt.time
        delay = float(current_time - previous_time)
        
        if delay > 0:
            time.sleep(delay)

        frame_processing(pkt)

        previous_time = current_time

    print("Finished replaying packets.")


replay_pcap_with_timing("/home/kali/Detection_Testing/left_skewed_dist_mod.pcap")