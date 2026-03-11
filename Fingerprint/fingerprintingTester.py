from scapy.all import *
import sqlite3
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
        if(ie.ID == 1):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 50):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 3):
            array_v.append(ie.ID)
            #array_v.append(ie.len)
        
        elif(ie.ID == 45):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 127):
            array_v.append(ie.ID)
            #array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i != 0):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        elif(ie.ID == 191):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 70):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i not in range(6)):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        elif(ie.ID == 107):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 59):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for c in ie.info:
                array_v.append(c)
        
        elif(ie.ID == 221):
            array_v.append(ie.ID)
            array_v.append(ie.len)
            for i, c in enumerate(ie.info):
                if(i != 5):
                    array_v.append(c)
                else:
                    array_v.append(ord('0'))
        
        ie = ie.payload
    
    footprint_mac = hex(lib.t1ha0(bytes(array_v), len(array_v), 3))[2:].upper()
    return footprint_mac

# def replay_pcap_with_timing(pcap_file):
#     packets = rdpcap(pcap_file)
    
#     if not packets:
#         print("No packets found in the PCAP file.")
#         return

#     print(f"Loaded {len(packets)} packets from {pcap_file}")

#     previous_time = 0.0
    
#     for pkt in packets:
#         current_time = pkt.time
#         delay = float(current_time - previous_time)
        
#         if delay > 0:
#             time.sleep(delay)

#         frame_processing(pkt)

#         previous_time = current_time

#     print("Finished replaying packets.")

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
        fingerprints = []

        for pkt in pkt_list:
            fingerprints.append(frame_processing(pkt))

        print(len(set(fingerprints)))

    print("Finished replaying packets.")


replay_pcap_with_timing("/home/kali/Detection_Testing/NN/normal_dist_30.pcap")