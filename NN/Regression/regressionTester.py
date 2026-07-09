from scapy.all import PcapReader, Dot11Elt
import subprocess
import pandas as pd
import sys
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

def frame_processing(pkt):

    ie = pkt.getlayer(Dot11Elt)
    array_v = []

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

def replay_pcap_with_timing(pcap_file):
    interval_buckets = {}
    max_bucket_index = 0

    with PcapReader(pcap_file) as reader:
        for pkt in reader:
            bucket_index = int(pkt.time // 300)

            if bucket_index > max_bucket_index:
                max_bucket_index = bucket_index

            if bucket_index not in interval_buckets:
                interval_buckets[bucket_index] = []
            
            interval_buckets[bucket_index].append(pkt)

    for i in range(0, max_bucket_index + 1):
        if i not in interval_buckets:
            interval_buckets[i] = []

    max_bucket = max(interval_buckets.keys())
    if all(abs(float(pkt.time) - max_bucket * 300.0) < 0.001 for pkt in interval_buckets[max_bucket]):
        interval_buckets[max_bucket - 1].extend(interval_buckets[max_bucket])
        interval_buckets[max_bucket] = []

    n_pkts = [len(value) for _, value in sorted(interval_buckets.items())]
    print(*n_pkts)

    for _, pkt_list in sorted(interval_buckets.items()):
        rows = []

        for pkt in pkt_list:
            rows.append(frame_processing(pkt))
        
        df = pd.DataFrame(rows)

        df.to_csv("sniffedData.csv", index=False)

        subprocess.run(["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/NN/Regression/crowdingRegressor.py"])

    print("Finished replaying packets.")

replay_pcap_with_timing("/home/kali/Detection_Testing/Scenarios/300_uniform_dist_30.pcap")