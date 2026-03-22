from scapy.all import PcapReader, PacketList, Dot11Elt
import subprocess
import pandas as pd
import sys
sys.path.append('/home/kali/Desktop')
from t1ha0 import ffi, lib

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

    return {'MAC': pkt.addr2, 'Fingerprint': fingerprint}

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

replay_pcap_with_timing("/home/kali/Detection_Testing/NN/normal_dist_30.pcap")