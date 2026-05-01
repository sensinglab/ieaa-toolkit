from scapy.all import PcapReader, Dot11Elt
import subprocess
import pandas as pd
import sys
sys.path.append('/home/kali/Desktop')

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

def parse_packet_to_dict(pkt):
    row = {'MAC': pkt.addr2}
    ie = pkt.getlayer(Dot11Elt)
    
    while ie:
        if ie.ID in [1, 3, 45, 50, 59, 70, 107, 191]:
            col_name = allowed_ids[ie.ID]
            row[col_name] = ie.info.hex()
        elif ie.ID == 221:
            if len(ie.info) >= 3:
                oui = ie.info[:3].hex()
                col_name = f'IE_Vendor_{oui}'
                row[col_name] = row.get(col_name, "") + ie.info[3:].hex()
        ie = ie.payload
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
                interval_buckets[bucket_index] = []
            
            interval_buckets[bucket_index].append(pkt)

    for i in range(0, max_bucket_index + 1):
        if i not in interval_buckets:
            interval_buckets[i] = []

    max_bucket = max(interval_buckets.keys())
    if all(abs(float(pkt.time) - max_bucket * 300.0) < 0.001 for pkt in interval_buckets[max_bucket]):
        interval_buckets[max_bucket - 1].extend(interval_buckets[max_bucket])
        interval_buckets[max_bucket] = []

    for _, pkt_list in sorted(interval_buckets.items()):
        rows = []

        for pkt in pkt_list:
            rows.append(parse_packet_to_dict(pkt))
        
        df = pd.DataFrame(rows)
        df.to_csv("sniffedData.csv", index=False)

        subprocess.run(["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/NN/Regression/crowdingRegressorDBSCAN.py"])

    print("Finished replaying packets.")

replay_pcap_with_timing("/home/kali/Detection_Testing/Scenarios/uniform_dist_30.pcap")