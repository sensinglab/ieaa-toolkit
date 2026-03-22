from scapy.all import PcapReader, Dot11ProbeReq, Dot11Elt
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
            rows.append(frame_processing(pkt))
        
        df = pd.DataFrame(rows)

        object_cols = df.select_dtypes(include=['object']).columns
        df[object_cols] = df[object_cols].fillna('MISSING')

        numeric_cols = df.select_dtypes(include=['number']).columns
        df[numeric_cols] = df[numeric_cols].fillna(-1)

        df.to_csv("sniffedData.csv", index=False)

        subprocess.run(["sudo", "/usr/bin/python3", "/home/kali/Detection_Testing/NN/Classification/crowdingClassifier.py"])

    print("Finished replaying packets.")

# open('/home/kali/Detection_Testing/NN/Classification/classified_dist.csv', 'w').close()
replay_pcap_with_timing("/home/kali/Detection_Testing/NN/dense_dist_30.pcap")