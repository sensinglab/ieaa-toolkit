import os
import pandas as pd
from scapy.all import rdpcap, Dot11ProbeReq, Dot11Elt

data_dir = './Data'
output_csv = 'dataset_tabular.csv'

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

rows = []
pcap_files = [f for f in os.listdir(data_dir)]

for file in pcap_files:
    device_id = file.split('-')[0]
    full_path = os.path.join(data_dir, file)
    
    try:
        packets = rdpcap(full_path)
    except Exception as e:
        print(f"Error reading {file}: {e}")
        continue

    for pkt in packets:
        if not pkt.haslayer(Dot11ProbeReq):
            continue

        row = {
            'Device_ID': device_id,
            'MAC': pkt.addr2,
            'Timestamp': float(pkt.time),
            'Sequence_Number': int(pkt.SC >> 4)
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

df = pd.DataFrame(rows)

# Fill Missing Categorical Values
object_cols = df.select_dtypes(include=['object']).columns
df[object_cols] = df[object_cols].fillna('MISSING')

# Fill missing numeric cols (excluding Timestamp/Seq) with -1 if any exist
numeric_cols = df.select_dtypes(include=['number']).columns
cols_to_fill = [c for c in numeric_cols if c not in ['Timestamp', 'Sequence_Number']]
if cols_to_fill:
    df[cols_to_fill] = df[cols_to_fill].fillna(-1)

df.to_csv(output_csv, index=False)
print(f"CSV saved to {output_csv}")