import joblib
import pandas as pd
import numpy as np
import sqlite3
import sys
sys.path.append('/home/kali/Desktop')
from sensorFunctions import publish_mqtt_message

INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/sniffedData.csv'

model = joblib.load('wifi_crowd_regressor.pkl')
n_devices = 0

# Regression
try:
    df_raw = pd.read_csv(INPUT_CSV)
    
    if not df_raw.empty:
        df_raw = df_raw.sort_values(by='Time')

        total_packets = len(df_raw)
        unique_macs = df_raw['MAC'].nunique()
        unique_fingerprints = df_raw['Fingerprint'].nunique()

        last_seen_macs = {}
        total_bursts = 0
        
        for _, row in df_raw.iterrows():
            mac = row['MAC']
            time_val = row['Time']
            seq = row['Seq']
            
            is_new_burst = True
            
            if mac in last_seen_macs:
                last_pkt = last_seen_macs[mac]
                time_diff = time_val - last_pkt['time']
                seq_diff = (seq - last_pkt['seq']) % 4096 
                
                if time_diff <= 3.0 and seq_diff <= 15:
                    is_new_burst = False
            
            last_seen_macs[mac] = {'time': time_val, 'seq': seq}
            if is_new_burst:
                total_bursts += 1

        if unique_fingerprints == 0:
            packets_per_fingerprint = 0
            bursts_per_fingerprint = 0
        else:
            packets_per_fingerprint = total_packets / unique_fingerprints
            bursts_per_fingerprint = total_bursts / unique_fingerprints

        X_live = pd.DataFrame([{
            'Total_Packets': total_packets,
            'Total_Bursts': total_bursts,
            'Unique_MACs': unique_macs,
            'Unique_Fingerprints': unique_fingerprints,
            'Packets_Per_Fingerprint': packets_per_fingerprint,
            'Bursts_Per_Fingerprint': bursts_per_fingerprint
        }])
        
        # Predict
        raw_prediction = model.predict(X_live)[0]
        n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

print(n_devices)