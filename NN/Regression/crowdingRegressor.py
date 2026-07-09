import joblib
import pandas as pd
import numpy as np
import sys

INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/sniffedData.csv'
MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor.pkl'

n_devices = 0

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Failed to load NN model: {e}")
    sys.exit(1)

# Regression
try:
    df_raw = pd.read_csv(INPUT_CSV)
    
    if not df_raw.empty:
        total_packets = len(df_raw)
        unique_macs = df_raw['MAC'].nunique()
        unique_fingerprints = df_raw['Fingerprint'].nunique()

        if unique_fingerprints == 0:
            packets_per_fingerprint = 0
        else:
            packets_per_fingerprint = total_packets / unique_fingerprints

        X_live = pd.DataFrame([{
            'Total_Packets': total_packets,
            # 'Unique_MACs': unique_macs,
            # 'Unique_Fingerprints': unique_fingerprints,
            # 'Packets_Per_Fingerprint': packets_per_fingerprint
        }])

        raw_prediction = model.predict(X_live)[0]

        n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    # print("CSV is empty. Assuming 0 devices.")
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

print(n_devices)