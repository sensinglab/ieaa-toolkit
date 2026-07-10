import joblib
import pandas as pd
import numpy as np
import sys
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from tensorflow.keras.models import load_model


INPUT_CSV = '/home/kali/Detection_Testing/CNN/sniffedData.csv'
SCALER_PATH = '/home/kali/Detection_Testing/CNN/wifi_cnn_scaler.pkl'
MODEL_PATH = '/home/kali/Detection_Testing/CNN/wifi_cnn_regressor.keras'

n_devices = 0

try:
    # We must load BOTH the Scaler and the CNN Model
    scaler = joblib.load(SCALER_PATH)
    cnn_model = load_model(MODEL_PATH)
except Exception as e:
    print(f"Failed to load ML models: {e}")
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

        # 1. Create the Feature Array
        X_live = pd.DataFrame([{
            'Total_Packets': total_packets,
            'Unique_MACs': unique_macs,
            'Unique_Fingerprints': unique_fingerprints,
            'Packets_Per_Fingerprint': packets_per_fingerprint
        }])
        
        # 2. Scale the features
        X_live_scaled = scaler.transform(X_live)
        
        # 3. Reshape for the CNN (1 sample, 4 features, 1 channel)
        X_live_reshaped = X_live_scaled.reshape(1, X_live_scaled.shape[1], 1)

        # 4. Predict
        raw_prediction = cnn_model.predict(X_live_reshaped, verbose=0)[0][0]
        n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

print(n_devices)