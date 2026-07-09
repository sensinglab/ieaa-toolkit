import joblib
import pandas as pd
import numpy as np
import sys
from time import sleep
from sklearn.metrics import mean_squared_error

INPUT_CSV = 'regression_dataset_fing_20-20_burst_300.csv'
MODEL_PATH = 'wifi_crowd_regressor.pkl'

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Failed to load ML model: {e}")
    sys.exit(1)

try:
    print(f"Loading data from {INPUT_CSV}...\n")
    df = pd.read_csv(INPUT_CSV)
    
    if not df.empty:
        # X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
        # X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']]
        # X = df[['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'MACs_Per_Fingerprint']]
        # X = df[['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint', 'MACs_Per_Fingerprint']]
        X = df[['Total_Packets', 'Total_Bursts', 'Unique_Fingerprints']]
        y_true = df['Target_Device_Count']
        raw_predictions = model.predict(X)
        y_pred = np.maximum(0, np.round(raw_predictions)).astype(int)

        # print(f"{'Row':<5} | {'Real Devices':<15} | {'Predicted':<10} | {'Raw Output':<10} | {'Error'}")
        # print("-" * 65)
        
        # for idx in range(len(df)):
        #     real_val = y_true[idx]
        #     pred_val = y_pred[idx]
        #     raw_val = raw_predictions[idx]
        #     error = pred_val - real_val
            
        #     print(f"{idx:<5} | {real_val:<15} | {pred_val:<10} | {raw_val:<10.2f} | {error:+} devices")
            # sleep(0.05)

        # Mean Squared Error & Root Mean Squared Error
        mse = mean_squared_error(y_true, y_pred)
        rmse = np.sqrt(mse)

        # Pearson Correlation Coefficient
        if len(set(y_true)) > 1 and len(set(y_pred)) > 1:
            correlation = np.corrcoef(y_true, y_pred)[0, 1]
        else:
            correlation = 0.0

        print("\n" + "="*50)
        print("MODEL VALIDATION REPORT")
        print("="*50)
        print(f"Total Intervals Tested        : {len(df)}")
        print(f"Mean Squared Error (MSE)      : {mse:.2f}")
        print(f"Root Mean Squared Error (RMSE): {rmse:.2f} devices off on average")
        print(f"Pearson Correlation           : {correlation * 100:.2f}%")
        print("="*50 + "\n")

    else:
        print("CSV is empty. Nothing to verify.")

except FileNotFoundError:
    print(f"Error: Could not find file {INPUT_CSV}")
except Exception as e:
    print(f"Error during ML verification: {e}")