import joblib
import pandas as pd
import numpy as np
import sqlite3
import sys

from sklearn.cluster import DBSCAN
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer

sys.path.append('/home/kali/Desktop')
from sensorFunctions import publish_mqtt_message

INPUT_CSV = '/home/kali/Detection_Testing/RandomForestRegression/sniffedData.csv'
RF_MODEL_PATH = '/home/kali/Detection_Testing/RandomForestRegression/wifi_crowd_rf_regressor.pkl'

n_devices = 0 

try:
    rf_model = joblib.load(RF_MODEL_PATH)
except Exception as e:
    print(f"Failed to load RF model: {e}")
    sys.exit(1)

try:
    df_raw = pd.read_csv(INPUT_CSV)
    
    if not df_raw.empty:
        total_packets = len(df_raw)
        unique_macs = df_raw['MAC'].nunique()

        df_clean = df_raw.drop_duplicates(subset=[c for c in df_raw.columns if c != 'MAC'])
        X_raw = df_clean.drop(columns=['MAC'], errors='ignore')
        
        unique_clusters = 0
        if not X_raw.empty:
            if len(X_raw) == 1:
                unique_clusters = 1
            else:
                cat_cols = X_raw.select_dtypes(include=['object']).columns
                num_cols = X_raw.select_dtypes(include=['number']).columns
                
                transformers = []
                
                if len(cat_cols) > 0:
                    X_raw[cat_cols] = X_raw[cat_cols].fillna('MISSING').astype(str)
                    transformers.append(('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols))
                    
                if len(num_cols) > 0:
                    X_raw[num_cols] = X_raw[num_cols].fillna(-1)
                    transformers.append(('num', MinMaxScaler(), num_cols))

                preprocessor = ColumnTransformer(transformers)
                X_encoded = preprocessor.fit_transform(X_raw)
                
                dbscan = DBSCAN(eps=0.5, min_samples=2, metric='manhattan')
                clusters = dbscan.fit_predict(X_encoded)

                valid_clusters = len(set(clusters) - {-1})
                noise_points = list(clusters).count(-1)
                unique_clusters = valid_clusters + noise_points

        if unique_clusters == 0:
            packets_per_cluster = 0
        else:
            packets_per_cluster = total_packets / unique_clusters

        X_live = pd.DataFrame([{
            'Total_Packets': total_packets,
            'Unique_MACs': unique_macs,
            'Unique_Clusters': unique_clusters,
            'Packets_Per_Cluster': packets_per_cluster
        }])
        
        raw_prediction = rf_model.predict(X_live)[0]

        n_devices = max(0, int(np.round(raw_prediction)))
        # print(f"RF Stacked Prediction: {n_devices} Devices (from {unique_clusters} DBSCAN clusters)")

except pd.errors.EmptyDataError:
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

# Communication
try:
    connwifi = sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db', timeout=30)
    cwifi = connwifi.cursor()

    sensor_configuration = cwifi.execute("""SELECT * FROM SensorConfiguration""").fetchall()

    if len(sensor_configuration) != 0:
        sensorUUID = sensor_configuration[0][0]
        sensorName = sensor_configuration[0][1]
        influxdb_bucket = sensor_configuration[0][8]
        uploadTechnology = sensor_configuration[0][12]

        if uploadTechnology.lower() == "wifi":
            ip_address = cwifi.execute("""SELECT IP_Address FROM SensorCommunication""").fetchone()[0]
    else:
        print("Sensor is not currently configured. It is required a cloud IP address to connect to the cloud server via MQTT.\nPlease run the 'sensorConfiguration.py' script to configure the sensor.")
        sys.exit(0)

except sqlite3.Error as error:
    print("Failed to read sensor configuration from local database.")
    sys.exit(0)

# Upload via Wi-Fi
if uploadTechnology.lower() == "wifi":
    publish_mqtt_message(n_devices, f"sttoolkit/mqtt/wifi/numdetections/{influxdb_bucket}/{ip_address}/{sensorName}/{sensorUUID}")