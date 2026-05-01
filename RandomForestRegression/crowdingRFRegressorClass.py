import joblib
import pandas as pd
import numpy as np
import sqlite3
import sys
sys.path.append('/home/kali/Desktop')
from sensorFunctions import publish_mqtt_message

INPUT_CSV = '/home/kali/Detection_Testing/RandomForestRegression/sniffedData.csv'
RF_MODEL_PATH = '/home/kali/Detection_Testing/RandomForestRegression/wifi_crowd_rf_regressor.pkl'
CLASSIFIER_MODEL_PATH = '/home/kali/Detection_Testing/NN/Classification/wifi_device_classifier.pkl'

n_devices = 0 

try:
    rf_model = joblib.load(RF_MODEL_PATH)
    classifier_model = joblib.load(CLASSIFIER_MODEL_PATH)
    expected_cols = classifier_model.named_steps['preprocessor'].feature_names_in_
except Exception as e:
    print(f"Failed to load ML models: {e}")
    sys.exit(1)

try:
    df_raw = pd.read_csv(INPUT_CSV)
    
    if not df_raw.empty:
        total_packets = len(df_raw)
        unique_macs = df_raw['MAC'].nunique()
        
        #Classification
        df_clean = df_raw.drop_duplicates(subset=[c for c in df_raw.columns if c != 'MAC'])
        X_raw = df_clean.drop(columns=['MAC'], errors='ignore')
        
        unique_classes = 0
        if not X_raw.empty:
            X_aligned = X_raw.reindex(columns=expected_cols)
            
            for col in X_aligned.columns:
                X_aligned[col] = X_aligned[col].fillna('MISSING').astype(str)
                
            predictions = classifier_model.predict(X_aligned)
            unique_classes = len(set(predictions))
            
        # Regression
        if unique_classes == 0:
            packets_per_class = 0
        else:
            packets_per_class = total_packets / unique_classes

        X_live = pd.DataFrame([{
            'Total_Packets': total_packets,
            'Unique_MACs': unique_macs,
            'Unique_Classes': unique_classes,
            'Packets_Per_Class': packets_per_class
        }])
        
        raw_prediction = rf_model.predict(X_live)[0]

        n_devices = max(0, int(np.round(raw_prediction)))
        # print(f"RF Stacked Prediction: {n_devices} Devices (from {unique_classes} detected classes)")

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