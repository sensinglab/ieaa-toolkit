import joblib
import pandas as pd
import numpy as np
import sqlite3
import sys
sys.path.append('/home/kali/Desktop')
from sensorFunctions import publish_mqtt_message

INPUT_CSV = '/home/kali/Detection_Testing/RandomForestRegression/sniffedData.csv'
MODEL_PATH = '/home/kali/Detection_Testing/RandomForestRegression/wifi_crowd_rf_regressor.pkl'

n_devices = 0 

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Failed to load RF model: {e}")
    sys.exit(1)

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
        
        raw_prediction = model.predict(X_live)[0]

        n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    # print("CSV is empty. Assuming 0 devices.")
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

# Comunication
try:
    connwifi = sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db', timeout=30)
    cwifi = connwifi.cursor()

    sensor_configuration = cwifi.execute("""SELECT * FROM SensorConfiguration""").fetchall()

    #Sensor configuration
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