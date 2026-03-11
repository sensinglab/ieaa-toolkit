import joblib
import pandas as pd
import numpy as np
import sqlite3
import sys
sys.path.append('/home/kali/Desktop')
from sensorFunctions import publish_mqtt_message

INPUT_CSV = '/home/kali/Detection_Testing/NN/Classification/sniffedData.csv'
CLASSIFIED_CSV = '/home/kali/Detection_Testing/NN/Classification/classified_dist.csv'

model = joblib.load('wifi_device_classifier.pkl')
n_devices = 0
prediction = np.array([])

# Prediction
try:
    df = pd.read_csv(INPUT_CSV)

    if not df.empty:
        df_clean = df.drop_duplicates(keep='first').copy()

        drop_for_ml = ['MAC']
        X_raw = df_clean.drop(columns=drop_for_ml, errors='ignore')

        expected_cols = model.named_steps['preprocessor'].feature_names_in_
        X_raw = X_raw.reindex(columns=expected_cols)

        numeric_cols = ["IE_HTCapabilities_", "IE_ExtCap_"]
        for col in X_raw.columns:
            is_numeric = any(pattern in col for pattern in numeric_cols)

            if is_numeric:
                X_raw[col] = X_raw[col].fillna(-1)
            else:
                X_raw[col] = X_raw[col].fillna('MISSING')
                X_raw[col] = X_raw[col].astype(str)

        prediction = model.predict(X_raw)
        n_devices = len(set(prediction))
    else:
        n_devices = 0
        prediction = np.array([])

except pd.errors.EmptyDataError:
    n_devices = 0
    prediction = np.array([])

# Testing
# try:
#     df_class = pd.read_csv(CLASSIFIED_CSV, sep=';')
# except pd.errors.EmptyDataError:
#     df_class = pd.DataFrame()

# new_len = len(np.unique(prediction.flatten()))
# current_len = len(df_class)
# max_len = max(current_len, new_len)

# if new_len > current_len:
#     rows_to_add = new_len - current_len
#     top_pad = pd.DataFrame(np.nan, index=range(rows_to_add), columns=df_class.columns, dtype='object')
#     df_class = pd.concat([top_pad, df_class], axis=0)
#     df_class = df_class.reset_index(drop=True)

# new_series = pd.Series(np.nan, name=str(df_class.shape[1]*5 + 5), index=range(max_len), dtype='object')
# if new_len > 0:
#     new_series.iloc[-new_len:] = np.unique(prediction.flatten())

# df_class = pd.concat([df_class, new_series], axis=1)

# df_class.to_csv(CLASSIFIED_CSV, index=False, sep=';')

# Comunication
try:
    connwifi= sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db' , timeout=30)
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
        exit(0)

except sqlite3.Error as error:
    print("Failed to read sensor configuration from local database.")
    exit(0)

# Upload via Wi-Fi
if uploadTechnology.lower() == "wifi":
    publish_mqtt_message(n_devices, f"sttoolkit/mqtt/wifi/numdetections/{influxdb_bucket}/{ip_address}/{sensorName}/{sensorUUID}")