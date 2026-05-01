import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
import sqlite3
import sys
sys.path.append('/home/kali/Desktop')
from sensorFunctions import publish_mqtt_message

input_csv = '/home/kali/Detection_Testing/DBSCAN/sniffedData.csv'

try:
    df = pd.read_csv(input_csv)

    df_clean = df.drop_duplicates(keep='first').copy()

    drop_for_ml = ['MAC']
    X_raw = df_clean.drop(columns=drop_for_ml, errors='ignore')

    categorical_cols = X_raw.select_dtypes(include=['object']).columns
    numeric_cols = X_raw.select_dtypes(include=['number']).columns

    # Define the transformers
    # Categorical -> OneHot (Becomes 0s and 1s)
    # Numeric -> MinMaxScaler (Scales -1, 0, 5, etc. to roughly 0.0 to 1.0)
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols),
            ('num', MinMaxScaler(), numeric_cols) 
        ]
    )

    X_encoded = preprocessor.fit_transform(X_raw)

    dbscan = DBSCAN(eps=2.1, min_samples=2, metric='manhattan')

    clusters = dbscan.fit_predict(X_encoded)

    valid_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
    noise_points = list(clusters).count(-1)
    n_clusters = valid_clusters + noise_points
except pd.errors.EmptyDataError:
    n_clusters = 0

try:
    connwifi= sqlite3.connect('/home/kali/Desktop/DB/SensorConfiguration.db' , timeout=30)
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
        exit(0)

except sqlite3.Error as error:
    print("Failed to read sensor configuration from local database.")
    exit(0)

# Upload via Wi-Fi
if uploadTechnology.lower() == "wifi":
    publish_mqtt_message(n_clusters, f"sttoolkit/mqtt/wifi/numdetections/{influxdb_bucket}/{ip_address}/{sensorName}/{sensorUUID}")