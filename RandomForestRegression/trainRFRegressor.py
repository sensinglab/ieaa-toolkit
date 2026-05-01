import pandas as pd
import joblib
from sklearn.ensemble import RandomForestRegressor

INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset.csv'
# INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_dbscan.csv'
# INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_class.csv'
# INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_class_burst.csv'
MODEL_FILENAME = 'wifi_crowd_rf_regressor.pkl'

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Clusters', 'Packets_Per_Cluster']]
# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Classes', 'Packets_Per_Class']]
# X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Classes', 'Packets_Per_Class', 'Bursts_Per_Class']]
y = df['Target_Device_Count']

print("\nPlanting the Random Forest...")
rf_regressor = RandomForestRegressor(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1
)

rf_regressor.fit(X, y)
print("Training Complete!")

joblib.dump(rf_regressor, MODEL_FILENAME)
print(f"\nModel saved to {MODEL_FILENAME}")