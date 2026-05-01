import pandas as pd
import joblib
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# INPUT_DATASET = 'regression_dataset_fing3.csv'
# INPUT_DATASET = 'regression_dataset_burst.csv'
# INPUT_DATASET = 'regression_dataset_dbscan.csv'
# INPUT_DATASET = 'regression_dataset_class.csv'
# INPUT_DATASET = 'regression_dataset_class_burst.csv'
INPUT_DATASET = 'regression_dataset_ratios.csv'
MODEL_FILENAME = 'wifi_crowd_regressor.pkl'

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

# df = df[df.Interval_ID != 0]

# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
# X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']]
# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Clusters', 'Packets_Per_Cluster']]
# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Classes', 'Packets_Per_Class']]
# X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Classes', 'Packets_Per_Class', 'Bursts_Per_Class']]
X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Burst', 'Packets_Per_MAC', 'Packets_Per_Fingerprint', 'Bursts_Per_MAC', 'Bursts_Per_Fingerprint', 'MACs_Per_Fingerprint']]
y = df['Target_Device_Count']

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('regressor', MLPRegressor(
        # hidden_layer_sizes=(8,8),
        # hidden_layer_sizes=(12,12),
        # hidden_layer_sizes=(16),
        # hidden_layer_sizes=(8,8),
        # hidden_layer_sizes=(8,8),
        hidden_layer_sizes=(20),
        max_iter=10000,
        random_state=24,
        learning_rate = 'adaptive',
        early_stopping=True
    ))
])

print("\nTraining Neural Network...")
pipeline.fit(X, y)
print("Training Complete!")

joblib.dump(pipeline, MODEL_FILENAME)
print(f"\nModel saved to {MODEL_FILENAME}")