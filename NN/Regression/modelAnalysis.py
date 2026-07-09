import pandas as pd
import joblib
from sklearn.inspection import permutation_importance

INPUT_DATASET = 'regression_dataset_fing_20-20_300.csv'
MODEL_FILENAME = 'wifi_crowd_regressor.pkl'

# 1. Load data and model
print("Loading data and model...")
df = pd.read_csv(INPUT_DATASET)
# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
# X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']]
# X = df[['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'MACs_Per_Fingerprint']]
# X = df[['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint', 'MACs_Per_Fingerprint']]
X = df[['Total_Packets']]
y = df['Target_Device_Count']

pipeline = joblib.load(MODEL_FILENAME)

# 2. Calculate Permutation Importance
# n_repeats is the number of times to shuffle each feature to get a stable average
print("Calculating permutation importance (this may take a moment)...")
result = permutation_importance(
    pipeline, X, y, n_repeats=10, random_state=24, n_jobs=-1
)

# 3. Format and display the results
importance_df = pd.DataFrame({
    'Feature': X.columns,
    'Importance_Mean': result.importances_mean,
    'Importance_Std': result.importances_std
}).sort_values(by='Importance_Mean', ascending=False)

print("\n--- Neural Network Permutation Importance ---")
print(importance_df.to_string(index=False))