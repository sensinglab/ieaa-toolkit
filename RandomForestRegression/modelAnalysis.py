import joblib
import pandas as pd

MODEL_FILENAME = 'wifi_crowd_rf_regressor.pkl'
feature_names = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']

# Load the model
rf_regressor = joblib.load(MODEL_FILENAME)

# Retrieve feature importances
importances = rf_regressor.feature_importances_

# Pair the importances with their corresponding feature names
importance_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': importances
}).sort_values(by='Importance', ascending=False)

print("--- Feature Importances ---")
print(importance_df.to_string(index=False))