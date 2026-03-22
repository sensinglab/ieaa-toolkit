import pandas as pd
import joblib
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

INPUT_DATASET = 'regression_dataset.csv'
MODEL_FILENAME = 'wifi_crowd_regressor.pkl'

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
y = df['Target_Device_Count']

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('regressor', MLPRegressor(
        hidden_layer_sizes=(8,8),
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