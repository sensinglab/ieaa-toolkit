import pandas as pd
import joblib
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# INPUT_DATASET = 'regression_dataset_fing_20-20_300.csv'
INPUT_DATASET = 'regression_dataset_fing_20-20_burst_300.csv'
# INPUT_DATASET = 'regression_dataset_fing_20-20_ratios_300.csv'
# INPUT_DATASET = 'regression_dataset_fing_20-20_burst_ratios_300.csv'
MODEL_FILENAME = 'wifi_crowd_regressor.pkl'

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

df = df[df.Interval_ID != 0]
# df = df[df.Target_Device_Count <= 170]

# X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
# X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']]
# X = df[['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'MACs_Per_Fingerprint']]
# X = df[['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint', 'MACs_Per_Fingerprint']]
X = df[['Total_Packets']]
y = df['Target_Device_Count']

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('regressor', MLPRegressor(
        # hidden_layer_sizes=(6),
        hidden_layer_sizes=(12,12),
        max_iter=10000,
        random_state=24,
        learning_rate = 'adaptive',
        early_stopping=True
    ))
])

print("\nTraining Neural Network...")
pipeline.fit(X, y)
print("Training Complete!")

# 1. Extract the trained Neural Network from the pipeline
# mlp_model = pipeline.named_steps['regressor']

# # 2. Extract weights and biases
# weights = mlp_model.coefs_
# biases = mlp_model.intercepts_

# print("\n--- NEURAL NETWORK COEFFICIENTS ---")
# print(f"Total layers (including output): {mlp_model.n_layers_}")

# # Print Weights
# for i, weight_matrix in enumerate(weights):
#     print(f"\nWeights from Layer {i} to Layer {i+1}:")
#     print(f"Shape: {weight_matrix.shape}")
#     print(weight_matrix)

# # Print Biases
# for i, bias_vector in enumerate(biases):
#     print(f"\nBiases for Layer {i+1}:")
#     print(f"Shape: {bias_vector.shape}")
#     print(bias_vector)

joblib.dump(pipeline, MODEL_FILENAME)
print(f"\nModel saved to {MODEL_FILENAME}")