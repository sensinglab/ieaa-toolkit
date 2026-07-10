import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_absolute_error, mean_squared_error
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Flatten, Dense, Dropout

INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_fing_20-20_300.csv'
SCALER_FILENAME = 'wifi_cnn_scaler.pkl'
MODEL_FILENAME = 'wifi_cnn_regressor.keras'

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

X = df[['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']]
y = df['Target_Device_Count']

# Scale Data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Reshape Data for CNN
# A 1D CNN expects a 3D input: (Number of Samples, Number of Features, Channels)
# We have 4 features, treated as 1 channel.
X_reshaped = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

print("\nBuilding Convolutional Neural Network (CNN)...")
model = Sequential([
    # Convolutional Layer: Looks for patterns across the 4 features
    Conv1D(filters=16, kernel_size=2, activation='relu', input_shape=(X_reshaped.shape[1], 1)),
    
    # Flatten: Turns the 3D CNN output back into a flat 1D array
    Flatten(),
    
    # Dense Layers: Standard Neural Network layers to process the patterns
    Dense(32, activation='relu'),
    Dropout(0.2), # Dropout randomly turns off 20% of neurons to prevent overfitting
    Dense(16, activation='relu'),
    
    # Output Layer: 1 neuron for the final predicted crowd size
    Dense(1, activation='linear')
])

model.compile(optimizer='adam', loss='mse', metrics=['mae'])

# Train the model
print("Training Model...")
history = model.fit(
    X_reshaped, y,
    epochs=100,
    batch_size=32,
    validation_split=0.2,
    verbose=1
)

print("\nTraining Complete!")

# Save Scaler and Model
joblib.dump(scaler, SCALER_FILENAME)
model.save(MODEL_FILENAME)
print(f"\nSaved scaler to {SCALER_FILENAME}")
print(f"Saved model to {MODEL_FILENAME}")