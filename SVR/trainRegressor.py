import pandas as pd
import joblib
from sklearn.svm import SVR
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_absolute_error, root_mean_squared_error

INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_fing_20-20_burst_300.csv'
MODEL_FILENAME = 'wifi_crowd_regressor.pkl'

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

X = df[['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']]
y = df['Target_Device_Count']

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('regressor', SVR(
        kernel='rbf',   # Radial Basis Function (allows curvy, non-linear trendlines)
        C=10.0,         # Regularization parameter. Higher C = tighter fit to training data.
        epsilon=0.5,    # The width of the "no-penalty tube". 0.5 means it ignores errors smaller than half a device.
        gamma='scale'   # Automatically scales the kernel based on the number of features
    ))
])

print("\nTraining Support Vector Regressor (SVR)...")
pipeline.fit(X, y)
print("Training Complete!")

# 1. Extract the trained SVR from the pipeline
svr_model = pipeline.named_steps['regressor']

print("\n--- SUPPORT VECTOR MACHINE STATS ---")
print(f"Number of Support Vectors used: {len(svr_model.support_)} out of {len(X)} training samples")

# A quick sanity check evaluation on the training data
y_pred = pipeline.predict(X)
print(f"Training MAE: {mean_absolute_error(y, y_pred):.2f} devices")
print(f"Training RMSE: {root_mean_squared_error(y, y_pred):.2f} devices")

joblib.dump(pipeline, MODEL_FILENAME)
print(f"\nModel saved to {MODEL_FILENAME}")