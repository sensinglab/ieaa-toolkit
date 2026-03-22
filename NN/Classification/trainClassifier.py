import pandas as pd
import joblib
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

INPUT_CSV = 'labeled_dataset_70.csv'
MODEL_FILENAME = 'wifi_device_classifier.pkl'

LABEL_COLS = ['Device vendor', 'Device model', 'Device OS', 'Device OS version']

# Columns to DROP
DROP_COLS = ['Device_ID', 'MAC', 'Timestamp', 'Sequence_Number']

print(f"Loading {INPUT_CSV}...")
df = pd.read_csv(INPUT_CSV, sep=';')

# Create the target variable like "Apple_iPhone13_iOS_15"
df['Target_Label'] = df[LABEL_COLS].astype(str).agg('_'.join, axis=1)

# Separate features and target
X = df.drop(columns=DROP_COLS + LABEL_COLS + ['Target_Label'], errors='ignore')
y = df['Target_Label']

# Check how many classes we have
n_classes = y.nunique()
print(f"Found {n_classes} unique device classes to learn.")
print(y.value_counts().head())

categorical_cols = X.select_dtypes(include=['object']).columns
numeric_cols = X.select_dtypes(include=['number']).columns

print(f"\nPreprocessing: {len(categorical_cols)} categorical columns, {len(numeric_cols)} numeric columns.")

preprocessor = ColumnTransformer(
    transformers=[
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols),
        ('num', MinMaxScaler(), numeric_cols)
    ]
)

clf = MLPClassifier(
    hidden_layer_sizes=(100, 50),
    learning_rate='adaptive',
    max_iter=500,
    random_state=42,
    verbose=True  # Prints progress
)

model_pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', clf)
])

print("\nStarting Training (this may take a while)...")
model_pipeline.fit(X, y)
print("Training Complete.")

joblib.dump(model_pipeline, MODEL_FILENAME)
print(f"\nModel saved to {MODEL_FILENAME}")