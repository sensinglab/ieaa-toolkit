import pandas as pd
import joblib

from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

INPUT_CSV = '/home/kali/Detection_Testing/NN/labeled_dataset_70_detailed.csv'
MODEL_FILENAME = 'wifi_device_classifier.pkl'

# # Columns to combine into the Target Label
LABEL_COLS = ['Device vendor', 'Device model', 'Device OS', 'Device OS version']

# Columns to DROP (Identifiers that would allow cheating)
DROP_COLS = ['Device_ID', 'MAC', 'Timestamp', 'Sequence_Number']

print(f"Loading {INPUT_CSV}...")
df = pd.read_csv(INPUT_CSV, sep=';')

# Create the target variable
# # Combine Vendor + Model + OS + Version into one string like "Apple_iPhone13_iOS_15"
df['Target_Label'] = df[LABEL_COLS].astype(str).agg('_'.join, axis=1)

# Separate features and target
X = df.drop(columns=DROP_COLS + LABEL_COLS + ['Target_Label'], errors='ignore')
y = df['Target_Label']

# Check how many classes we have
n_classes = y.nunique()
print(f"Found {n_classes} unique device classes to learn.")
print(y.value_counts().head())

# Split into Training (80%) and Testing (20%) sets
# stratify=y ensures we have a balanced mix in both sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

categorical_cols = X.select_dtypes(include=['object']).columns
numeric_cols = X.select_dtypes(include=['number']).columns

print(f"\nPreprocessing: {len(categorical_cols)} categorical columns, {len(numeric_cols)} numeric columns.")

preprocessor = ColumnTransformer(
    transformers=[
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols),
        ('num', MinMaxScaler(), numeric_cols)
    ]
)

# Define the Neural Network
# hidden_layer_sizes=(100, 50): Two layers. 
#   Layer 1 has 100 neurons (detects broad patterns).
#   Layer 2 has 50 neurons (combines patterns into specific device features).
# max_iter=500: Give it enough time to learn.
clf = MLPClassifier(
    hidden_layer_sizes=(100, 50),
    activation='relu',
    solver='adam',
    alpha=0.0001,
    batch_size='auto',
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

# print("\nEvaluating on Test Data...")
# accuracy = model_pipeline.score(X_test, y_test)
# print(f"Model Accuracy: {accuracy:.2%}")

# # Detailed Report
# y_pred = model_pipeline.predict(X_test)
# print("\nClassification Report:")
# print(classification_report(y_test, y_pred))

joblib.dump(model_pipeline, MODEL_FILENAME)
print(f"\nModel saved to {MODEL_FILENAME}")
print("You can now load this file to classify new packets.")