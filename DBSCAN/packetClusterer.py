import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.metrics import silhouette_score

# LOAD DATA
input_csv = '/home/kali/Detection_Testing/DBSCAN/dataset_tabular.csv' # 'dataset_tabular.csv' or 'dataset_tabular_detailed.csv'
print(f"Loading data from {input_csv}...")
df = pd.read_csv(input_csv)

n_unique_devices = df['Device_ID'].nunique()
print(f"Ground Truth: There are {n_unique_devices} unique Device_IDs in the dataset.")

print(f"Original shape: {df.shape}")

# DEDUPLICATION
cols_to_ignore_for_dedup = ['Timestamp', 'Sequence_Number', 'IE_DSSSParameterSet']
subset_cols = [c for c in df.columns if c not in cols_to_ignore_for_dedup]
df_clean = df.drop_duplicates(subset=subset_cols, keep='first').copy()

# SEPARATE IDENTIFIERS
identifiers = df_clean[['Device_ID', 'MAC']].reset_index(drop=True)
drop_for_ml = ['Device_ID', 'MAC', 'Timestamp', 'Sequence_Number', 'IE_DSSSParameterSet']
X_raw = df_clean.drop(columns=drop_for_ml, errors='ignore')

# PREPROCESSING PIPELINE
categorical_cols = X_raw.select_dtypes(include=['object']).columns
numeric_cols = X_raw.select_dtypes(include=['number']).columns

print(f"Categorical columns: {len(categorical_cols)}")
print(f"Numeric columns: {len(numeric_cols)}")

# Define the transformers
# Categorical -> OneHot (Becomes 0s and 1s)
# Numeric -> MinMaxScaler (Scales -1, 0, 5, etc. to roughly 0.0 to 1.0)
preprocessor = ColumnTransformer(
    transformers=[
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols),
        ('num', MinMaxScaler(), numeric_cols) 
    ]
)

X_encoded = preprocessor.fit_transform(X_raw)

print(f"Shape of data passed to DBSCAN: {X_encoded.shape}")

# DBSCAN CLUSTERING
dbscan = DBSCAN(eps=1.1, min_samples=1, metric='manhattan')

clusters = dbscan.fit_predict(X_encoded)

# RESULTS ANALYSIS
# Add the Cluster ID back to our identifiers to see who is who
results = identifiers.copy()
results['Cluster_ID'] = clusters

n_clusters_ = len(set(clusters)) - (1 if -1 in clusters else 0)
n_noise_ = list(clusters).count(-1)

print("\n" + "="*30)
print("CLUSTERING RESULTS")
print("="*30)
print(f"Estimated number of clusters: {n_clusters_}")
print(f"Estimated number of noise points: {n_noise_}")

if n_clusters_ > 0:
    print(f"Silhouette Coefficient: {silhouette_score(X_encoded, clusters):.3f}")

print("\nSample of Clusters found:")
# Group by Cluster ID and list the unique Device_IDs found in that cluster
cluster_summary = results.groupby('Cluster_ID')['Device_ID'].unique()
print(cluster_summary.head(20)) # Print first 20 clusters

# Save results
results.to_csv('clustering_results.csv', index=False)
print("\nDetailed results saved to 'clustering_results.csv'")