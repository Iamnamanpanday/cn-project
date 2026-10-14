
# Program to implement K-Means Clustering
# Dataset: Breast Cancer Wisconsin (Diagnostic)

import matplotlib.pyplot as plt

from sklearn.datasets import load_breast_cancer
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score

# Step 1: Load dataset
data = load_breast_cancer()
X = data.data

print("Dataset loaded successfully!")
print("Dataset shape:", X.shape)
print("Number of features:", X.shape[1])

# Step 2: Standardize the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Step 3: Apply K-Means clustering
kmeans = KMeans(
    n_clusters=2,
    random_state=42,
    n_init=10
)

clusters = kmeans.fit_predict(X_scaled)

print("\nK-Means clustering completed!")
print("Number of clusters:", kmeans.n_clusters)

# Step 4: Display cluster counts
for cluster in range(2):
    count = (clusters == cluster).sum()
    print(f"Cluster {cluster}: {count} samples")

# Step 5: Evaluate clustering using silhouette score
score = silhouette_score(X_scaled, clusters)
print("\nSilhouette Score: {:.4f}".format(score))

# Step 6: Reduce features to 2 dimensions for visualization
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

# Step 7: Plot clusters
plt.figure(figsize=(8, 6))

plt.scatter(
    X_pca[:, 0],
    X_pca[:, 1],
    c=clusters,
    cmap="viridis",
    s=40
)

plt.xlabel("Principal Component 1")
plt.ylabel("Principal Component 2")
plt.title("K-Means Clustering (K=2)")
plt.colorbar(label="Cluster")
plt.tight_layout()
plt.show()

# Step 8: Display cluster centers
centers_pca = pca.transform(kmeans.cluster_centers_)

plt.figure(figsize=(8, 6))
plt.scatter(
    X_pca[:, 0],
    X_pca[:, 1],
    c=clusters,
    cmap="viridis",
    s=40
)

plt.scatter(
    centers_pca[:, 0],
    centers_pca[:, 1],
    marker="X",
    s=200,
    c="red",
    label="Cluster Centers"
)

plt.xlabel("Principal Component 1")
plt.ylabel("Principal Component 2")
plt.title("K-Means Clusters and Centers")
plt.legend()
plt.tight_layout()
plt.show()
