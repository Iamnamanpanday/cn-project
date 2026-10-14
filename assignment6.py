# Program to implement K-Nearest Neighbors (KNN)
# Dataset: Breast Cancer Wisconsin (Diagnostic)

import matplotlib.pyplot as plt

from sklearn.datasets import load_breast_cancer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

# Step 1: Load the dataset
data = load_breast_cancer()
X = data.data
y = data.target

print("Dataset loaded successfully!")
print("Dataset shape:", X.shape)
print("Number of features:", X.shape[1])
print("Classes:", data.target_names)

# Step 2: Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# Step 3: Standardize the features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Step 4: Create and train the KNN classifier
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X_train, y_train)

# Step 5: Make predictions
y_pred = knn_model.predict(X_test)

# Step 6: Evaluate the model
accuracy = accuracy_score(y_test, y_pred) * 100

print("\n--- KNN RESULTS ---")
print("Accuracy: {:.2f}%".format(accuracy))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Step 7: Plot the confusion matrix
from sklearn.metrics import ConfusionMatrixDisplay

ConfusionMatrixDisplay.from_predictions(
    y_test,
    y_pred,
    display_labels=data.target_names,
    cmap="Blues"
)

plt.title("KNN Confusion Matrix")
plt.tight_layout()
plt.show()

# Step 8: Predict a new sample
sample = X_test[0].reshape(1, -1)
prediction = knn_model.predict(sample)

print("\nActual class:", data.target_names[y_test[0]])
print("Predicted class:", data.target_names[prediction[0]])