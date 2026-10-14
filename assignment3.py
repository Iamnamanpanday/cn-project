
# Program to implement Support Vector Machine (SVM)
# for a classification problem

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay
)

# --------------------------------------------------
# STEP 1: Generate a synthetic classification dataset
# --------------------------------------------------

X, y = make_classification(
    n_samples=500,
    n_features=2,
    n_informative=2,
    n_redundant=0,
    n_clusters_per_class=1,
    class_sep=1.5,
    random_state=42
)

print("Synthetic Dataset Created Successfully!")
print("Number of samples:", X.shape[0])
print("Number of features:", X.shape[1])

# Display first five rows
df = pd.DataFrame(X, columns=["Feature 1", "Feature 2"])
df["Class"] = y

print("\nFirst five rows of the dataset:")
print(df.head())

# --------------------------------------------------
# STEP 2: Split dataset into training and testing sets
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

# --------------------------------------------------
# STEP 3: Feature scaling
# --------------------------------------------------

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# --------------------------------------------------
# STEP 4: Create and train the SVM classifier
# --------------------------------------------------

model = SVC(kernel="linear", C=1.0)

model.fit(X_train, y_train)

print("\nSVM model trained successfully!")

# --------------------------------------------------
# STEP 5: Make predictions
# --------------------------------------------------

y_pred = model.predict(X_test)

print("\nActual labels:")
print(y_test)

print("\nPredicted labels:")
print(y_pred)

# --------------------------------------------------
# STEP 6: Evaluate the model
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy: {:.2f}%".format(accuracy * 100))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# --------------------------------------------------
# STEP 7: Visualize the confusion matrix
# --------------------------------------------------

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Class 0", "Class 1"]
)

disp.plot(cmap="Blues")
plt.title("SVM Confusion Matrix")
plt.show()

# --------------------------------------------------
# STEP 8: Visualize the classification results
# --------------------------------------------------

plt.figure(figsize=(8, 6))

plt.scatter(
    X_test[:, 0],
    X_test[:, 1],
    c=y_pred,
    cmap="coolwarm",
    edgecolors="black"
)

plt.xlabel("Feature 1 (scaled)")
plt.ylabel("Feature 2 (scaled)")
plt.title("SVM Classification Predictions")
plt.colorbar(label="Predicted Class")
plt.show()

# --------------------------------------------------
# STEP 9: Predict a new sample
# --------------------------------------------------

new_sample = np.array([[0.5, -0.5]])

new_sample_scaled = scaler.transform(new_sample)

prediction = model.predict(new_sample_scaled)

print("\nPrediction for new sample:", prediction[0])

if prediction[0] == 0:
    print("The sample belongs to Class 0")
else:
    print("The sample belongs to Class 1")
