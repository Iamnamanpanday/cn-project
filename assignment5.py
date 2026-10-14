
# Program to implement Decision Tree and Random Forest
# Dataset: Breast Cancer Wisconsin (Diagnostic)

import matplotlib.pyplot as plt

from sklearn.datasets import load_breast_cancer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
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

# Step 3: Implement Decision Tree
dt_model = DecisionTreeClassifier(random_state=42)
dt_model.fit(X_train, y_train)

dt_pred = dt_model.predict(X_test)
dt_accuracy = accuracy_score(y_test, dt_pred) * 100

print("\n--- DECISION TREE RESULTS ---")
print("Accuracy: {:.2f}%".format(dt_accuracy))
print("Confusion Matrix:")
print(confusion_matrix(y_test, dt_pred))

# Step 4: Implement Random Forest
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)
rf_model.fit(X_train, y_train)

rf_pred = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_pred) * 100

print("\n--- RANDOM FOREST RESULTS ---")
print("Accuracy: {:.2f}%".format(rf_accuracy))
print("Confusion Matrix:")
print(confusion_matrix(y_test, rf_pred))

# Step 5: Compare accuracy
models = ["Decision Tree", "Random Forest"]
accuracies = [dt_accuracy, rf_accuracy]

plt.bar(models, accuracies)
plt.ylabel("Accuracy (%)")
plt.title("Decision Tree vs Random Forest")
plt.ylim(0, 100)

for i, value in enumerate(accuracies):
    plt.text(i, value + 1, "{:.2f}%".format(value),
             ha="center")

plt.tight_layout()
plt.show()

# Step 6: Predict a new sample
sample = X_test[0].reshape(1, -1)

print("\nActual class:",
      data.target_names[y_test[0]])
print("Decision Tree prediction:",
      data.target_names[dt_model.predict(sample)[0]])
print("Random Forest prediction:",
      data.target_names[rf_model.predict(sample)[0]])
