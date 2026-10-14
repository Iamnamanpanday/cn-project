
    # Program to implement Bagging and Boosting
    # Dataset: Breast Cancer Wisconsin (Diagnostic)

    import pandas as pd
    import matplotlib.pyplot as plt

    from sklearn.datasets import load_breast_cancer
    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import BaggingClassifier, AdaBoostClassifier
    from sklearn.metrics import accuracy_score, confusion_matrix

    # Step 1: Load dataset
    data = load_breast_cancer()
    X = data.data
    y = data.target

    print("Dataset loaded successfully!")
    print("Dataset shape:", X.shape)
    print("Features:", X.shape[1])
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

    # Step 3: Implement Bagging
    bagging_model = BaggingClassifier(
        estimator=DecisionTreeClassifier(random_state=42),
        n_estimators=100,
        random_state=42
    )

    bagging_model.fit(X_train, y_train)
    bagging_pred = bagging_model.predict(X_test)

    bagging_accuracy = accuracy_score(y_test, bagging_pred) * 100

    print("\n--- BAGGING RESULTS ---")
    print("Accuracy: {:.2f}%".format(bagging_accuracy))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, bagging_pred))

    # Step 4: Implement Boosting using AdaBoost
    boosting_model = AdaBoostClassifier(
        n_estimators=100,
        random_state=42
    )

    boosting_model.fit(X_train, y_train)
    boosting_pred = boosting_model.predict(X_test)

    boosting_accuracy = accuracy_score(y_test, boosting_pred) * 100

    print("\n--- BOOSTING RESULTS ---")
    print("Accuracy: {:.2f}%".format(boosting_accuracy))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, boosting_pred))

    # Step 5: Compare accuracy using a bar chart
    models = ["Bagging", "Boosting"]
    accuracies = [bagging_accuracy, boosting_accuracy]

    plt.bar(models, accuracies)
    plt.ylabel("Accuracy (%)")
    plt.title("Bagging vs Boosting Accuracy")
    plt.ylim(0, 100)

    for i, value in enumerate(accuracies):
        plt.text(i, value + 1, f"{value:.2f}%", ha="center")

    plt.tight_layout()
    plt.show()

    # Step 6: Predict a new sample
    sample = X_test[0].reshape(1, -1)

    print("\nActual class:",
        data.target_names[y_test[0]])
    print("Bagging prediction:",
        data.target_names[bagging_model.predict(sample)[0]])
    print("Boosting prediction:",
        data.target_names[boosting_model.predict(sample)[0]])