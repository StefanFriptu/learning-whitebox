import numpy as np
import pandas as pd
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score

# Load the dataset
dataset_csv = pd.read_csv(r'./datasets/obfuscated_dataset_v1.1.csv')

# Drop function name
dataset_csv = dataset_csv.drop(columns=['function name'])

# Fill target as 'not related'=0
dataset_csv[['target']] = dataset_csv[['target']].fillna(value=0)

# Split dataset into training and test
features = dataset_csv.drop('target', axis=1)
target = dataset_csv['target']

X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2)

# Define the classifier
classifier = SVC()

# Define the hyperparameter grid
param_grid = [
    {
        'C': [0.1, 1, 10, 100],
        'kernel': ['linear'],
    },
    {
        'C': [0.1, 1, 10, 100],
        'kernel': ['rbf'],
        'gamma': ['scale', 'auto', 0.1, 1, 10, 100]
    },
    {
        'C': [0.1, 1, 10, 100],
        'kernel': ['poly'],
        'gamma': ['scale', 'auto'],
        'degree': [2, 3, 4]
    }
]

# Create the GridSearchCV object
grid_search = GridSearchCV(estimator=classifier, param_grid=param_grid, cv=5, n_jobs=-1, verbose=2)

# Add weights to features
weights = np.ones(X_train.shape[0])
weights[X_train.iloc[:, 7] == 1] = 3

# Fit the GridSearchCV object to the training data
grid_search.fit(X_train, y_train, sample_weight = weights)

# Get the best hyperparameters
best_params = grid_search.best_params_
print("Best hyperparameters:", best_params)

# Get the best model
best_model = grid_search.best_estimator_

# Evaluate the model on the test set
y_pred = best_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Test accuracy: {accuracy:.2f}")
