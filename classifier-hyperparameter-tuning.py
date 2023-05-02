import pandas as pd
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score
from sklearn.pipeline import Pipeline

# Load the dataset
dataset_csv = pd.read_csv(r'./datasets/obfuscated_dataset_v1.csv')

# Drop function name
dataset_csv = dataset_csv.drop(columns=['function name'])

# Fill target as 'not related'=0
dataset_csv[['target']] = dataset_csv[['target']].fillna(value=0)

# Split dataset into training and test
features = dataset_csv.drop('target', axis=1)
target = dataset_csv['target']

X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2)

# Create an SVM pipeline with StandardScaler for preprocessing
pipeline = Pipeline([
    ('classifier', SVC())
])

# Define the hyperparameters for tuning
param_grid = {
    'classifier__C': [0.1, 1, 10, 100],
    'classifier__kernel': ['linear', 'rbf', 'poly'],
    'classifier__degree': [2, 3, 4],
    'classifier__gamma': ['scale', 'auto']
}

# Perform Grid Search for hyperparameter tuning
grid_search = GridSearchCV(pipeline, param_grid, refit=True, cv=5, verbose=2, scoring='accuracy')
grid_search.fit(X_train, y_train)

print("Best parameters found by Grid Search:", grid_search.best_params_)

# Get the best model
best_model = grid_search.best_estimator_

# Evaluate the model on the test set
y_pred = best_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Test accuracy: {accuracy:.2f}")
