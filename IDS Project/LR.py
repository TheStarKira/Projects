from urllib import request
import numpy as np
import pandas as pd
import re
import joblib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests 
from sklearn import metrics
from sklearn.base import BaseEstimator, ClassifierMixin

# Code adapted from:
# "7.2.6. Implementing Logistic Regression from scratch in Python"
# Retrieved From: https://www.youtube.com/watch?v=DeUAvYyB0Os&list=PLfFghEzKVmjsF8ixJ-xKVuQayPWRH4Sp6&index=6
#
# and
#
# "How to implement Logistic Regression from scratch with Python"
# Retrieved From: https://www.youtube.com/watch?v=DeUAvYyB0Os&list=PLfFghEzKVmjsF8ixJ-xKVuQayPWRH4Sp6&index=6
# Define sigmoid function
# Reference for using BeautifulSoup for web scraping
# Source: https://realpython.com/beautiful-soup-web-scraper-python/

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

# Define Logistic Regression class

class LogisticRegression(BaseEstimator, ClassifierMixin):
    def __init__(self, lrate=0.001, nofiters=1000):
        self.lrate = lrate
        self.nofiters = nofiters
        
    def evaluate(self, X, y_true):
        y_pred = self.predict(X)
        accuracy = np.mean(y_pred == y_true)  # Calculate accuracy
        return accuracy    

    def fit(self, X, y):
        # Number of rows and columns
        nofsamples, noffeatures = X.shape
        self.weights = np.zeros(noffeatures)
        self.bias = 0

        for _ in range(self.nofiters):
            linpred = np.dot(X, self.weights) + self.bias
            predictions = sigmoid(linpred)

            # Derivatives
            dw = (1 / nofsamples) * np.dot(X.T, (predictions - y))
            db = (1 / nofsamples) * np.sum(predictions - y)

            self.weights -= self.lrate * dw
            self.bias -= self.lrate * db

    def predict(self, X):
        linpred = np.dot(X, self.weights) + self.bias
        y_pred = sigmoid(linpred)
        return np.where(y_pred >= 0.5, 1, -1)  # Changed to return 1 or -1

    def predict_proba(self, X):
        linpred = np.dot(X, self.weights) + self.bias
        y_prob = sigmoid(linpred)
        return np.vstack((1 - y_prob, y_prob)).T  # Return probabilities for both classes

    def set_params(self, **params):
        for key, value in params.items():
            setattr(self, key, value)
        return self

    def get_params(self, deep=True):
        return {"lrate": self.lrate, "nofiters": self.nofiters}


# Load dataset
df = pd.read_csv(r'C:\Users\karab\Downloads\ddddd\phishing.csv')

# Rename columns 
df.rename(columns={
    'Symbol@': 'SymbolAt',
    'Redirecting//': 'Redirecting',
    'PrefixSuffix-': 'PrefixSuffix'
}, inplace=True)

# Inspect column names
print("Column names in the dataset:")
print(df.columns)


desired_columns = ['UsingIP', 'LongURL', 'SymbolAt', 'Redirecting', 'PrefixSuffix', 'SubDomains', 'HTTPS', 'InfoEmail','class']


df = df[desired_columns]

# Display the first few rows
print("First few rows of the dataset:")
print(df.head())

# Display summary statistics
print(df.describe())

# Ensure all features are numeric
df = df.apply(pd.to_numeric, errors='coerce')

# Drop rows with any NaN values
df.dropna(inplace=True)

# Feature extraction
X = df.iloc[:, :-1].values  # Convert to NumPy array (exclude the 'class' column)
y = df.iloc[:, -1].values    # Convert to NumPy array (only the 'class' column)

# Shuffling
indexes = np.arange(X.shape[0])
np.random.shuffle(indexes)

X = X[indexes]
y = y[indexes]

# Splitting
split_ratio = 0.2
split_index = int(split_ratio * len(indexes))

X_train = X[:split_index]
y_train = y[:split_index]
X_test = X[split_index:]
y_test = y[split_index:]

print("Training data shape:", X_train.shape, y_train.shape)
print("Testing data shape:", X_test.shape, y_test.shape)

# Train the model
model = LogisticRegression(lrate=0.1, nofiters=500)
model.fit(X_train, y_train)
joblib.dump(model, 'logistic_regression_model.joblib')
# Predict on test set
y_pred = model.predict(X_test)


# Evaluate model performance
accuracy = metrics.accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy * 100:.2f}%")
precision = metrics.precision_score(y_test, y_pred, pos_label=-1)  
print(f"Precision: {precision:.2f}")
# Recall
recall = metrics.recall_score(y_test, y_pred, pos_label=-1)
print(f"Recall: {recall:.2f}")
# F1-Score
f1 = metrics.f1_score(y_test, y_pred, pos_label=-1)
print(f"F1-Score: {f1:.2f}")
cm = metrics.confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(cm)

report = metrics.classification_report(y_test, y_pred)
print("Classification Report:")
print(report)
lr_metrics = {
    'Accuracy': accuracy,
    'Precision': precision,
    'Recall': recall,
    'F1-Score': f1
}

# Feature extraction functions
def redirect_check(url):
    if url.startswith("https://"):
        ex_pos = 7
    else:
        ex_pos = 6
    return 1 if url.find('//', ex_pos) > ex_pos else -1

def submit_to_email(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form', action=re.compile(r'^mailto:', re.IGNORECASE))
        return 1 if forms else -1
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return -1
#finding best parameters
param_grid = {
    'lrate': [0.001, 0.01, 0.1],
    'nofiters': [500, 1000, 1500]
}

best_score = 0
best_params = {}

for lrate in param_grid['lrate']:
    for nofiters in param_grid['nofiters']:
        model = LogisticRegression(lrate=lrate, nofiters=nofiters)
        model.fit(X_train, y_train)
        score = model.evaluate(X_train, y_train)  # Define an `evaluate` function in your class
        if score > best_score:
            best_score = score
            best_params = {'lrate': lrate, 'nofiters': nofiters}

print("Best Parameters:", best_params)

