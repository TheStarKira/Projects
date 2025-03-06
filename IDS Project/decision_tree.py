from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics
from sklearn.model_selection import train_test_split
import numpy as np
import pandas as pd
import joblib

def load_data():
    df = pd.read_csv(r'C:\Users\karab\OneDrive\Desktop/IDS Project/phishing.csv')
    print(df.columns)
    # Rename columns 
    df.rename(columns={
        'Symbol@': 'SymbolAt',
        'Redirecting//': 'Redirecting',
        'PrefixSuffix-': 'PrefixSuffix'
    }, inplace=True)

    desired_columns = ['StatsReport', 'WebsiteTraffic', 'UsingIP', 'LongURL', 'SymbolAt', 'Redirecting', 'PrefixSuffix', 'SubDomains', 'HTTPS', 'DomainRegLen', 'InfoEmail', 'AgeofDomain', 'ShortURL']
    
    #  feature selection and target
    X = df[desired_columns]
    y = df['class'].apply(pd.to_numeric, errors='coerce').dropna()
    
    
    
    print(f"Shape of X: {X.shape}")  
    print(f"Shape of y: {y.shape}") 
    return X, y

def train_and_save_model():
    X, y = load_data()
    # Split training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Initialize the decision tree classifier
    decision_tree = DecisionTreeClassifier(max_depth=3)
    # Fit the model on the training data
    decision_tree.fit(X_train, y_train)
    
    # Predict on the test data
    y_pred = decision_tree.predict(X_test)
    
    # Metrices to measure performance 
    accuracy = metrics.accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.2f}")
    
    # Precision
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
    
    # Saves the model to a file
    joblib.dump(decision_tree, 'decision_tree_model.pkl')
    
    # Save X_test and y_test for later use( gonna use it for ensemble training)
    joblib.dump(X_test, 'X_test.joblib')
    joblib.dump(y_test, 'y_test.joblib')
    joblib.dump(X_train, 'X_train.joblib')
    joblib.dump(y_train, 'y_train.joblib')

    return {
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1-Score': f1
    }

def load_model():
    return joblib.load('decision_tree_model.pkl')

def predict(features):
    model = load_model()
    predictions = model.predict(features)
    print("This is Pred: ", predictions)
    return predictions


if __name__ == "__main__":
    train_and_save_model()
