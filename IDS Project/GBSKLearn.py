import pandas as pd 
import joblib
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import GridSearchCV
from sklearn import metrics
 
data = pd.read_csv(r'C:\Users\karab\Downloads\ddddd\phishing.csv')
data.rename(columns={
    'Symbol@': 'SymbolAt',
    'Redirecting//': 'Redirecting',
    'PrefixSuffix-': 'PrefixSuffix'
}, inplace=True)

# Desired columns for training
desired_columns = ['UsingIP', 'LongURL', 'SymbolAt', 'Redirecting', 'PrefixSuffix', 'SubDomains', 'HTTPS', 'InfoEmail', 'class']
df = data[desired_columns]

# Define features and target
X = df.drop('class', axis=1)
y = df['class']

#split into testing and training 
X_train, X_test, y_train, y_test = train_test_split(X,y, test_size=0.2, random_state=42)
gradientbooster =  GradientBoostingClassifier(learning_rate=1.0, max_depth=5, n_estimators=10)
gradientbooster.fit(X_train, y_train)
joblib.dump(gradientbooster, 'gradientbooster_model.joblib')
y_pred = gradientbooster.predict(X_test)
cvs = cross_val_score(gradientbooster, X_train, y_train, cv=3)


#metrices to measure performance 
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
#Checking for which parameters are the best 
#param_grid = {
   # 'n_estimators' : [10,50, 100, 500],
    #'learning_rate': [0.0001, 0.001, 0.01, 0.1, 1.0],
    #'max_depth': [3,5,7,9] 
#}

#gbr = GridSearchCV(gradientbooster, param_grid, cv=3, n_jobs=-1)
#gbr.fit(X_train, y_train)
#cvs2 = cross_val_score(gbr, X_train, y_train, cv=3)
#gbrbsp = gbr.best_params_
#print(gbrbsp)
#print(cvs)
#print(cvs2)



