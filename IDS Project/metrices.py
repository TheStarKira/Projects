import pandas as pd
import matplotlib.pyplot as plt


data = pd.read_csv(r'C:\Users\karab\Downloads\ddddd\phishing.csv')
data.rename(columns={
    'Symbol@': 'SymbolAt',
    'Redirecting//': 'Redirecting',
    'PrefixSuffix-': 'PrefixSuffix'
}, inplace=True)

# Sample 10 rows from the dataset
sample_data = data.sample(n=10)

# Create a figure and axis
fig, ax = plt.subplots(figsize=(10, 6))  

# Hide axes
ax.axis('tight')
ax.axis('off')

# Create a table from the sample data
table_data = ax.table(cellText=sample_data.values, colLabels=sample_data.columns, cellLoc = 'center', loc='center')
plt.title('Sample Dataset Visualization')
plt.show()
