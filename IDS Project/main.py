from decision_tree import predict
from feature_extraction import extract_features
import numpy as np
import pandas as pd

FEATURE_NAMES = ['StatsReport', 'WebsiteTraffic', 'UsingIP', 'LongURL', 'SymbolAt', 'Redirecting', 'PrefixSuffix', 'SubDomains', 'HTTPS', 'DomainRegLen','InfoEmail', 'AgeofDomain', 'ShortURL']
# Function to preprocess user input URL
def preprocess_url(url):
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=FEATURE_NAMES)  # Convert to DataFrame with column name
    return features_df
    #return np.array(features).reshape(1, -1)


# Function to predict if URL is phishing
def predict_url(url):
    features = preprocess_url(url)
    prediction = predict(features)
    return prediction[0]
    
    

# Loop to continuously check URLs until "stop" is entered, Loop is for testing only
#while True:
 #   user_url = input("Enter a URL to check if it's phishing (or type 'stop' to exit): ")
#    if user_url.lower() == 'stop':
 #       break
#    result = predict_url(user_url)
#    print(f"The URL '{user_url}' is {result}.")
