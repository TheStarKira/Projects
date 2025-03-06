import pandas as pd
import sqlite3
import re


csv_path = r'C:\Users\karab\Downloads\phishset.csv'
df = pd.read_csv(csv_path)

conn = sqlite3.connect('phish_database.db')
cursor = conn.cursor()

# Create the table 
cursor.execute('''
    CREATE TABLE IF NOT EXISTS phish_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        verified TEXT CHECK(verified IN ('yes', 'no')) DEFAULT 'no'
    )
''')
cursor.execute("CREATE INDEX IF NOT EXISTS idx_url ON phish_urls(url)")

df.columns = [col.strip().lower() for col in df.columns]  
def clean_url (url):
    # Remove https, http, www.
    url = re.sub(r"^(https?://)?(www\.)?", "", url)
    url = re.match(r'^[^/]+', url).group(0)
    return url

# Inserts  data into  table
for _, row in df.iterrows():
    cleaned_url = clean_url(row['url'])  # Clean the URL before inserting
    cursor.execute('''
        INSERT INTO phish_urls (url, verified) VALUES (?, ?)
    ''', (cleaned_url, row['verified']))


# Close the connection
conn.commit()
conn.close()


def database_check(url):
    # Connect to SQLite database
    conn = sqlite3.connect('phish_database.db')  # Replace with your database path
    cursor = conn.cursor()
    
    # cleans the URL for comparison
    cleaned_url  = clean_url (url)
    cursor.execute("SELECT verified FROM phish_urls WHERE url = ?", (cleaned_url ,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return -1 if result[0].lower() == 'yes' else 1
    else:
        return 1
    
    

