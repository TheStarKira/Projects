from tkinter import *
import re
import requests
from tkinter import font, messagebox, ttk
import tkinter as tkr
import threading
import main as mn
import feature_extraction as fe
from PIL import Image, ImageTk

# Shortening Service are in whitelist
# Check Shortening service 
def is_shortening_service_(url): 
    shortening_services = r"(bit\.ly|tinyurl\.com|is\.gd|t\.co|ow\.ly|adf\.ly|rebrand\.ly|bl\.ink|clkim\.com|shorte\.st|u\.to|v\.gd|short\.io|snip\.ly|cut\.ly|tiny\.cc|linktr\.ee)"
    if re.search(shortening_services, url):
        return True  
    return False

def resolve_shortened_url(url):
    try:
        # Send a GET request to the shortened URL, follow redirects, and get the final URL
        response = requests.get(url, allow_redirects=True)
        return response.url
    except requests.exceptions.RequestException as e:
        print(f"Error resolving URL: {e}")
        return None 
    
def submit_url():
    url = url_entry.get()
    
    if not url: 
        status_label.config(text="Error: Please enter a URL!", fg="red")
        return 
    
    result_text.delete(1.0, tkr.END)  # Clear previous results
    status_label.config(text="Processing...", fg="blue")
    progress_bar.start()
    
    def process_url():
        # Extract features from the URL
        if is_shortening_service_(url):
            final_url = resolve_shortened_url(url)
            if final_url:  # If we successfully resolved the shortened URL
                features = fe.extract_features(final_url)
            else:
                status_label.config(text="Failed to resolve shortened URL.", fg="red")
                result_text.insert(tkr.END, "Could not resolve shortened URL.\n")
                progress_bar.stop()
                return
        else:  
            features = fe.extract_features(url)
    
        # Heuristics check and display info
        display_heuristics(features)
        
        # Check web traffic (Feature 1)
        if features[1] == 1:  
            status_label.config(text="Legitimate site", fg="green")
            result_text.insert(tkr.END, "The site is recognized in Legitamate database.\n")
            progress_bar.stop()
            return
        
        if features[0] == -1:  
            status_label.config(text="Illegitimate URL", fg='red')  
            result_text.insert(tkr.END, "Found in Phishing Database.\n")  
            progress_bar.stop()
            return

        # Perform prediction and display results
        result = mn.predict_url(url)
        progress_bar.stop()
        
        if result == 1:
            status_label.config(text="Legitimate site", fg="green")
        elif result == -1:
            status_label.config(text="Phishing site Detected", fg="red")
        else:
            status_label.config(text="Suspicious", fg="orange")
        
        print("This is final result: ", result)
    
    threading.Thread(target=process_url).start()

def display_heuristics(features):
    detailed_info = ""

    # Feature 0: Phishing report from known databases
    if features[0] == -1:
        detailed_info += "URL reported as phishing by a known database.\n"

    # Feature 1: Website traffic check (rank from top sites)
    if features[1] == -1:
        detailed_info += "Website has low or no traffic, indicating possible phishing.\n"

    # Feature 2: Using IP address instead of domain name
    if features[2] == -1:
        detailed_info += "IP address used instead of domain name, a common phishing tactic.\n"

    # Feature 3: Long URL
    if features[3] == -1:
        detailed_info += "Suspiciously long URL length detected.\n"

    # Feature 4: '@' symbol in URL
    if features[4] == -1:
        detailed_info += "'@' symbol detected, often used in phishing URLs.\n"

    # Feature 5: Redirection (based on the presence of redirection patterns)
    if features[5] == -1:
        detailed_info += "Redirection detected, a potential phishing indicator.\n"

    # Feature 6: Prefix or suffix in the domain name (e.g., hyphens)
    if features[6] == -1:
        detailed_info += "Hyphen found in the domain name, often used in phishing URLs.\n"

    # Feature 7: Number of subdomains (suspicious if too many)
    if features[7] == -1:
        detailed_info += "Multiple subdomains detected, which could indicate phishing.\n"

    # Feature 8: HTTPS usage (invalid or missing)
    if features[8] == -1:
        detailed_info += "Invalid or missing HTTPS. Or invalid SSL cert.\n"

    # Feature 9: Short domain registration length (short expiry)
    if features[9] == -1:
        detailed_info += "Expiry date of Domain registration is close.\n"

    # Feature 10: Email submission in URL
    if features[10] == -1:
        detailed_info += "Suspicious email submission detected.\n"

    # Feature 11: Domain age (very recent domain creation)
    if features[11] == -1:
        detailed_info += "Domain has a very short lifespan, it was created quite recently.\n"
    
    if features[12] == -1:
        detailed_info += "Shortening service identified. Usually used to hide long URLS"
        
    if detailed_info:
        result_text.insert(tkr.END, f"Heuristics:\n{detailed_info}")
    else:
        result_text.insert(tkr.END, "No major red flags detected.")

def reset_form():
    url_entry.delete(0, END)
    result_text.delete(1.0, END)
    status_label.config(text="")

root = Tk()
root.geometry("500x400")
root.title("Phishing Detection Tool")
root.resizable(True, True)

# Fonts
header_font = font.Font(family="Helvetica", size=16, weight="bold")
label_font = font.Font(family="Arial", size=12)

# Title label
title_label = Label(root, text="Phishing Detection Tool", font=header_font)
title_label.pack(pady=10)

# Frame for input and buttons
input_frame = Frame(root)
input_frame.pack(pady=10)

# URL label and entry
url_label = Label(input_frame, text="Enter URL:", font=label_font)
url_label.grid(row=0, column=0, padx=5, pady=5)

url_entry = Entry(input_frame, width=40)
url_entry.grid(row=0, column=1, padx=5, pady=5)

# Submit and Reset buttons
submit_button = Button(input_frame, text="Submit", command=submit_url, width=15)
submit_button.grid(row=1, column=0, pady=10)

reset_button = Button(input_frame, text="Reset", command=reset_form, width=15)
reset_button.grid(row=1, column=1, pady=10)

# Status Label
status_label = Label(root, text="", font=label_font)
status_label.pack(pady=5)

# Result Text Box
result_text = tkr.Text(root, height=10, width=60)
result_text.pack(padx=10, pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="indeterminate")
progress_bar.pack(pady=10)

root.mainloop()
