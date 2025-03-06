import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def check_https_details(url):
    parsed_url = urlparse(url)

    # Checks if  URL uses HTTPS
    if parsed_url.scheme != 'https':
        return -1  # Not using HTTPS

    hostname = parsed_url.hostname

    # Creates a socket connection
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443)) as sock:
            #Get the SSL certificate
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Extract issuer and notAfter attributes
                issuer = dict(x[0] for x in cert['issuer'])
                not_after = cert['notAfter']

                # Convert notAfter to a datetime object
                cert_expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y GMT')

                # List of trusted issuers
                trusted_issuers = [
                    'DigiCert',
                    'GoDaddy',
                    'Sectigo',
                    'GlobalSign',
                    'Entrust',
                    'Let’s Encrypt',
                    'Amazon Trust Services',
                    'Google Trust Services',
                    'Buypass',
                    'SSL.com',
                    'ID Authority',
                    'Actalis',
                ]
                
                issuer_name = issuer.get('organizationName', '')

                # Check if the issuer is trusted
                is_trusted = any(trusted_issuer in issuer_name for trusted_issuer in trusted_issuers)

                # Calculate the age of the certificate in years
                age_years = (cert_expiry - datetime.now()).days / 365

                #the classifier 
                if is_trusted and age_years >= 1:
                    return 1  
                elif is_trusted and age_years < 1:
                    return 0  
                else:
                    return -1  

    except Exception as e:
        return -1  # Error occurred (considered phishing for safety)
#only for testing 
# Example usage
# url = input("Enter URL: ")
# https_check = check_https_details(url)
# print(f"HTTPS Check Result: {https_check}")
