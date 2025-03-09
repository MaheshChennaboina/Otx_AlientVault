import requests
import pandas as pd

def get_otx_api_key():
    # Replace 'YOUR_OTX_API_KEY' with your actual OTX API key
    return 'Your_API_key'

def get_ip_analysis(ip_address, api_key):
    url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/reputation'
    headers = {
        'Content-Type': 'application/json',
        'X-OTX-API-KEY': api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

def print_analysis_overview(ip_analysis):
    if ip_analysis:
        print(ip_analysis)
        # Add your desired printing logic here
    else:
        print("No analysis data available.")

def process_excel_file(file_path, api_key):
    df = pd.read_excel(file_path)

    for index, row in df.iterrows():
        ip_address = str(row['IP'])  # Assuming 'IP' is the column name for IP addresses
       # file_name = str(row['File'])  # Assuming 'File' is the column name for file names

        print(f"\nProcessing IP: {ip_address}")
        
        ip_analysis = get_ip_analysis(ip_address, api_key)
        print_analysis_overview(ip_analysis)

def main():
    api_key = get_otx_api_key()

    if not api_key:
        print("Please provide a valid OTX API key.")
        return

    excel_file_path = "input.xlsx"  # Replace with your actual Excel file path
    process_excel_file(excel_file_path, api_key)

if __name__ == "__main__":
    main()

import re
import dns.resolver
import smtplib
import pandas as pd

def is_valid_syntax(email):
    """Check if the email has a valid syntax."""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

def get_mx_record(domain):
    """Get the MX record of the domain."""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange).strip('.')
        return mx_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None

def verify_email_smtp(email, mx_record):
    """Verify the email address using SMTP connection."""
    try:
        server = smtplib.SMTP(mx_record, 25, timeout=5)
        server.helo()
        server.mail("check@example.com")  # Dummy sender email
        code, _ = server.rcpt(email)
        server.quit()
        return code == 250  # 250 means email exists
    except Exception:
        return False

def get_mail_provider(mx_record):
    """Extract mail provider from MX record dynamically."""
    if not mx_record:
        return "Unknown"

    mx_parts = mx_record.split('.')
    if len(mx_parts) > 2:
        return mx_parts[-2] + '.' + mx_parts[-1]  # Extract main domain part
    return mx_record

def validate_email(email):
    """Complete email validation process."""
    if not is_valid_syntax(email):
        return {"Deliverable": "No", "Valid Email": "No", "MX Provider": "Invalid", "Domain": "Invalid"}

    domain = email.split('@')[1]
    mx_record = get_mx_record(domain)
    
    if not mx_record:
        return {"Deliverable": "No", "Valid Email": "No", "MX Provider": "Not Found", "Domain": domain}

    is_valid = verify_email_smtp(email, mx_record)
    return {
        "Deliverable": "Yes" if is_valid else "No",
        "Valid Email": "Yes" if is_valid else "No",
        "MX Provider": get_mail_provider(mx_record),
        "Domain": domain
    }

def process_excel(input_file, output_file):
    """Reads emails from an Excel file, validates them, and writes results to a new Excel file."""
    df = pd.read_excel(input_file)

    if 'Email' not in df.columns:
        print("Error: The input Excel file must contain a column named 'Email'")
        return

    results = df['Email'].apply(validate_email)
    results_df = pd.DataFrame(results.tolist())

    final_df = pd.concat([df, results_df], axis=1)
    final_df.to_excel(output_file, index=False)

    print(f"✅ Validation completed! Results saved in: {output_file}")

# Input and Output Excel file paths
input_file = "emails.xlsx"   # Input file with a column named 'Email'
output_file = "validated_emails.xlsx"  # Output file with validation results

process_excel(input_file, output_file)


27rsewnath@tenafly.k12.nj.us
aanderson@glytec-systems.com
aandriopulos@sherpadigitalmedia.com
aanglace@completestaffingsolutions.com
aaron.m@focuscares.com
aaron@atlanticstss.com
abby.parker@selectyourdata.com
abel.x.sanchez@questdiagnostics.com
aberger@pensionbridge-email.com
abhijeet.gaikwad@automationedge.com
abigail.c.baeza@rrd.com
abigail@midlevelu.com
abishop@pods.com
abrava@merraine.com
abush@elasticroi.com
academy@alchemysystems.com
achisholm@boma.org
aclements@powerofcleanenergy.com
acorter1@newcourtland.org





