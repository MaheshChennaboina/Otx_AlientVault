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
