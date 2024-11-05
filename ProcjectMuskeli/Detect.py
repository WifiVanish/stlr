import requests
import time
import os

# Set your VirusTotal API key here
API_KEY = '32fd8f4b548f60b3b17e74d2fead26d37734c49e57eef845a8963ac626ef1d1b'  # Replace with your actual API key

def upload_file_to_virustotal(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    
    # Check the size of the file (in bytes)
    file_size = os.path.getsize(file_path)
    print(f"Uploading file of size: {file_size} bytes")

    if file_size > 650 * 1024 * 1024:  # 650 MB in bytes
        print(f"The file is too large for VirusTotal. Maximum size is 650 MB.")
        return None

    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            params = {'apikey': API_KEY}
            response = requests.post(url, files=files, params=params)

        if response.status_code == 200:
            result = response.json()
            return result['resource']  # Return the resource ID to get scan results
        else:
            print(f"Failed to upload the file. Status code: {response.status_code}")
            print(f"Response content: {response.text}")  # Print response content for debugging
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_scan_results(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': resource}

    # Retry until we get the results
    for _ in range(10):
        response = requests.get(url, params=params)
        result = response.json()
        if result.get('response_code') == 1:
            return result  # The scan is done, return the result
        else:
            print("Waiting for scan results...")
            time.sleep(15)  # Wait for 15 seconds before trying again

    return None

def display_detection_results(scan_results):
    positives = scan_results.get('positives', 0)
    total = scan_results.get('total', 0)

    print(f"\nDetection Summary: {positives}/{total} antivirus engines detected the file.")
    if positives > 0:
        print("\nDetected by the following antivirus engines:")
        for engine, result in scan_results['scans'].items():
            if result['detected']:
                print(f"{engine}: {result['result']}")

def main():
    # Ask for the file path in the command line
    file_path = input("Enter the path to the file you want to scan: ")

    # Step 1: Upload the file to VirusTotal
    resource = upload_file_to_virustotal(file_path)
    if resource:
        print("File uploaded successfully. Getting scan results...")

        # Step 2: Get the scan results
        scan_results = get_scan_results(resource)
        if scan_results:
            # Step 3: Display detection results
            display_detection_results(scan_results)
        else:
            print("Failed to retrieve scan results.")
    else:
        print("File upload failed.")

if __name__ == "__main__":
    main()
