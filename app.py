from flask import Flask, render_template, request, redirect, url_for
import os
import requests
import hashlib
import json

app = Flask(__name__)

# Define the folder to store uploaded PE files
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Replace 'YOUR_API_KEY' with your actual VirusTotal V3 API key
VT_API_KEY = 'a5133077b3a53e1c05f5e9053562a4d0aad5a63117897160921d45729e2928e6'
VT_API_URL = 'https://www.virustotal.com/api/v3/'

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filename)

            # Perform malware analysis with VirusTotal V3
            analysis_result = analyze_pe_with_virustotal_v3(filename)
            return render_template('index.html', result=analysis_result)
    return render_template('index.html', result=None)

def analyze_pe_with_virustotal_v3(pe_path):
    try:
        # Prepare the API request headers
        headers = {
            'x-apikey': VT_API_KEY,
        }

        # Get information about the results of analysis
        file_hash = hashlib.sha256(open(pe_path, 'rb').read()).hexdigest()
        info_url = VT_API_URL + 'files/' + file_hash
        response = requests.get(info_url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            # Extract and format only the essential information
            essential_info = extract_essential_info(result)
            return essential_info
        else:
            return "Error getting information from VirusTotal V3."

    except Exception as e:
        return f"Error analyzing PE file: {str(e)}"

def extract_essential_info(result):
    try:
        essential_data = {}

        # Check if 'data' key exists in the result
        if 'data' in result:
            data = result['data']

            # Extract overall statistics
            stats = data.get("attributes", {}).get("stats", {})
            essential_data["Malicious"] = stats.get("malicious", 0)
            essential_data["Undetected"] = stats.get("undetected", 0)

            # Extract scan engine results
            results = data.get("attributes", {}).get("results", {})
            engine_results = []

            for k, v in results.items():
                if v.get("category") == "malicious":
                    engine_result = {
                        "Engine Name": v.get("engine_name", "N/A"),
                        "Version": v.get("engine_version", "N/A"),
                        "Category": v.get("category", "N/A"),
                        "Result": v.get("result", "N/A"),
                        "Method": v.get("method", "N/A"),
                        "Engine Update": v.get("engine_update", "N/A"),
                    }
                    engine_results.append(engine_result)

            essential_data["Engine Results"] = engine_results

        return essential_data

    except Exception as e:
        return f"Error extracting essential info: {str(e)}"


if __name__ == '__main__':
    app.run(debug=True)
