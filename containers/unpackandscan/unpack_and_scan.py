import os
import time
import logging
import tempfile
import json
import zipfile
import tarfile
import shutil
import requests
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

# Initialize the Flask app
app = Flask(__name__)

# Set default environment variables
GAM_MALWARE_THRESHOLD = int(os.getenv('GAM_MALWARE_THRESHOLD', 60))
EXTRACT_PATH = os.getenv('EXTRACT_PATH', '/tmp')

# Configure logging to stdout/stderr
logging.basicConfig(level=logging.INFO)

# Utility function to extract archives
def extract_archive(file_path, extract_to):
    total_files = 0
    total_size = 0
    extracted_files = []

    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, 'r') as archive:
            archive.extractall(extract_to)
            extracted_files = archive.namelist()
    elif tarfile.is_tarfile(file_path):
        with tarfile.open(file_path, 'r:*') as archive:
            archive.extractall(extract_to)
            extracted_files = archive.getnames()

    # Calculate the total number of files and bytes extracted
    for extracted_file in extracted_files:
        total_files += 1
        total_size += os.path.getsize(os.path.join(extract_to, extracted_file))

    return total_files, total_size, extracted_files

# Utility function to scan a file using GAM backend
def scan_file_with_gam(file_data, file_name):
    source_url = f"http://0/file/{file_name}"
    encoded_source_url = encode_base64(source_url)

    metadata = json.dumps({"SourceURL": encoded_source_url})
    scan_request = {
        "meta": ("meta.json", metadata, "application/json"),
        "body": (file_name, file_data, "application/octet-stream")
    }

    encoder = MultipartEncoder(fields=scan_request)
    headers = {'Content-Type': encoder.content_type}

    try:
        response = requests.post(
            f"{GAM_BACKEND_URL}/GAMScanServer/v1/scans",
            data=encoder,
            headers=headers,
            auth=GAM_AUTH,
            verify=False
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error scanning file: {str(e)}")
        return {'error': str(e)}

# Route to handle file uploads and scanning
@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(uploaded_file.filename)
    file_path = os.path.join(EXTRACT_PATH, filename)
    
    # Save the uploaded file to temporary storage
    uploaded_file.save(file_path)

    # Check if the file is an archive and extract if necessary
    total_files = 0
    total_size = 0
    extracted_files = []
    infected_files = []
    not_infected_files = []

    if zipfile.is_zipfile(file_path) or tarfile.is_tarfile(file_path):
        start_time = time.time()
        extract_to = tempfile.mkdtemp(dir=EXTRACT_PATH)
        total_files, total_size, extracted_files = extract_archive(file_path, extract_to)
        logging.info(f"Extracted archive {filename} with {total_files} files totaling {total_size} bytes")

        # Scan each extracted file
        for extracted_file in extracted_files:
            full_path = os.path.join(extract_to, extracted_file)
            with open(full_path, 'rb') as f:
                file_data = f.read()
                scan_result = scan_file_with_gam(file_data, extracted_file)

                malware_name = scan_result.get('MalwareName')
                malware_probability = scan_result.get('MalwareProbability', 0)
                if malware_name or malware_probability > GAM_MALWARE_THRESHOLD:
                    infected_files.append({
                        "file": extracted_file,
                        "malware_name": malware_name,
                        "malware_probability": malware_probability
                    })
                else:
                    not_infected_files.append(extracted_file)

        shutil.rmtree(extract_to)
        elapsed_time = time.time() - start_time
        logging.info(f"Scanned archive {filename} in {elapsed_time:.2f} seconds: "
                     f"{len(infected_files)} infected, {len(not_infected_files)} clean")

    else:
        # If the file is not an archive, scan it directly
        with open(file_path, 'rb') as f:
            file_data = f.read()
            scan_result = scan_file_with_gam(file_data, filename)

            malware_name = scan_result.get('MalwareName')
            malware_probability = scan_result.get('MalwareProbability', 0)
            if malware_name or malware_probability > GAM_MALWARE_THRESHOLD:
                infected_files.append({
                    "file": filename,
                    "malware_name": malware_name,
                    "malware_probability": malware_probability
                })
            else:
                not_infected_files.append(filename)

    # Return the results
    return jsonify({
        "infected_files": infected_files,
        "not_infected_files": not_infected_files,
        "total_infected": len(infected_files),
        "total_clean": len(not_infected_files)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
