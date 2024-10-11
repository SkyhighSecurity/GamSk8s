
import os
import time
import logging
import tempfile
import json
import zipfile
import tarfile
import shutil
import concurrent.futures
import requests
import base64
import magic  # Use magic to detect file type
import pycdlib  # For ISO extraction
from requests_toolbelt.multipart.encoder import MultipartEncoder
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

# Initialize the Flask app
app = Flask(__name__)

# Set default environment variables
GAM_HOST = os.getenv('GAM_HOST', 'localhost')
GAM_PORT = os.getenv('GAM_PORT', '8080')
GAM_BACKEND = f"http://{GAM_HOST}:{GAM_PORT}"

GAM_USER = os.getenv('GAM_USER', 'testing')
GAM_PASSWORD = os.getenv('GAM_PASSWORD',  'testing')
GAM_AUTH = (GAM_USER, GAM_PASSWORD)

GAM_MALWARE_THRESHOLD = int(os.getenv('GAM_MALWARE_THRESHOLD', 60))
EXTRACT_PATH = os.getenv('EXTRACT_PATH', '/tmp')

# Configure logging to stdout/stderr
logging.basicConfig(level=logging.INFO)

# Utility function to extract archives
def extract_archive(file_path, extract_to):
    total_files = 0
    total_size = 0
    extracted_files = []

    # Use magic to identify the file type based on content
    file_type = magic.from_file(file_path, mime=True)

    # Handle ZIP files
    if file_type == 'application/zip':
        with zipfile.ZipFile(file_path, 'r') as archive:
            archive.extractall(extract_to)
            extracted_files = archive.namelist()
    # Handle TAR files (compressed or uncompressed)
    elif file_type in ['application/x-tar', 'application/gzip', 'application/x-bzip2', 'application/x-xz']:
        with tarfile.open(file_path, 'r:*') as archive:
            archive.extractall(extract_to)
            extracted_files = archive.getnames()
    # Handle ISO files
    elif file_type == 'application/x-iso9660-image':
        with pycdlib.PyCdlib() as iso:
            iso.open(file_path)
            iso_path = tempfile.mkdtemp(dir=extract_to)
            extract_iso(iso, iso_path)
            extracted_files = os.listdir(iso_path)
            iso.close()

    total_files = len(extracted_files)
    total_size = sum(os.path.getsize(os.path.join(extract_to, f)) for f in extracted_files)

    return extracted_files, total_files, total_size

def encode_base64(content):
    """
    Encodes the given content to base64 format.
    """
    return base64.b64encode(content.encode('utf-8')).decode('utf-8')

# Utility function to scan a file using the GAM backend
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
            f"{GAM_BACKEND}/GAMScanServer/v1/scans",
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

# Utility function to extract ISO files
def extract_iso(iso, extract_to):
    for dirpath, dirnames, filenames in os.walk(extract_to):
        for file in filenames:
            extracted_file = os.path.join(dirpath, file)
            full_path = os.path.join(extract_to, extracted_file)
            iso.get_file_from_iso(full_path)

# Route for streaming file upload and scanning
@app.route('/scan', methods=['POST'])
def scan_streaming():
    '''
    Handles streaming file uploads and scans them in chunks.
    Ensures each request starts fresh and preserves the original filename.
    '''
    infected_files = []
    file_name = None
    original_filename = None

    try:
        # Check if a file was uploaded in the request
        if 'file' not in request.files:
            logging.error("No file part in the request")
            return jsonify({"error": "No file part in the request"}), 400

        # Get the uploaded file
        uploaded_file = request.files['file']

        # Preserve the original filename from the Content-Disposition header
        original_filename = uploaded_file.filename
        logging.info(f"Original filename from Content-Disposition: {original_filename}")

        # Check if the file is empty
        if original_filename == '':
            logging.error("No selected file")
            return jsonify({"error": "No selected file"}), 400

        # Create a temporary file to store the uploaded content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            uploaded_file.save(temp_file.name)
            file_name = temp_file.name

        # Detect the file type
        file_type = magic.from_file(file_name, mime=True)
        logging.info(f"Detected file type: {file_type}")

        if file_type in ['application/zip', 'application/x-tar', 'application/x-7z-compressed', 'application/gzip', 'application/x-bzip2', 'application/x-xz']:
            logging.info(f"Extracting archive: {original_filename}")

            # Extract the archive and get a list of extracted files
            extracted_files, total_files, total_size = extract_archive(file_name, EXTRACT_PATH)
            logging.info(f"Archive {original_filename} extracted to {total_files} files and {total_size} bytes.")
            logging.info(f"Extracted files: {extracted_files}")
            # Scan the extracted files in parallel using a ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                future_to_file = {}
                
                for extracted_file in extracted_files:
                    extracted_file_path = os.path.join(EXTRACT_PATH, extracted_file)
                    extracted_file_name = os.path.basename(extracted_file)

                    try:
                        # Open the file and read the content
                        with open(extracted_file_path, 'rb') as f:
                            file_data = f.read()

                        # Submit the task to the executor
                        logging.info()
                        future = executor.submit(scan_file_with_gam, file_data, extracted_file_name)
                        future_to_file[future] = extracted_file_name
                    
                    except Exception as exc:
                        logging.error(f"Failed to open file {extracted_file_name}: {exc}")

                # Processing the results as futures complete
                for future in concurrent.futures.as_completed(future_to_file):
                    extracted_file_name = future_to_file[future]
                    logging.info(f"Extracted_file_name: {extracted_file_name}")
                    try:
                        scan_result = future.result()
                        logging.info(f"{extracted_file_name} result:{scan_result}")
                        if 'malware' in scan_result and scan_result['malware']:
                            infected_files.append({
                                'file': extracted_file_name,
                                'malware_info': scan_result
                            })
                            

                    except Exception as exc:
                        logging.error(f"File {extracted_file_name} generated an exception: {exc}")

        else:
            # If it's not an archive, scan the file directly
            logging.info(f"Scanning file: {original_filename}")
            scan_result = scan_file_with_gam(uploaded_file.read(), original_filename)

            if 'malware' in scan_result and scan_result['malware']:
                infected_files.append({
                    'file': original_filename,
                    'malware_info': scan_result
                })

        if infected_files:
            return jsonify({'infected_files': infected_files}), 200
        else:
            return jsonify({'message': 'No malware detected'}), 200

    except Exception as e:
        logging.error(f"Error scanning file: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
