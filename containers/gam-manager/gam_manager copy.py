
import os
import time
import logging
import tempfile
import json
import zipfile
import tarfile
import shutil
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

        # Create a temporary file to store the upload
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                file_name = temp_file.name
                logging.info(f"Receiving and saving file stream to temporary file: {file_name}")

                # Read and log the first 100 bytes
                first_100_bytes = uploaded_file.read(100)
                logging.info(f"First 100 bytes of the file: {first_100_bytes}")

                # Write the rest of the file to disk (starting after the first 100 bytes)
                temp_file.write(first_100_bytes + uploaded_file.read())

            # Ensure the file has been fully written before proceeding
            if not os.path.exists(file_name):
                logging.error(f"File {file_name} was not created properly")
                return jsonify({"error": f"File {file_name} was not created properly"}), 500

            logging.info(f"File stream received, starting scan for {file_name}")

        except Exception as e:
            logging.error(f"Error writing file to disk: {e}")
            return jsonify({"error": f"Error writing file to disk: {e}"}), 500

        # Check if the file is an archive or not
        file_type = magic.from_file(file_name, mime=True)
        logging.info(f"Detected file type: {file_type}")

        if file_type in ['application/zip', 'application/x-tar', 'application/gzip', 'application/x-bzip2', 'application/x-xz', 'application/x-iso9660-image']:
            # It's an archive, proceed with extraction
            logging.info("File is an archive, extracting...")
            extracted_files, total_files, total_size = extract_archive(file_name, EXTRACT_PATH)
            logging.info(f"Extraction complete: {total_files} files extracted with total size {total_size} bytes")

            # Scan each extracted file
            for extracted_file in extracted_files:
                full_path = os.path.join(EXTRACT_PATH, extracted_file)

                if os.path.isfile(full_path):
                    with open(full_path, 'rb') as f:
                        file_data = f.read()

                        # Log the original extracted filename
                        logging.info(f"Sending extracted file {extracted_file} for scanning")

                        # Send file to GAM backend
                        scan_result = scan_file_with_gam(file_data, extracted_file)

                        malware_name = scan_result.get('MalwareName')
                        malware_probability = scan_result.get('MalwareProbability', 0)
                        if malware_name and malware_probability > GAM_MALWARE_THRESHOLD:
                            infected_files.append({
                                "file": extracted_file,
                                "malware_name": malware_name,
                                "malware_probability": malware_probability
                            })
                else:
                    logging.info(f"Skipping directory entry: {full_path}")

        else:
            # It's not an archive, process it directly using the original filename
            logging.info(f"File is not an archive, sending original file {original_filename} for scanning")

            with open(file_name, 'rb') as f:
                file_data = f.read()

                # Pass the original filename directly without modification
                logging.info(f"Sending original file {original_filename} for scanning")

                # Send the file for scanning, preserving the original filename
                scan_result = scan_file_with_gam(file_data, original_filename)
                logging.info(f"scan_result = {scan_result}")
                malware_name = scan_result.get('MalwareName')
                malware_probability = scan_result.get('MalwareProbability', 0)
                if malware_name and malware_probability > GAM_MALWARE_THRESHOLD:
                    infected_files.append({
                        "file": original_filename,
                        "malware_name": malware_name,
                        "malware_probability": malware_probability
                    })

    except Exception as e:
        logging.error(f"Error during file processing: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        # Clean up temporary file and directory
        if file_name and os.path.exists(file_name):
            os.remove(file_name)
            logging.info(f"Temporary file {file_name} deleted")
        if os.path.exists(EXTRACT_PATH):
            shutil.rmtree(EXTRACT_PATH)
            logging.info(f"Temporary extraction path {EXTRACT_PATH} deleted")

    # Return the result
    return jsonify({
        "infected_files": infected_files,
        "total_infected": len(infected_files),
        "not_infected": total_files - len(infected_files) if 'total_files' in locals() else 0
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
