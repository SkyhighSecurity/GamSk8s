from pyicap import ICAPServer, BaseICAPRequestHandler
import socketserver
import os
import json
import magic
import requests
import logging
import base64
from requests_toolbelt.multipart.encoder import MultipartEncoder
from archive_extraction import extract_archive

# Set up temporary values to be passed later
GAM_BACKEND_URL = "http://gamapi:8080"
GAM_AUTH = ("testing", "testing")
GAM_MALWARE_THRESHOLD = 60

# Set up basic logging
logging.basicConfig(level=logging.DEBUG)

# Step 1: Create a multithreaded ICAP server using ThreadingMixIn
class ThreadedICAPServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def options_OPTIONS(self):
        """
        Handles OPTIONS requests from ICAP clients.
        This method tells the client what methods and features the server supports.
        """
        logging.info(f"Received ICAP OPTIONS request from {self.client_address}")
        
        # Set the ICAP response to 200 OK
        self.set_icap_response(200)
        
        # Inform the client about the supported methods
        self.set_icap_header(b"Methods", b"REQMOD")
        
        # Set additional ICAP headers (max file size, supported encodings, etc.)
        self.set_icap_header(b"Service", b"GAM Hyper-Scaler ICAP Service")
        self.set_icap_header(b"ISTag", b"GAM2019")  # Optional tag for versioning
        self.set_icap_header(b"Max-Connections", b"100")
        
        # Add Allow 204 support
        self.set_icap_header(b"Allow", b"204")

        # End the ICAP response
        self.send_headers()

    def echo_OPTIONS(self):
        """
        Handles OPTIONS requests for echo functionality.
        This method should tell the client what capabilities are supported for echo requests.
        """
        logging.info(f"Received ICAP ECHO OPTIONS request from {self.client_address}")
        
        # Set the ICAP response to 200 OK
                # Ensure status codes are properly set
        self.set_icap_response(200)
        
        # Set headers for echo capabilities
        self.set_icap_header(b"Methods", b"ECHO")
        self.set_icap_header(b"Service", b"My ICAP Echo Service 1.0")
        self.set_icap_header(b"ISTag", b"MyICAPEchoServiceTag1234")
        self.set_icap_header(b"Max-Connections", b"100")
        # Preview support removed
        # self.set_icap_header(b"Preview", b"1024")  # Allow previews up to 1024 bytes for echo
        # Transfer-Preview removed
        # self.set_icap_header(b"Transfer-Preview", b"1024")

        # Send the headers back to the client
                # Add Encapsulated header for REQMOD
        self.set_icap_header(b"Encapsulated", b"req-hdr=0, null-body=0")
        self.send_headers()

    def echo_REQMOD(self):
        """
        Handles REQMOD (Request Modification) requests for echo functionality.
        This method echoes back the request body, which is useful for testing.
        """
        logging.info(f"Received ICAP ECHO REQMOD request from {self.client_address}")
        
        # Set the ICAP response to 200 OK
                # Ensure status codes are properly set
        self.set_icap_response(200)
        
        # Check if the request has a body
        if not self.has_body:
            logging.info("No body in REQMOD request, returning unmodified request.")
            self.no_adaptation_required()
            return

        # Read the HTTP request body (which could contain file uploads or other data)
        request_data = self.read_file_from_request()
        if request_data:
            logging.info(f"Received request data of size: {len(request_data)} bytes, echoing back.")
            
            # Echo back the received data in the response
            self.set_enc_request(request_data)
        else:
            logging.warning("No valid request data found.")
            self.no_adaptation_required()

        # Finalize and send the response
        logging.debug("Sending ICAP headers and echoed request body.")
                # Add Encapsulated header for REQMOD
        self.set_icap_header(b"Encapsulated", b"req-hdr=0, null-body=0")
        self.send_headers()

    def reqmod_REQMOD(self):
        logging.info(f"Received ICAP REQMOD request from {self.client_address}")
        
        if not self.has_body:
            logging.info("No body in REQMOD request, returning unmodified request.")
            self.no_adaptation_required()
            return

        request_data = self.read_file_from_request()
        
        if request_data:
            logging.info(f"Received request data of size: {len(request_data)} bytes")
            
            # Call scan_file_with_gam to scan the file
            api_response = scan_file_with_gam(request_data, "scanned_file")

            # Check if the file is infected based on the new criteria using GAM_MALWARE_THRESHOLD
            malware_name = api_response.get('MalwareName')
            malware_probability = api_response.get('MalwareProbability', 0)

            if malware_name or malware_probability > GAM_MALWARE_THRESHOLD:
                logging.info(f"File is infected. MalwareName: {malware_name}, Probability: {malware_probability}")
                
                # Respond with ICAP 403 and encapsulate the JSON response in the body
                self.set_icap_response(403)  # Forbidden if the file is infected
                self.set_enc_status(b'HTTP/1.1 403 Forbidden')  # Use bytes for status
                
                # Send headers before sending the body
                self.send_headers(has_body=True)

                # Convert the API response to JSON string
                json_response = json.dumps(api_response)
                logging.debug(f"Encapsulating GAM response: {json_response}")
                
                # Encapsulate the JSON response using write_chunk
                self.write_chunk(json_response.encode('utf-8'))
                self.write_chunk(b'')  # Empty chunk to signal the end of the body
            else:
                logging.info("File is clean. Returning ICAP 204 (No Adaptation Required).")
                self.no_adaptation_required()
                return  # Ensure no further code is executed after no_adaptation_required

    def reqmod_OPTIONS(self):
        """
        Handles OPTIONS requests for the REQMOD method from ICAP clients.
        This method tells the client what methods and features the server supports.
        """
        logging.info(f"Received ICAP REQMOD OPTIONS request from {self.client_address}")
        
        # Set the ICAP response to 200 OK
        self.set_icap_response(200)
        
        # Inform the client about the supported methods
        self.set_icap_header(b"Methods", b"REQMOD")
        
        # Set additional ICAP headers (max file size, supported encodings, etc.)
        self.set_icap_header(b"Service", b"My ICAP Service 1.0")
        self.set_icap_header(b"ISTag", b"MyICAPServiceTag1234")
        self.set_icap_header(b"Max-Connections", b"100")
        
        # Add Allow 204 support for REQMOD
        self.set_icap_header(b"Allow", b"204")

        # End the ICAP response
        self.send_headers()

    def read_file_from_request(self):
        logging.debug("Checking if request has a body.")
        if not self.has_body:
            logging.debug("No body in request.")
            return None

        file_data = b''  # Ensure file_data is binary from the start
        logging.debug("Reading file in chunks.")

        while True:
            chunk = self.read_chunk()
            if chunk == b'':
                logging.debug("End of chunks.")
                break
            file_data += chunk

        logging.debug(f"Total file size: {len(file_data)} bytes.")
        return file_data  # Ensure binary data is returned

def run_server():
    server_address = ('', 1344)
    icap_server = ThreadedICAPServer(server_address, ICAPHandler)
    icap_server.serve_forever()

def encode_base64(content):
    """
    Encodes the given content to base64 format.
    """
    return base64.b64encode(content.encode('utf-8')).decode('utf-8')

def scan_file_with_gam(file_data, file_name):
    """
    Sends a file to the GAM backend scanning service for malware scanning.
    Args:
        file_data: The binary data of the file to be scanned.
        file_name: The name of the file.
    
    Returns:
        The scan result returned by the GAM backend service.
    """
    # Ensure that the file_data is in binary format
    if isinstance(file_data, int):
        raise ValueError("file_data is expected to be binary, not an integer")

    # Use only the file name in the SourceURL and base64 encode it
    source_url = f"http://0/file/{file_name}"
    encoded_source_url = encode_base64(source_url)

    # Prepare the metadata and file content for scanning, with the base64-encoded SourceURL
    metadata = json.dumps({"SourceURL": encoded_source_url})
    scan_request = {
        "meta": ("meta.json", metadata, "application/json"),  # Ensure metadata is a string
        "body": (file_name, file_data, "application/octet-stream")  # Ensure file_data is binary
    }

    encoder = MultipartEncoder(fields=scan_request)
    
    headers = {
        'Content-Type': encoder.content_type,
    }

    # Log the details of the request being sent
    logging.info(f"Sending file '{file_name}' to GAM backend for scanning.")
    logging.debug(f"Request headers: {headers}")
    logging.debug(f"File metadata: {metadata}")
    
    # Submit the request to the GAM backend
    try:
        response = requests.post(
            f"{GAM_BACKEND_URL}/GAMScanServer/v1/scans",
            data=encoder,
            headers=headers,
            auth=GAM_AUTH,  # Add basic authentication
            verify=False  # You can disable SSL verification with verify=False, though not recommended
        )
        response.raise_for_status()
        
        # Log the response details
        logging.info(f"Received response from GAM backend with status code: {response.status_code}")
        logging.debug(f"Response content: {response.text}")

        # Parse and return the scan result
        scan_result = response.json()
        logging.debug(f"Scan result: {scan_result}")
        return scan_result

    except requests.RequestException as e:
        logging.error(f"Error sending file to backend for scanning: {str(e)}")
        logging.debug(f"Request details: File name={file_name}, Headers={headers}, Encoder={encoder}")
        return {'error': str(e)}

if __name__ == "__main__":
    run_server()
