from pyicap import ICAPServer, BaseICAPRequestHandler
import socketserver
import json
import requests
import logging
import os
from requests_toolbelt.multipart.encoder import MultipartEncoder

# Set up temporary values to be passed later
GAM_MANAGER_HOST = os.getenv('GAM_MANAGER_HOST', 'localhost')
GAM_MANAGER_PORT = os.getenv('GAM_MANAGER_PORT', '5000')
GAM_MANAGER_URL = f"http://{GAM_MANAGER_HOST}:{GAM_MANAGER_PORT}/scan"


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

        http_request = self.enc_req
        method, url, version = http_request
        filename = os.path.basename(url)
        logging.info(f"Processing file: {filename}")

        request_data = self.read_file_from_request()

        if request_data:
            logging.info(f"Received request data of size: {len(request_data)} bytes")
            
            # Call scan_with_manager to scan the file
            api_response = scan_with_manager(request_data, filename)
###
            # Check for infected files
            logging.info(f"api_response: {api_response}")
            infected_files = api_response.get('infected_files', '')
            
            if infected_files:
                # Infected files were found
                # Respond with ICAP 403 and encapsulate the JSON response in the body
                self.set_icap_response(403)  # Forbidden if the file is infected
                self.set_enc_status(b'HTTP/1.1 403 Forbidden')  # Use bytes for status
                
                # Send headers before sending the body
                self.send_headers(has_body=True)

                # Convert the API response to JSON string
                json_response = json.dumps(api_response)
                logging.debug(f"Encapsulating GAM-Manager response: {json_response}")
                
                # Encapsulate the JSON response using write_chunk
                self.write_chunk(json_response.encode('utf-8'))
                self.write_chunk(b'')  # Empty chunk to signal the end of the body

            else:
                # No infected files were found
                logging.info(f"No infected files found for {filename}")
                logging.info("File is clean. Returning ICAP 204 (No Adaptation Required).")
                self.no_adaptation_required()


###


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

def scan_with_manager(file_data, file_name):
    """
    Sends a file to the middle layer API to check if it contains any infected files.
    
    Args:
        file_name: The name of the file being scanned.
        file_data: The binary content of the file being scanned.
        
    Returns:
        A json result from the gam-backend
    """
    try:

        logging.info(f"Scan with manager filename: {file_name}")
        logging.info(f"Scan with manager filedata: {file_data}")


        # Prepare the file for the request
        files = {'file': (file_name, file_data, 'application/octet-stream')}
        
        # Send the file to the middle layer for scanning
        response = requests.post(GAM_MANAGER_URL, files=files)
        response.raise_for_status()  # Raise an exception for any HTTP errors
        
        # Log and parse the response
        scan_result = response.json()
        logging.info(f"Received scan result: {scan_result}")
        
        return scan_result

    except requests.RequestException as e:
        logging.error(f"Error scanning file {file_name}: {str(e)}")
        return False, None

if __name__ == "__main__":
    run_server()
