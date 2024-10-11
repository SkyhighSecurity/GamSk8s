from pyicap import ICAPServer, BaseICAPRequestHandler
import socketserver
import requests
import logging
import os
import mimetypes
import json
from requests_toolbelt.multipart.encoder import MultipartEncoder

# Set up temporary values to be passed later
GAM_MANAGER_HOST = os.getenv('GAM_MANAGER_HOST', 'localhost')
GAM_MANAGER_PORT = os.getenv('GAM_MANAGER_PORT', '5000')
GAM_MANAGER_URL = f"http://{GAM_MANAGER_HOST}:{GAM_MANAGER_PORT}/scan"

TEMP_PATH = os.getenv('TEMP_PATH', '/tmp')

# Set up basic logging
logging.basicConfig(level=logging.DEBUG)

# Step 1: Create a multithreaded ICAP server using ThreadingMixIn
class ThreadedICAPServer(socketserver.ThreadingMixIn, ICAPServer):
    pass

class ICAPHandler(BaseICAPRequestHandler):

    def options_OPTIONS(self):
        '''
        Handles OPTIONS requests from ICAP clients.
        This method tells the client what methods and features the server supports.
        '''
        logging.info(f"Received ICAP OPTIONS request from {self.client_address}")
        
        # Set the ICAP response to 200 OK
        self.set_icap_response(200)
        
        # Inform the client about the supported methods
        self.set_icap_header(b'Methods', b'REQMOD')
        
        # Set additional ICAP headers (max file size, supported encodings, etc.)
        self.set_icap_header(b'Service', b'GAM Hyper-Scaler ICAP Service')
        self.set_icap_header(b'ISTag', b'GAM2019')  # Optional tag for versioning
        self.set_icap_header(b'Max-Connections', b'100')
        
        # Add Allow 204 support
        self.set_icap_header(b'Allow', b'204')

        # End the ICAP response
        self.send_headers()

    def echo_OPTIONS(self):
        '''
        Handles OPTIONS requests for echo functionality.
        This method should tell the client what capabilities are supported for echo requests.
        '''
        logging.info(f"Received ICAP ECHO OPTIONS request from {self.client_address}")
        
        # Set the ICAP response to 200 OK
        self.set_icap_response(200)
        
        # Inform the client about supported methods
        self.set_icap_header(b'Methods', b'REQMOD, RESPMOD')
        
        # Additional headers for echo service
        self.set_icap_header(b'Service', b'Echo ICAP Service')
        self.set_icap_header(b'ISTag', b'Echo2024')
        self.set_icap_header(b'Max-Connections', b'100')

        # End the ICAP response
        self.send_headers()

    def reqmod_OPTIONS(self):
        '''
        Handles OPTIONS requests for REQMOD functionality.
        This method informs the client about supported features for REQMOD.
        '''
        logging.info(f"Received ICAP REQMOD OPTIONS request from {self.client_address}")

        # Set the ICAP response to 200 OK
        self.set_icap_response(200)
        
        # Inform the client about the supported methods
        self.set_icap_header(b'Methods', b'REQMOD')

        # Additional ICAP headers
        self.set_icap_header(b'Service', b'GAM Hyper-Scaler ICAP Service')
        self.set_icap_header(b'ISTag', b'GAM2019')
        self.set_icap_header(b'Max-Connections', b'100')
        self.set_icap_header(b'Preview', b'2048')
        
        # Add Allow 204 support
        self.set_icap_header(b'Allow', b'204')

        # End the ICAP response
        self.send_headers()

    def stream_to_backend(self, file_name):
        '''
        Reads file chunks from the ICAP request and streams them to the backend scanner.
        
        Args:
            file_name: The name of the file being streamed.
        
        Returns:
            A JSON result from the GAM backend.
        '''
        try:
            logging.info(f"Streaming {file_name} to backend")

            def chunk_generator():
                if not self.has_body:
                    logging.debug("No body in request.")
                    return
                logging.debug("Reading file in chunks.")
                boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
                yield f'--{boundary}\r\n'.encode()
                yield f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'.encode()
                file_mime_type = mimetypes.guess_type(file_name)[0] or 'application/octet-stream'
                yield f'Content-Type: {file_mime_type}\r\n\r\n'.encode()
                
                while True:
                    chunk = self.read_chunk()
                    if chunk == b'':
                        logging.debug("End of chunks.")
                        break
                    yield chunk

                yield f'\r\n--{boundary}--\r\n'.encode()

            # Set the headers manually
            headers = {
                'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'
            }

            # Stream the file to the backend
            response = requests.post(GAM_MANAGER_URL, data=chunk_generator(), headers=headers, stream=True)
            response.raise_for_status()  # Raise an exception for any HTTP errors

            # Log and parse the response
            scan_result = response.json()
            logging.info(f"Received scan result: {scan_result}")

            return scan_result

        except requests.RequestException as e:
            logging.error(f"Error scanning file {file_name}: {str(e)}")
            return False, None

    def echo_REQMOD(self):
        '''
        A simple echo service that returns the request back to the client.
        '''
        logging.info("Echo service activated for REQMOD.")
        self.set_icap_response(200)
        self.send_headers(False)

        while True:
            chunk = self.read_chunk()
            if chunk == b'':
                break
            self.write_chunk(chunk)

        self.write_chunk(b'')

    def reqmod_REQMOD(self):
        '''
        Processes request modifications (REQMOD).
        '''
        logging.info(f"Received REQMOD from {self.client_address}")
        
        # Default file name in case parsing fails
        file_name = "uploaded_file"
        
        # Extract the encapsulated GET request from the ICAP headers
        encapsulated_headers = self.enc_req  # Assuming this stores the encapsulated request as a list of byte strings

        # Log the encapsulated headers for debugging purposes
        logging.debug(f"Encapsulated headers: {encapsulated_headers}")
        
        # Decode the encapsulated headers from byte strings to regular strings
        try:
            decoded_headers = [header.decode('utf-8') for header in encapsulated_headers]
            logging.debug(f"Decoded encapsulated headers: {decoded_headers}")
            
            # Check if the decoded headers have at least 3 elements (GET, URL, HTTP version)
            if len(decoded_headers) >= 3 and decoded_headers[0] == 'GET':
                url = decoded_headers[1]  # Extract the URL part (second element)
                if url.startswith("file://"):
                    # Extract the file name from the URL, stripping out any preceding path
                    file_name = os.path.basename(url[len("file://"):])
            else:
                logging.warning(f"Unexpected encapsulated headers format: {decoded_headers}")
        
        except Exception as e:
            logging.error(f"Error parsing encapsulated headers: {e}")
        
        logging.info(f"Processing file: {file_name}")
        
        # Stream file chunks from ICAP to the backend scanner
        scan_result = self.stream_to_backend(file_name)
        logging.debug(f"scan_result: {scan_result}")
        infected_files = scan_result.get('infected_files', '')
        logging.debug(f"Infected files: {infected_files}")
        
        if len(infected_files) > 0:
            # Infected files were found
            # Respond with ICAP 403 and encapsulate the JSON response in the body
            self.set_icap_response(403)  # Forbidden if the file is infected
            self.set_enc_status(b'HTTP/1.1 403 Forbidden')  # Use bytes for status
            
            # Send headers before sending the body
            self.send_headers(has_body=True)

            # Convert the API response to JSON string
            json_response = json.dumps(scan_result)
            logging.info(f"Infected files found for {file_name}")
            logging.debug(f"Encapsulating GAM-Manager response: {json_response}")
            
            # Encapsulate the JSON response using write_chunk
            self.write_chunk(json_response.encode('utf-8'))
            self.write_chunk(b'')  # Empty chunk to signal the end of the body

        else:
            # No infected files were found
            logging.info(f"No infected files found for {file_name}")
            logging.info("File is clean. Returning ICAP 204 (No Adaptation Required).")
            self.no_adaptation_required()

def run_server():
    server_address = ('', 1344)
    icap_server = ThreadedICAPServer(server_address, ICAPHandler)
    icap_server.serve_forever()

if __name__ == "__main__":
    run_server()
