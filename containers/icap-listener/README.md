
# ICAP Listener Service

This service provides an ICAP interface that allows clients to send files for processing. The files are streamed to the GAM-Manager service which extract files and distributes load to GAM workers.

## Features

- Accepts ICAP requests from clients to process files.
- Unpacks archive files (zip, 7z, tar, tgz, etc.) and sends them for processing.
- Integrates with a downstream API for further file analysis.
- Supports concurrent request processing using multithreading.

## Requirements

The service depends on the following Python libraries (specified in `requirements.txt`):

- `pyicap`
- `requests==2.31.0`
- `python-magic==0.4.27`
- `py7zr==0.19.0`
- `requests-toolbelt==0.9.1`
- `urllib3==1.26.16`

Install the required dependencies using:

```sh
pip install -r requirements.txt
```

## Usage

This ICAP listener is implemented in Python. It can be built into a Docker container and run in a containerized environment such as Kubernetes. You should scale the deployment of icap listeners or run it in a multithreaded environment for additional performance.

## Environment Variables

To configure the service, the following environment variables should be set:

- **GAM_MANAGER_HOST**: Hostname of the gam-manager service responsible for unpacking files and distributing load to GAM worker
- **GAM_MANAGER_PORT**: TCP port that the gam-manager service is running on.

### Running the Service

1. **Build Docker Image**
   
   Use the `Dockerfile` provided to build the image:
   
   ```sh
   docker build -t icap-listener-service .
   ```

2. **Run the Docker Container**

   ```sh
   docker run -p 1344:1344 --env-file .env icap-listener-service
   ```

   Ensure port `1344` is exposed, as this is the default ICAP port.

### Making Requests

The service listens for ICAP requests on port `1344`. To call the service, you can use an ICAP client to send a file. The supported headers include filename information, such as:

- `X-C-ICAP-Client-Original-File`: Filename metadata for file processing.

For testing, you can use `c-icap-client` to make a request:

```sh
c-icap-client -i <hostname> -p 1344 -req file://0/<filename> -s reqmod -f <file-to-process>
```

You can set these environment variables in an `.env` file for convenience.

## Contact

If you have any questions or run into issues, please reach out to [nate.brady@skyhighsecurity.com](mailto:nate.brady@skyhighsecurity.com).
