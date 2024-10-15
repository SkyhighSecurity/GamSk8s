# GAM Manager Service

This service provides an interface to manage the unpacking of files and distribute the load to GAM workers for analysis. It is intended to be deployed behind a service listener such as HTTP or ICAP which stream files to this service.

## Features

- Accepts file processing requests from listener services such as HTTP or ICAP
- Unpacks archive files (zip, 7z, tar, tgz, iso, etc.) and sends them for analysis.
- Integrates with a downstream GAM worker API for file analysis.
- Supports concurrent request processing for efficient workload distribution.

## Requirements

The service depends on the following Python libraries (specified in `requirements.txt`):

- `Flask==2.1.0`
- `requests==2.28.1`
- `requests-toolbelt==0.9.1`
- `gunicorn==20.1.0`
- `Werkzeug==2.1.2`
- `pycdlib==1.10.0`
- `python-magic==0.4.27`

Install the required dependencies using:

```sh
pip install -r requirements.txt
```

## Usage

The GAM Manager service is implemented in Python. It can be built into a Docker container and run in a containerized environment such as Kubernetes. The service can handle multiple requests concurrently to ensure optimal performance.

## Environment Variables

To configure the service, the following environment variables should be set:

- **GAM\_WORKER\_API\_HOST**: Hostname of the GAM worker API responsible for file analysis.
- **GAM\_WORKER\_API\_PORT**: TCP port that the GAM worker API is running on.
- **GAM\_USER**: Username for authentication with the GAM worker API.
- **GAM\_PASSWORD**: Password for authentication with the GAM worker API.
- **GAM\_MALWARE\_THRESHOLD**: Threshold value for determining if a file is considered malware.
- **EXTRACT\_PATH**: Directory path where extracted files will be temporarily stored.
- **GAM\_WORKERS**: Number of GAM workers to be used for file analysis. This is the number of simultaneous API calls made to the GAM workers pool or service.

### Running the Service in Docker

1. **Build Docker Image**

   Use the `Dockerfile` provided to build the image:

   ```sh
   docker build -t gam-manager-service .
   ```

2. **Run the Docker Container**

   ```sh
   docker run -p 5000:5000 --env-file .env gam-manager-service
   ```

   Ensure port `5000` is exposed, as this is the default port for the Flask service.

You can set these environment variables in an `.env` file for convenience.

## Contact

If you have any questions or run into issues, please reach out to [nate.brady@skyhighsecurity.com](mailto\:nate.brady@skyhighsecurity.com).
