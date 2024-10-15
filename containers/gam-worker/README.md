
This project exposes Skyhigh Gateway AntiMalware (GAM) services through a REST API.  These services include file reputation, signature analysis, and emulation.

# Prerequisites

## In order to use the container you must also have the following:
 - License files (prodid.txt and gam-product.conf)
 - Latest engine and definition update files (from the Skyhigh support site)
 
## Construct the updates folder on persistent storage
 - Create a directory named 'updates' with subdirectories named '1' (so that you have updates/1)
 - In updates/1 place your license files (prodid.txt and gam-product.conf), engine, and definition update files

## Keeping the engine up to date
 - As new engine and definition updates are released, these can be placed in numbered subdirectories (/2, /3, etc.)
 - The server will periodically scan this folder and update using the highest numbered folder found

## Mount the persistent storage volume to the container
 - In docker, use -v /path/to/updates/folder:/updates
 - The goal is to have the numbered folders in the container as:
   - /updates/1
   - /updates/2
   - etc.

## Mount your license file (product.conf) at the following location:
  /gam/gam-product.conf

# Arguments
## Environment variables (-e)

| Parameter      | Value           | Description     |
| -------------- | --------------- | --------------- |
| air-gapped     | true or false   | Optional (default = false) - Tells the GAM server whether or not it should / is able to reach out to Skyhigh Cloud for updated threat intelligence (GTI)  |
| APIUSERNAME    | string          | Optional (default = apiuser) - The HTTP Auth username for the REST API
| APIUSERPASSWORD| string          | Optional (default = apiuser) - The HTTP Auth password for the REST API

# Usage examples

## Docker CLI

```
docker run -d \
  --name=gamserver \
  -e AIRGAPPED=true \
  -e APIUSERNAME=apiUser \
  -e APIUSERPASSWORD=apiPassword \
  -p 8080:8080 \
  -v /path/to/updates/folder:/updates \
  --restart unless-stopped \
  registry1.dso.mil/skyhighsecurity/gam/gamapi/gamapi
```

# Scanning files

The REST server requires three basic components:

  1. A caller (cUNIQUE_CALLER_ID) and file ID (sUNIQUE_FILE_ID) provided in the endpoint.  These values are arbitrary and do not affect the operation of the scanner, but can be useful in debugging to trace the results of a scan back to the call that triggered it.
    - Endpoint format: http://HOST:PORT/GAMScanServer/v1/scans/cUNIQUE_CALLER_ID/sUNIQUE_FILE_ID
  2. A BASE64-encoded authorization header which incudes the username and password set by the APIUSER and APIPASSWORD environment variables.
  3. The data to scan.  This should be encapsulated in JSON with two name/value pairs:
    - "Body" - Set to the BASE64 encoded file or content intended to be scanned
    - "SourceURL" - Usually set to the BASE64 encoded URL for the file. This is used to augment the scan with reputation information from the source.
      - For scanning email attachments, construct the URL as follows: smtp://sender-name@sender-domain/attachment-filename
      - For scanning other file sources, we recommend the following scheme: aux://source-system-or-ip/filename

## Sample POST cURL

```

curl --location --request POST 'http://HOST:PORT/GAMScanServer/v1/scans/cUNIQUE_CALLER_ID/sUNIQUE_FILE_ID' \
--header 'Authorization: Basic BASE64_ENCODED_AUTH' \
--header 'Content-Type: application/json' \
--data-raw '{
    "Body": "BASE64_ENCODED_BODY",
    "SourceURL": "BASE64_ENCODED_SOURCE_URL"
}'

```

# Additional documentation

[GAM Embedder's Guide](https://s3.amazonaws.com/gamapi.skyhighlabs.net/GAM+Embedders+Guide.pdf)
