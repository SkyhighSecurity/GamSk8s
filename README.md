# GamSk8s (GAM Skates)

GamSk8s is a scalable, high-performance, and extensible anti-malware scanning platform composed of three main components. It is designed to operate efficiently on a Kubernetes cluster but can also be run locally using Docker for testing purposes.

## Architecture

The following ASCII diagram depicts how the components of GamSk8s interact to scan files:

```
+-----------------+
| External Service|
+-----------------+
        |
        |  (1) File is sent via ICAP to Kubernetes Load balancer service
        v
+-------------------+
|  ICAP Listener    |
| (Kubernetes Pod)  |
+-------------------+
        |
        |  (2) Streams file to Gam-Manager via gam-manager-service
        v
+-------------------+
|   Gam-Manager     |
| (Kubernetes Pod)  |
+-------------------+
        |
        |  (3) Unpacks archives and distributes files
        |      to Gam-Workers for scanning via gam-worker-service
        v
   +-------------------+      +-------------------+
   |   Gam-Worker 1    |      |   Gam-Worker 2    |
   | (Kubernetes Pod)  |      | (Kubernetes Pod)  |
   +-------------------+      +-------------------+
          ...
```

1. **External Service**: An external service (e.g., a web proxy) sends a file to the ICAP-Listener for scanning.
2. **ICAP Listener**: Receives the file via ICAP protocol and streams it to the Gam-Manager.
3. **Gam-Manager**: Handles the unpacking of archives and distributes individual files to multiple Gam-Worker nodes for scanning.
4. **Gam-Workers**: Multiple workers run the Skyhigh Gateway AntiMalware (GAM) engine to scan files concurrently.

## Components

### 1. **ICAP-Listener**

- Provides an ICAP front-end for interacting with the anti-malware service.
- Accepts file scanning requests via the ICAP protocol.
- Future plans include adding listeners for REST API and cloud storage.

### 2. **Gam-Manager**

- Acts as the middleware between listeners and the scanning engine.
- Handles incoming requests, unpacks archives, and distributes individual files to Gam-Workers for scanning.
- Manages communication and load balancing between listeners and workers.
- Requires a product license from Skyhigh Security and agreement with the terms in containers/gam-worker/README.md

### 3. **Gam-Worker**

- Consists of the proprietary **Skyhigh Gateway AntiMalware (GAM)** engine.
- Hosts a lightweight REST API that scans individual files.
- Requires a valid license to run.

## Features

- **Scalability**: Built to scale across multiple nodes in a Kubernetes cluster.
- **Extensibility**: Easily integrate new listeners (e.g., REST API or cloud storage).
- **High-Performance**: Optimized for high throughput and low-latency malware scanning.

## Prerequisites

- Skyhigh Gateway AntiMalware (GAM) software and license (for Gam-Worker)

## Installation

### Kubernetes Deployment

To deploy GamSk8s on Kubernetes, follow these steps:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/SkyhighSecurity/GamSk8s.git
   cd GamSk8s
   ```

2. **Review and Modify Manifest Files**:
   - The Kubernetes manifest files (`.yaml` files) for deploying ICAP Listener, Gam-Manager, and Gam-Worker are located in the `kubernetes/` directory.
   - Carefully review the content and comments in each manifest file to ensure they meet your deployment requirements.

3. **Configure Product License**:
   - Edit the `product.secret.template.yaml` file to configure the GAM license information.
   - Deploy the secret to your Kubernetes cluster:
   
   ```bash
   kubectl apply -f kubernetes/product.secret.template.yaml
   ```

4. **Deploy the Manifests**:
   - After configuring the necessary settings, deploy each of the manifest files:
   
   ```bash
   kubectl apply -f kubernetes/icap-listener.deployment.yaml
   kubectl apply -f kubernetes/gam-manager.deployment.yaml
   kubectl apply -f kubernetes/gam-worker.deployment.yaml
   kubectl apply -f kubernetes/icap-listener.service.yaml
   kubectl apply -f kubernetes/gam-manager.service.yaml
   kubectl apply -f kubernetes/gam-worker.service.yaml
   ```

### Docker Compose Deployment

A `docker-compose.yml` file is provided in the repository for local testing and development. You can use it to quickly bring up all components using Docker Compose.

1. **Clone the repository**:

   ```bash
   git clone https://github.com/SkyhighSecurity/GamSk8s.git
   cd GamSk8s
   ```

2. **Run Docker Compose**:

   ```bash
   docker-compose up -d
   ```

3. **Modify as needed**: The provided `docker-compose.yml` file is a basic setup. You may need to modify it to suit your specific requirements, such as adjusting environment variables, volumes, or network configurations.

## Usage

Once deployed, the ICAP-Listener will accept requests and forward them to the Gam-Manager. The Gam-Manager will process the requests, unpack files if necessary, and distribute them to Gam-Workers for malware scanning.

## License

The Gam-Worker component requires a valid license for **Skyhigh Gateway AntiMalware (GAM)**. Contact [Skyhigh Security](https://www.skyhighsecurity.com/) for more details.

## Contributing

If you'd like to contribute to this project, feel free to submit a pull request or open an issue.

## Contact

For more information, please contact Nate Brady at nate.brady@skyhighsecurity.com.

