# Use the official Python image from Docker Hub
FROM python:3.9-slim
LABEL org.opencontainers.image.source https://github.com/skyhighsecurity/gamsk8s

# Install system dependencies for file type detection and archive extraction
RUN apt-get update && apt-get install -y \
    libmagic1 \
    p7zip-full \
    && rm -rf /var/lib/apt/lists/*
                        
# Set the working directory in the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Expose the ICAP port
EXPOSE 1344

# Run the ICAP service
CMD ["python", "icap_listener.py"]
