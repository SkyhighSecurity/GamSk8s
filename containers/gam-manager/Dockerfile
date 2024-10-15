# Use an official Python runtime as a parent image
FROM python:3.9-slim
LABEL org.opencontainers.image.source https://github.com/skyhighsecurity/gamsk8s
# Set environment variables
ENV GAM_MALWARE_THRESHOLD=60

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y \
    libmagic1 \
    file \
    && rm -rf /var/lib/apt/lists/*

# Make port 5000 available to the world outside this container
EXPOSE 5000

CMD ["python", "gam_manager.py"]
# Use Gunicorn to run the Flask app with multiple workers
#CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "gam_manager:app"]
