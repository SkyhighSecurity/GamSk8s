# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV EXTRACT_PATH=/tmp
ENV GAM_MALWARE_THRESHOLD=60

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Use Gunicorn to run the Flask app with multiple workers
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
