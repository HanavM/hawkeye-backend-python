# Use a base image with Python 3.12 and system libraries installed
FROM python:3.12-slim

# Install required system dependencies for OpenCV
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    build-essential \
    libopencv-dev \
    ffmpeg \
    libsm6 \
    libxext6

# Set the working directory in the container
WORKDIR /app

# Copy the application code to the container
COPY . /app

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "app3:app"]
