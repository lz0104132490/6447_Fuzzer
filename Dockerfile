# Start from a default ubuntu image.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
# Install 
RUN apt-get update && \
    apt-get install -y python3 && \
    rm -rf /var/lib/apt/lists/*
# set dictionary
WORKDIR /fuzzer
# Copy/Compile my fuzzer
COPY xml.py .
# Run
CMD ["python3", "./xml.py"]
