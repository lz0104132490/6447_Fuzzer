# Start from a default ubuntu image.
FROM ubuntu:22.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY src/ /build/src/
COPY include/ /build/include/
COPY shared/ /build/shared/
COPY libs/ /build/libs/
COPY Makefile /build/
COPY fuzzer_wrapper.sh /fuzzer_wrapper.sh

# Build the fuzzer
WORKDIR /build
RUN cp libs/json_parser/CJSON.h libs/json_parser/cJSON.h && \
    make clean && make

# Copy compiled binaries to root
RUN cp /build/fuzzer /fuzzer && \
    cp /build/shared.so /shared.so && \
    chmod +x /fuzzer && \
    chmod +x /fuzzer_wrapper.sh

# Clean up build files to reduce image size
RUN rm -rf /build

# Set working directory
WORKDIR /

# Run the wrapper script
CMD ["/bin/bash", "/fuzzer_wrapper.sh"]