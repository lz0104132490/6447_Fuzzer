FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-pip \
        gcc \
        g++ \
        make \
        file \
        binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /fuzzer

COPY generate_vulnerable_elf.py .
COPY elf.py .

RUN chmod +x generate_vulnerable_elf.py elf.py

RUN mkdir -p /test_binaries /test_example_inputs && \
    python3 generate_vulnerable_elf.py

CMD ["python3", "./elf.py"]
