FROM python:3.10-slim

WORKDIR /

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

COPY forkserver_lib.c /forkserver_lib.c
RUN gcc -shared -fPIC -O2 -o /forkserver_lib.so /forkserver_lib.c -ldl \
 && rm -f /forkserver_lib.c

COPY fuzzer.py /fuzzer.py
COPY utils.py /utils.py
COPY mutators /mutators
COPY forkserver.py /forkserver.py

RUN mkdir -p /fuzzer_output

ENTRYPOINT ["python3", "/fuzzer.py"]
