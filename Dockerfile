FROM python:3.10-slim

WORKDIR /

COPY fuzzer.py /fuzzer.py

RUN mkdir /fuzzer_output 

ENTRYPOINT ["python3", "/fuzzer.py"]
