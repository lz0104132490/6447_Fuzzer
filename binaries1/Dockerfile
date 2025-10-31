FROM python:3.9-slim
ENV PYTHONUNBUFFERED=1  FUZZ_TIME_PER_BINARY=60
WORKDIR /
COPY main.py /main.py
COPY fuzzer.py /fuzzer.py
COPY harness.py /harness.py 
COPY csv_mutator.py /csv_mutator.py
COPY json_mutator.py /json_mutator.py
COPY generic_mutator.py /generic_mutator.py
COPY typechecker.py /typechecker.py
COPY strategies.py /strategies.py

ENTRYPOINT ["python3", "-u", "/main.py"]


