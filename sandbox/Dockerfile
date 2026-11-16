FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils binutils-multiarch file xxd grep coreutils bash \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir \
    'pefile==2024.8.26' 'pyelftools>=0.32,<1' 'capstone>=5.0.3,<6' \
    'unicorn>=2.1,<3' 'cryptography>=44' 'pycryptodome>=3.21' 'pydantic>=2.9,<3'

COPY malanalyzer/__init__.py malanalyzer/models.py malanalyzer/static_analysis.py malanalyzer/binary_tools.py /opt/python/malanalyzer/
COPY sandbox/runner.py /opt/malanalyzer/runner.py
ENV PYTHONPATH=/opt/python PYTHONDONTWRITEBYTECODE=1 HOME=/workspace
WORKDIR /workspace
RUN mkdir -p /input
USER 65532:65532
CMD ["sleep", "infinity"]
