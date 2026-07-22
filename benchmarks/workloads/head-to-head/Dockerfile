FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/e-navigator-head-to-head

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt

COPY head_to_head.py ./head_to_head.py

USER 65532:65532

ENTRYPOINT ["python", "-u", "/opt/e-navigator-head-to-head/head_to_head.py"]
