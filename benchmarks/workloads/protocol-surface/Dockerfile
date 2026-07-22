FROM docker.io/library/python@sha256:cab2dbf575e971934a81e4622f5aba17aa7929719bd7e31033a3a83b97fd0464

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY protocol_surface.py /usr/local/bin/protocol-surface
RUN chmod 0555 /usr/local/bin/protocol-surface

USER 65532:65532
ENTRYPOINT ["python", "-u", "/usr/local/bin/protocol-surface"]
