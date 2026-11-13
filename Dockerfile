# Deus Witness server image. Build context = the root of this repository (docker-compose.yml does it).
# The same Dockerfile as the hosted service: base image pinned by digest, hash-locked dependencies, fixed mtimes.
ARG BASE_IMAGE=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
FROM ${BASE_IMAGE}
ARG SOURCE_DATE_EPOCH=1760832000
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_COMPILE=1
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin witness
WORKDIR /app
# hash-locked deps only (cloud/deploy/requirements.lock = pip-compile --generate-hashes of cloud/deploy/requirements.txt); --no-deps: the lock is the full closure
COPY cloud/deploy/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --no-compile --no-deps --require-hashes -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock
COPY svidetel_v4/ /app/svidetel_v4/
COPY anchor/ /app/anchor/
COPY cloud/server/ /app/cloud/server/
COPY cloud/web/ /app/cloud/web/
COPY cloud/contract/wa_profile.py /app/cloud/contract/wa_profile.py
# 0.2: quorum/batch profile (contract 00), DLP library (03), RFC 3161 client (06) -- the server does not start without the first two
COPY cloud/contract/v02/wq_profile.py /app/cloud/contract/v02/wq_profile.py
COPY cloud/lib/dlp/dw_dlp/ /app/cloud/lib/dlp/dw_dlp/
COPY cloud/lib/tsa/tsa.py cloud/lib/tsa/providers.json /app/cloud/lib/tsa/
COPY cloud/lib/tsa/ca/ /app/cloud/lib/tsa/ca/
# pinned Intel SGX Root CA (only used with DW_TEE=on); sha256(DER)=44a0196b...74d3
COPY cloud/tee/Intel_SGX_RootCA.pem /app/cloud/tee/Intel_SGX_RootCA.pem
# node 2 modules the server checks node 2's objects with (only used with DW_NODE2=on; the pack carries copies)
COPY cloud/node2/node2/__init__.py cloud/node2/node2/cosign.py cloud/node2/node2/attest.py cloud/node2/node2/amd.py /app/cloud/node2/node2/
# explicit owners/modes and no bytecode; normalise mtimes so layer content does not depend on the build time
RUN mkdir -p /data && chown witness:witness /data && chmod 0750 /data \
    && chown -R root:root /app && chmod -R u=rwX,go=rX /app \
    && find /app -name '__pycache__' -type d -prune -exec rm -rf {} + \
    && find /app /data -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
USER witness
WORKDIR /app/cloud/server
EXPOSE 8787
CMD ["python", "-m", "app.main", "--host", "0.0.0.0", "--port", "8787"]
