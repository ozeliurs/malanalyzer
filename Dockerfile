# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS opencode
ARG OPENCODE_VERSION=1.19.5
RUN npm install --global "opencode-ai@${OPENCODE_VERSION}" && opencode --version

FROM docker:28.5.2-cli AS docker-cli

FROM python:3.12-slim-bookworm AS wheels
WORKDIR /build
COPY pyproject.toml ./
COPY malanalyzer ./malanalyzer
RUN --mount=type=cache,target=/root/.cache/pip pip wheel --wheel-dir /wheels .

FROM python:3.12-slim-bookworm AS runtime
ARG TARGETARCH
ARG KUBECTL_VERSION=v1.34.1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
    && curl -fsSLo /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256" \
    && printf '%s  /usr/local/bin/kubectl\n' "$(cat /tmp/kubectl.sha256)" | sha256sum --check \
    && chmod +x /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/* /tmp/kubectl.sha256
COPY --from=opencode /usr/local/bin/node /usr/local/bin/node
COPY --from=opencode /usr/local/lib/node_modules/opencode-ai /usr/local/lib/node_modules/opencode-ai
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=wheels /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels malanalyzer \
    && rm -rf /wheels \
    && ln -s /usr/local/lib/node_modules/opencode-ai/bin/opencode.exe /usr/local/bin/opencode \
    && opencode --version && kubectl version --client \
    && useradd --uid 10001 --create-home --home-dir /home/malanalyzer malanalyzer \
    && mkdir -p /data /app && chown 10001:10001 /data /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data EMBEDDED_WORKER=false HOME=/home/malanalyzer
WORKDIR /app
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["uvicorn", "malanalyzer.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
