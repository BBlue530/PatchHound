FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    python3 python3-pip pipx \
    curl wget jq tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /cli_image

ENV SYFT_VERSION=1.38.0
ENV TRIVY_VERSION=0.56.2
ENV SEMGREP_VERSION=1.95.0

ENV PATH="/cli_image/PatchHound_CLI:$PATH"
ENV BASE_DIR_BIN="/usr/local/bin"

ENV PH_CONFIG_DIR="/cli_image/config"
RUN mkdir -p $PH_CONFIG_DIR

VOLUME ["/cli_image/config"]

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b "$BASE_DIR_BIN" "v$SYFT_VERSION"

RUN curl -fL -o trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
      https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz && \
    tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz && \
    mv trivy "$BASE_DIR_BIN/trivy" && \
    rm trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz

RUN PIPX_BIN_DIR=/usr/local/bin pipx install "semgrep==${SEMGREP_VERSION}"

COPY ./PatchHound_CLI /cli_image/PatchHound_CLI

RUN bash /cli_image/PatchHound_CLI/install.sh

COPY . .
