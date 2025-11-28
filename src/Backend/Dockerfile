FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl unzip git build-essential libssl-dev libffi-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/

ENV GRYPE_VERSION=0.104.1
ENV COSIGN_VERSION=2.5.3
ENV PATH=/root/.local/bin:$PATH

RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /root/.local/bin && \
    curl -L -o /root/.local/bin/cosign \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" && \
    chmod +x /root/.local/bin/cosign

RUN curl -sSfL "https://raw.githubusercontent.com/anchore/grype/v${GRYPE_VERSION}/install.sh" \
    | sh -s -- -b /root/.local/bin v${GRYPE_VERSION}

COPY . .

EXPOSE 8080

CMD ["python3", "app.py"]
