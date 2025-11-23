FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl unzip git build-essential libssl-dev libffi-dev python3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app/Backend

COPY src/Backend/requirements.txt .

RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

ENV COSIGN_VERSION=2.5.3
RUN curl -L -o /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
    && chmod +x /usr/local/bin/cosign

ENV GRYPE_VERSION=0.68.0
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/v${GRYPE_VERSION}/install.sh | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

COPY src/Backend/ .

EXPOSE 8080

CMD ["gunicorn", "-w", "2", "--threads", "4", "-b", "0.0.0.0:8080", "--preload", "app:app"]
