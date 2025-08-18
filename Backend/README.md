# Backend PatchHound

---

## Features

- Ingests and stores SBOMs and vulnerability reports
- Attests SBOMs and signs the attestation
- Alerts using webhooks
- Logs all events that happen in the backend
- Auto updates vulnerability database and rescan for new vulnerabilities
- Handle multiple request at the same time
- Generates json and pdf summary report for each workflow
- Handles exclusions of vulnerabilities in the workflow and carry across versions
- Handles signing and verification of container images

---

## Usage

### Starting the Backend  
Getting started with PatchHounds backend is straightforward: 

```bash
bash Start.sh
```

This single command will:
- Install all necessary scanning tools and dependencies automatically.
- Initialize the database to store token keys and related data if it doesnt already exist.
- Start the daily vulnerability scan scheduler to keep all resources continuously monitored.

Once running the backend will be managing updates, scans and alerts.

---

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

---