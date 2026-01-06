# PacketReaper


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Wails](https://img.shields.io/badge/Wails-v2-red)](https://wails.io)

PacketReaper is a network forensic analysis tool built with Go (Wails) and React. It is designed to process PCAP files and provide detailed insights into network traffic.

## Features

PacketReaper includes a wide range of analysis capabilities:

*   **PCAP Parsing**: High-performance packet capture processing.
*   **Anomaly Detection**: Automatically flags suspicious traffic patterns (e.g., potential malware signatures).
*   **JA3 Fingerprinting**: Extracts TLS client fingerprints for identifying malicious clients.
*   **GeoIP & ASN Lookup**: Resolves IP addresses to physical locations and Autonomous Systems (requires Maxmind DBs).
*   **Decryption**: Supports TLS decryption if provided with the appropriate keys.
*   **Credential Extraction**: Identifies and extracts cleartext credentials from protocols like HTTP, FTP, etc.
*   **VoIP Analysis**: Extracts and analyzes SIP/RTP streams.
*   **DNS Analysis**: Parses and visualizes DNS queries and responses.
*   **Certificate Extraction**: Parsons and extracts X.509 certificates from TLS handshakes.
*   **File Extraction**: Reconstructs files (images, documents, executables) transferred over the network.
*   **Message Extraction**: Reconstructs chat messages (IRC, etc.).
*   **Keyword Search**: Fast search across packet payloads.

## Prerequisites

### Maxmind Databases
This application requires Maxmind GeoLite2 databases for IP geolocation and ASN lookups.
1.  Sign up for a free MaxMind account at [dev.maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2.  Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
3.  Place these `.mmdb` files in the `pkg/geoip/` directory.

> **Note:** These files are ignored by git to avoid licensing conflicts.

### Tools
- [Wails](https://wails.io/) (v2)
- Go (1.23+)
- Node.js (for frontend)

## Development

To run in live development mode:

```bash
wails dev
```

This acts as a hybrid backend/frontend development server.

## Building

To build the application for production:

1.  **Frontend Build**:
    ```bash
    cd frontend
    npm install
    npm run build
    cd ..
    ```

2.  **Application Build**:
    ```bash
    wails build
    ```


The compiled binary will be located in:
`build/bin/PacketReaper.exe`
