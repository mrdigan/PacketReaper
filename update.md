# PacketReaper v1.2.0 - IPv6 & Safe-Mode Extraction

This release marks a major milestone for PacketReaper, introducing native IPv6 support across the entire analysis pipeline and a new "Safe-Mode" extraction engine that prioritizes security and performance.

## New Features

### 🌐 Comprehensive IPv6 Support
PacketReaper is no longer blind to IPv6 traffic. The core analysis engine has been refactored to treat IPv4 and IPv6 as first-class citizens.
*   **Pipeline Parity**: Hosts, Sessions, Stream Assembly, DNS, HTTP, Credentials, and Anomalies now support IPv6 natively.
*   **ICMPv6 Detection**: Enhanced anomaly detection for ICMPv6 tunneling and malformed traffic.
*   **Unified Endpoints**: A new centralized extraction utility ensures consistent IP/Port/Protocol metadata regardless of the IP version.
*   **Hardened Assembly**: Stream IDs and temporary file naming have been hardened to handle IPv6 colon-delimited addresses, ensuring "Follow Stream" works flawlessly on Windows.

### 🛡️ Safe-Mode Image Extraction
We've overhauled how images are handled during extraction to reduce disk footprint and improve security.
*   **Memory-Only Previews**: Images are now captured directly from the network stream into memory. The UI generates previews from these byte arrays, completely eliminating the need to write temporary image files to disk for thumbnail rendering.
*   **Risk Tracking & Transparency**: Every extracted file now explicitly tracks its state. A new **Risk** column in the Files tab alerts users if an artifact is "Memory Only (Untrusted)" or has been "Written to Disk".
*   **Memory Optimization**: To preserve system resources, full file bytes are only retained for image types requiring previews. Metadata, MD5, and SHA256 hashes are still calculated for all files.

### 📍 Updated GeoIP & ASN Attribution
*   Bundled with the latest **MaxMind GeoLite2 City, Country, and ASN** databases (April 2026).
*   Improved accuracy for geographic mapping and network ownership attribution.

## Improvements & Bug Fixes

### Backend Refinement
*   **ASN.1 Kerberos Parser**: Replaced heuristic string-scanning with a robust ASN.1 parser for Kerberos (AS-REQ) credentials, including TCP 4-byte prefix normalization.
*   **Strict Port Matching**: Enforced numeric port checks for Telnet, FTP, POP3, IMAP, and SMTP to eliminate false positives on alternative or ephemeral ports.
*   **Nil-Safety**: Added defensive guards around IP parsing and conversion to prevent application panics on malformed packets.
*   **Stream Cleanup**: Added automatic cleanup of temporary stream directories on application shutdown and startup.

### UI & UX Enhancements
*   **Intelligent Stream Linking**: The `findMatchingSession` helper now uses bidirectional specificity scoring to ensure items like Files or Credentials correctly link back to their parent network session, even with partial metadata.
*   **Refined Stream Viewer**: Outbound and inbound traffic panes are now balanced in a 50/50 grid for better readability.
*   **Session Reliability**: Fixed a bug where session packet counts were doubled; counts are now accurate (1:1 per packet).
