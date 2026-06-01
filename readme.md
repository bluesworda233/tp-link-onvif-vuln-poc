# CVE Application Report
## TP-Link IPC Series Network Camera ONVIF Service Hardcoded Credentials Vulnerability

---

## Executive Summary

**Vulnerability Title:** Hardcoded Credentials in TP-Link IPC Series Network Cameras ONVIF Service

**Severity:** CVSS v3.1: 9.8 (Critical)

**Vendor:** TP-Link Corporation

**Affected Products:** TP-Link IPC Series Network Cameras

**Confirmed Models:** TL-IPC48AW (Firmware ID: TL-IPC301-4)

**Attack Vector:** Network (ONVIF over HTTP)

**Authentication Required:** No

**User Interaction Required:** No

---

## I. Vulnerability Information

### I.1 Basic Details

| Field | Content |
|-------|---------|
| **Vulnerability Name** | TP-Link IPC Series Network Cameras ONVIF Service Hardcoded Credentials Vulnerability |
| **Vulnerability Type** | Hardcoded Credentials (CWE-798) |
| **Vendor** | TP-Link Corporation |
| **Affected Products** | TP-Link IPC Series Network Cameras |
| **Confirmed Models** | TL-IPC48AW (Firmware identifier: TL-IPC301-4) |
| **Confirmed Firmware Version** | Build 250119 (January 19, 2025) |
| **Severity Level** | Critical |
| **CVSS v3.1 Score** | 9.8 |
| **Attack Vector** | Network |
| **Attack Complexity** | Low |
| **Privileges Required** | None |
| **User Interaction** | None |
| **Impact** | Complete takeover of device ONVIF control |

---

## II. Vulnerability Overview

The TP-Link IPC series network cameras contain a critical vulnerability in their ONVIF protocol implementation. The device firmware utilizes a hardcoded recovery key `TPL075526460603` for authentication in the Imaging Service GetStatus interface.

Without requiring knowledge of the administrator password, an attacker can:

1. Trigger the device to generate temporary authentication credentials
2. Calculate the temporary password using algorithms reverse-engineered from the firmware
3. Authenticate via ONVIF standard authentication using the temporary password
4. Gain complete control over the device

---

## III. Vulnerability Details

### III.1 Root Cause

The firmware main binary `/bin/main` (4.97MB, ARM 32-bit, musl libc, stripped) contains the following hardcoded constants:

| Constant | Value | Virtual Address | Purpose |
|----------|-------|-----------------|---------|
| **Recovery Key** | TPL075526460603 | 0x39F50B | ONVIF timg_get_status endpoint authentication |
| **Brand Key** | tplinksohoteam2 | 0x3D840B | Temporary password SHA1 salt value (default code value) |
| **XOR Encoding Key** | RDpbLfCPsJZ7fiv | 0x38979B | Password obfuscation encoding |
| **RSA Key Pair** | 1024-bit RSA | — | Cryptographic key pair for device authentication |

**Backdoor Entry Point Function (IDA address 0x26F128):**

```c
int sub_26F128(int a1) {
    return sub_26EEC0(a1, "TPL075526460603");
}
```

### III.2 Brand Key Configuration

TP-Link default configuration in `squashfs-root-0/etc/oem.config` specifies the `pwr_mix_key` field in brand_spec/info:

```json
"brand_spec": {
    "info": {
        "manufacturer": "TP-Link",
        "onvif_name": "TP-IPC",
        "pwr_mix_key": "tplinksohoteam2"
    }
}
```

The brand key `tplinksohoteam2` is used as a SHA1 salt value in the temporary password generation process.

### III.3 Temporary Password Generation Algorithm

The firmware uses a proprietary algorithm to generate temporary passwords:

```python
import hashlib

def compute_temp_password(recovery_code, brand_key="tplinksohoteam2"):
    digits = recovery_code[1:]
    sha1_hex = hashlib.sha1((digits + brand_key).encode()).hexdigest()
    raw = ''
    for i in range(4):
        idx = int(digits[i*2:i*2+2]) % 20
        raw += sha1_hex[idx*2:idx*2+2]
    return "".join(str(ord(c)-97) if "a"<=c<="f" else c for c in raw)
```

**Algorithm Steps:**
1. Extract numeric digits from recovery code (removing leading 'A')
2. Compute SHA1(digits + brand_key) to generate 40-character hex string
3. Extract 4 pairs of characters from SHA1 output using modulo-based indexing
4. Convert hexadecimal characters to their numeric equivalents (a-f → 0-5)
5. Return final 8-character temporary password string

---

## IV. Proof of Concept

### IV.1 Testing Environment

- **Attacker Machine:** Any Python 3 host
- **Target:** TP-Link IPC device with exposed ONVIF service
- **Tool:** Included PoC script

### IV.2 Reproduction Steps

Using the hardcoded recovery key and computed temporary password:

```bash
python poc_onvif_tp_link.py <IP:Port>
```

**Exploitation Process:**

1. **Trigger Backdoor:** Send ONVIF GetStatus request authenticated with `TPL075526460603`
2. **Extract Recovery Code:** Device responds with temporary recovery code
3. **Calculate Password:** Compute temporary password using recovery code + brand key
4. **Authenticate:** Use calculated password for ONVIF standard authentication
5. **Gain Access:** Execute privileged operations on the device

### IV.3 Impact

An attacker can:
- Access the ONVIF management interface without authentication
- Retrieve/modify camera configuration
- Access video streams
- Trigger device reboot
- Potentially execute arbitrary commands depending on ONVIF service implementation

---

## V. Vulnerability Scope and Real-World Exposure

### V.1 Affected Device Models

Security research has confirmed the following TP-Link IPC series models are vulnerable:

- TL-IPC45AW-DOUBLE-STREAM
- TL-IPC44GW-BANDS-ZOOM-DUAL
- TL-IPC632-A4GY
- TL-IPC652-A4
- TL-NAIPC5494P-MZ50
- TL-IPC48AW-PLUS
- TL-IPC43AW-COLOR
- TL-IPC544EP-AI4
- TL-IPC48GW-ZOOM-DUAL
- TL-IPC642-A4

### V.2 Firmware Versions Confirmed Vulnerable

Multiple firmware builds are confirmed vulnerable, including:
- Build 250326, Build 210811, Build 240819, Build 231122, Build 240508, Build 250616, Build 220715, Build 231220

Vulnerability likely affects many additional firmware versions across the entire TP-Link IPC product line.

### V.3 Exposure Assessment

**Scope of Vulnerability:**
- Multiple TP-Link IPC series cameras are currently deployed in production surveillance infrastructure
- Vulnerable devices can be identified using standard device discovery techniques
- The hardcoded nature of the vulnerability affects all devices running vulnerable firmware versions
- No user misconfiguration or non-standard deployment required for exploitation

**Discovery Methodology:**
Vulnerable devices can be identified through:
1. Network-wide ONVIF service scanning
2. Public device discovery platforms (FOFA, Shodan, etc.)
3. Direct ONVIF endpoint probing on port 8080 or device-specific ports
4. Standard HTTP service identification techniques

**Responsible Disclosure Commitment:**
In accordance with responsible vulnerability disclosure practices, specific device locations, IP addresses, and direct target information are **not disclosed** in this report. This protects:
- Individual device owners and users
- Organizations operating these devices
- Affected surveillance infrastructure
- Public safety and privacy

Device owners are encouraged to:
1. Identify potentially vulnerable devices using internal network scans
2. Check firmware versions against the TP-Link advisory
3. Update firmware to patched versions immediately
4. Restrict ONVIF service access to trusted networks
5. Implement network-level access controls

---

## VI. Impact Assessment

### VI.1 Affected Scope

- **Confirmed Model:** TL-IPC48AW (TL-IPC301-4)
- **Highly Likely to be Affected:** All TP-Link IPC series products using the same firmware platform
- **Impact:** Complete unauthorized access to device management and video streams
- **RSA Key Usage:** Device authentication relies on shared 1024-bit RSA key pair

### VI.2 CVSS v3.1 Score: 9.8 (Critical)

**Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value | Rationale |
|--------|-------|-----------|
| **Attack Vector (AV)** | Network (N) | Remote network exploitation over ONVIF/HTTP |
| **Attack Complexity (AC)** | Low (L) | No special conditions required |
| **Privileges Required (PR)** | None (N) | No authentication or privileges needed |
| **User Interaction (UI)** | None (N) | No user interaction required |
| **Scope (S)** | Unchanged (U) | Direct impact on the vulnerable camera |
| **Confidentiality (C)** | High (H) | Complete information disclosure (video streams, configuration) |
| **Integrity (I)** | High (H) | Complete modification of device configuration possible |
| **Availability (A)** | High (H) | Device can be rebooted or rendered unavailable |

---

## VII. Remediation Recommendations

1. **Remove Hardcoded Recovery Key:** Remove the hardcoded string `TPL075526460603` from firmware
2. **Generate Unique RSA Key Pairs:** Deploy device-specific RSA key pairs during manufacturing
3. **Dynamic Brand Key Generation:** Derive `pwr_mix_key` from device serial number or unique identifier
4. **Access Control:** Restrict recovery endpoint accessibility only when triggered by physical button or secure out-of-band challenge
5. **Firmware Update:** Release patched firmware version and notify all users for immediate upgrade
6. **Security Audit:** Conduct comprehensive security review of ONVIF implementation and other network-exposed services
7. **Rate Limiting:** Implement rate limiting on authentication attempts to prevent brute-force attacks

---

## VIII. Attachments and References

1. **PoC Verification Tool:** `poc_onvif_tp_link.py`
   - Demonstrates vulnerability exploitation
   - Extracts device information upon successful authentication
   - Confirms device vulnerability status
   - **Intended Use:** Testing only on devices the researcher owns or has explicit authorization to test

---

## IX. Legal and Ethical Considerations

### IX.1 Responsible Disclosure

This vulnerability report follows responsible security disclosure practices:

- **Non-Publication of Specific Targets:** Device-specific information (IP addresses, exact locations, URLs) is not disclosed to prevent unauthorized exploitation
- **Vendor Notification:** TP-Link Corporation has been notified in accordance with industry standard disclosure timelines
- **Public Interest Balance:** Information provided enables legitimate security researchers and device owners to identify and remediate vulnerable systems without exposing innocent victims
- **Ethical Research Standards:** This research adheres to ACM Code of Ethics, IEEE Code of Ethics, and industry vulnerability disclosure guidelines

### IX.2 Legal Compliance

This report is published in compliance with:

- **Computer Fraud and Abuse Act (CFAA):** No specific vulnerable targets are disclosed; report is for educational and defensive purposes only
- **General Data Protection Regulation (GDPR):** No personally identifiable information is included; privacy of device owners is protected
- **Cybersecurity Laws:** Country-specific network security regulations are respected through non-disclosure of specific targets
- **CVE Program Standards:** MITRE CVE program requirements for responsible disclosure are followed

### IX.3 Intended Use

This vulnerability information is intended for:
- ✅ Device owners validating their own equipment security
- ✅ Security researchers conducting authorized penetration testing
- ✅ Organization security teams assessing their infrastructure
- ✅ TP-Link engineers developing and deploying patches
- ✅ Security vendors creating detection and protection mechanisms

This information is **NOT** intended for:
- ❌ Unauthorized access to systems
- ❌ Mass exploitation of vulnerable devices
- ❌ Attacks on surveillance infrastructure
- ❌ Violation of applicable computer crime laws
- ❌ Privacy invasion or data theft

---

## X. Conclusion

This critical vulnerability in TP-Link IPC series network cameras allows unauthenticated remote attackers to gain complete control over affected devices. The hardcoded recovery credentials and predictable temporary password generation algorithm enable trivial exploitation with minimal attack complexity.

The widespread deployment of these devices in both public and private surveillance infrastructure creates significant security risks. Immediate patching and security hardening are essential to protect deployed systems.

This report is published following responsible disclosure principles to enable effective remediation while protecting the privacy and security of system owners.

---

## XI. Timeline and Disclosure

- **Discovery Date:** July 1, 2026
- **Initial Research:** Analysis of firmware Build 250119
- **Vendor Notification:** [Notification timeline in progress]
- **Vulnerability Confirmation:** Multiple firmware versions confirmed vulnerable
- **CVE Application Date:** June 1, 2026
- **Recommended Vendor Response Deadline:** 90 days from official notification
- **Responsible Disclosure:** Following industry standard 90-day disclosure policy

---

## XII. Researcher Information

**Research Organization:** Yangming Cybersecurity Studio  
Wuhan Vocational and Technical University

**Researcher:** Xin Xiang Fu

**Contact:** fuxinxiang0315@gmail.com

**Disclosure Statement:**
This research was conducted with the highest standards of security research ethics and legal compliance. The researcher(s) have not engaged in unauthorized access to any computer systems and have not disclosed information that would enable mass exploitation of vulnerable devices.

---

*This report is submitted for official CVE registration and responsible disclosure purposes.*

*Publication of this report does not constitute encouragement or assistance for unauthorized access to computer systems in violation of applicable law.*
