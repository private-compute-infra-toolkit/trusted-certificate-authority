#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys
import argparse
import json
import base64

def extract_cert_from_json(json_input):
    """Extracts the Base64-encoded certificate string from API JSON output."""
    try:
        data = json.loads(json_input)
        # Check if 'signedCertificates' exists and is a list
        # API usually outputs JSON fields in camelCase if the proto name is snake_case?
        # Or it depends on formatting. Protobuf JSON mapping uses lowerCamelCase.
        # signed_certificates -> signedCertificates
        certs = data.get('signedCertificates')
        if not certs:
             # Try snake_case just in case emit-defaults or similar is different
             certs = data.get('signed_certificates')

        if certs and isinstance(certs, list) and len(certs) > 0:
            return certs[0]
        else:
            print("Error: Could not find 'signedCertificates' field in input.", file=sys.stderr)
            return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reads API JSON output from stdin, extracts the Base64 certificate, and outputs raw DER bytes.",
        epilog='Example: curl ... | python issue_certificate_response_to_der.py > certificate.der'
    )
    # No arguments needed as input is from stdin
    args = parser.parse_args()

    try:
        json_content = sys.stdin.read()
    except Exception as e:
        print(f"Error reading from stdin: {e}", file=sys.stderr)
        sys.exit(1)

    b64_cert = extract_cert_from_json(json_content)

    if b64_cert:
        try:
            der_output = base64.b64decode(b64_cert)
            sys.stdout.buffer.write(der_output)
        except Exception as e:
            print(f"Error decoding Base64: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        sys.exit(1)
