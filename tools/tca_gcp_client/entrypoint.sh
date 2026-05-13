#!/bin/bash
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

set -e

# Step 1: Generate a new private key and a CSR in binary DER format.
openssl req -newkey rsa:2048 -nodes -keyout private_key.pem -outform DER -out csr.der -subj "/CN=test-workload" >/dev/null 2>&1

# Step 2: Get the public key in base64 DER format for the nonce.
PUBLIC_KEY_B64=$(openssl rsa -in private_key.pem -pubout -outform DER | base64 -w 0)

# Step 3: Chunk the public key for the nonce.
NONCES=$(echo -n "$PUBLIC_KEY_B64" | fold -w 88)

# Format nonces as a JSON array of strings.
NONCES_JSON_ARRAY="["
while IFS= read -r line; do
  NONCES_JSON_ARRAY+="\"$line\","
done <<< "$NONCES"
# Remove trailing comma and add closing bracket.
NONCES_JSON_ARRAY="${NONCES_JSON_ARRAY%,}]"

# Step 4: Prepare the JSON payload for the curl command.
JSON_PAYLOAD="{ \"audience\": \"test_app\", \"token_type\": \"OIDC\", \"nonces\": ${NONCES_JSON_ARRAY} }"

# Step 5: Make the curl request to get the attestation token.
ATTESTATION_TOKEN=$(curl -s -X POST --unix-socket /run/container_launcher/teeserver.sock \
  http://localhost/v1/token \
  -H "Content-Type: application/json" \
  -d "${JSON_PAYLOAD}")

# Step 6: Convert the binary DER CSR to a Base64 string
CSR_BASE64=$(base64 -w 0 csr.der)

# Step 7: Base64 encode the attestation token (it's a bytes field in proto)
ATTESTATION_TOKEN_BASE64=$(echo -n "${ATTESTATION_TOKEN}" | base64 -w 0)

# Step 8: Output the Base64 encoded values
echo "Base64 CSR:"
echo "${CSR_BASE64}"
echo ""
echo "Base64 Attestation Token:"
echo "${ATTESTATION_TOKEN_BASE64}"

# Clean up
rm -f csr.der private_key.pem
