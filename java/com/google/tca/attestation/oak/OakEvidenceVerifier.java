/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.attestation.oak;

import com.google.oak.attestation.v1.AttestationResults;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.tca.attestation.oak.OakAttestationVerifier.AttestationVerificationException;

/** Verifies attestation evidence using the Oak native library. */
public class OakEvidenceVerifier {

  static {
    System.loadLibrary("oak_attestation_verifier_jni");
  }

  /**
   * Verifies attestation evidence with a specific timestamp.
   *
   * @param nowUtcMillis The timestamp to use for verification (in milliseconds since epoch).
   * @param evidenceBytes Serialized `com.google.oak.attestation.v1.Evidence` protobuf.
   * @param endorsementsBytes Serialized `com.google.oak.attestation.v1.Endorsements` protobuf.
   * @param referenceValuesBytes Serialized `com.google.oak.attestation.v1.ReferenceValues`
   *     protobuf.
   * @return The deserialized `AttestationResults` protobuf on success.
   * @throws AttestationVerificationException if verification fails.
   */
  public AttestationResults verify(
      long nowUtcMillis,
      byte[] evidenceBytes,
      byte[] endorsementsBytes,
      byte[] referenceValuesBytes)
      throws AttestationVerificationException {
    byte[] resultBytes =
        nativeVerify(nowUtcMillis, evidenceBytes, endorsementsBytes, referenceValuesBytes);
    try {
      AttestationResults attestationResults = AttestationResults.parseFrom(resultBytes);
      if (attestationResults.getStatus() == AttestationResults.Status.STATUS_SUCCESS) {
        return attestationResults;
      } else {
        throw new AttestationVerificationException(attestationResults.getReason());
      }
    } catch (InvalidProtocolBufferException e) {
      throw new AttestationVerificationException(
          "Failed to parse AttestationResults protobuf: " + e.getMessage());
    }
  }

  private native byte[] nativeVerify(
      long nowUtcMillis,
      byte[] evidenceBytes,
      byte[] endorsementsBytes,
      byte[] referenceValuesBytes);
}
