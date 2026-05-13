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

package com.google.tca.domain.attestation;

import com.google.tca.domain.policy.ReferenceValues;
import java.security.PublicKey;

/** Interface for attestation verifier plugins. */
public interface AttestationVerifier {
  /**
   * Verifies an attestation token.
   *
   * @param evidence the attestation evidence to verify.
   * @param claimedPublicKey the public key embedded in the CSR.
   * @return true if the token is valid, otherwise false.
   */
  boolean verify(
      AttestationEvidence evidence, PublicKey claimedPublicKey, ReferenceValues referenceValues);
}
