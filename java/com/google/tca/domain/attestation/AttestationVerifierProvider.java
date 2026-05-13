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

import java.util.Optional;

/** Provides the appropriate {@link AttestationVerifier} for a given {@link AttestationEvidence}. */
public interface AttestationVerifierProvider {
  /**
   * Returns an {@link AttestationVerifier} for the given attestation evidence.
   *
   * @param evidence the attestation evidence to get a verifier for.
   * @return an {@link Optional} containing the {@link AttestationVerifier} if one is found,
   *     otherwise an empty {@link Optional}.
   */
  Optional<AttestationVerifier> getVerifier(AttestationEvidence evidence);
}
