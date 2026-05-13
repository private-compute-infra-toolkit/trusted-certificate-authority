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

package com.google.tca.adapters;

import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.attestation.AttestationVerifierProvider;
import jakarta.inject.Inject;
import java.util.Map;
import java.util.Optional;

/** A provider for {@link AttestationVerifier}s that uses a map to store and retrieve them. */
public class AttestationVerifierProviderImpl implements AttestationVerifierProvider {
  private final Map<Class<? extends AttestationEvidence>, AttestationVerifier> verifiers;

  @Inject
  public AttestationVerifierProviderImpl(
      Map<Class<? extends AttestationEvidence>, AttestationVerifier> verifiers) {
    this.verifiers = verifiers;
  }

  @Override
  public Optional<AttestationVerifier> getVerifier(AttestationEvidence evidence) {
    if (evidence == null) {
      return Optional.empty();
    }
    for (Map.Entry<Class<? extends AttestationEvidence>, AttestationVerifier> entry :
        verifiers.entrySet()) {
      if (entry.getKey().isAssignableFrom(evidence.getClass())) {
        return Optional.of(entry.getValue());
      }
    }
    return Optional.empty();
  }
}
