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

import com.google.tca.v1.AttestationEvidence;

/** Mapper for {@link AttestationEvidence}. */
public final class AttestationEvidenceMapper {

  private AttestationEvidenceMapper() {}

  public static com.google.tca.domain.attestation.AttestationEvidence toDomain(
      AttestationEvidence proto) {
    switch (proto.getEvidenceCase()) {
      case AWS_ATTESTATION_EVIDENCE:
        return AwsAttestationEvidence.create(
            proto.getAwsAttestationEvidence().getAttestationToken());
      case GCP_ATTESTATION_EVIDENCE:
        return GcpAttestationEvidence.create(
            proto.getGcpAttestationEvidence().getAttestationToken());
      case OAK_ATTESTATION_EVIDENCE:
        return OakAttestationEvidence.create(
            proto.getOakAttestationEvidence().getEvidence(),
            proto.getOakAttestationEvidence().getEndorsements(),
            proto.getOakAttestationEvidence().getSignedPublicKey());
      case EVIDENCE_NOT_SET:
      default:
        throw new IllegalArgumentException("Attestation evidence not set or unsupported");
    }
  }
}
