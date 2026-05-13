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

import com.google.auto.value.AutoValue;
import com.google.protobuf.ByteString;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.policy.ReferenceValuesType;

/** Domain entity for AWS attestation evidence. */
@AutoValue
public abstract class AwsAttestationEvidence implements AttestationEvidence {
  public static AwsAttestationEvidence create(ByteString attestationToken) {
    return new AutoValue_AwsAttestationEvidence(attestationToken);
  }

  public abstract ByteString getAttestationToken();

  public ByteString getRawBinaryEndorsement() {
    throw new UnsupportedOperationException(
        "In-toto endorsements properties extraction not supported for AWS yet");
  }

  public ReferenceValuesType getReferenceValuesType() {
    return ReferenceValuesType.AWS;
  }
}
