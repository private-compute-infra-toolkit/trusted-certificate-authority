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
import com.google.common.io.BaseEncoding;
import com.google.oak.Variant;
import com.google.oak.attestation.v1.ContainerEndorsement;
import com.google.oak.attestation.v1.Endorsements;
import com.google.oak.attestation.v1.Evidence;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.IncorrectEndorsementFormatException;
import com.google.tca.domain.policy.ReferenceValuesType;
import java.util.List;

/** Domain entity for Oak attestation evidence. */
@AutoValue
public abstract class OakAttestationEvidence implements AttestationEvidence {

  // This value comes from oak::Variant hardcoded mapping
  public static final ByteString CONTAINER_ENDORSEMENT_ID =
      ByteString.copyFrom(
          BaseEncoding.base16().lowerCase().decode("7297a51fa05d49a1afdb64cdee07862d"));

  public static OakAttestationEvidence create(
      Evidence evidence, Endorsements endorsements, ByteString signedPublicKey) {
    return new AutoValue_OakAttestationEvidence(evidence, endorsements, signedPublicKey);
  }

  public abstract Evidence getEvidence();

  public abstract Endorsements getEndorsements();

  public abstract ByteString getSignedPublicKey();

  public ByteString getRawBinaryEndorsement() {
    List<Variant> events = getContainerEndorsement();
    if (events.size() != 1) {
      throw new IncorrectEndorsementFormatException(
          String.format("There should be exactly 1 container endorsement, got %d", events.size()));
    }

    try {
      Variant containerVariant = events.get(0);
      ContainerEndorsement containerEndorsement =
          ContainerEndorsement.parseFrom(containerVariant.getValue());
      return containerEndorsement.getBinary().getEndorsement().getSerialized();
    } catch (InvalidProtocolBufferException e) {
      throw new IncorrectEndorsementFormatException("Failed to parse container endorsement", e);
    }
  }

  private List<Variant> getContainerEndorsement() {
    return getEndorsements().getEventsList().stream()
        .filter(event -> event.getId().equals(CONTAINER_ENDORSEMENT_ID))
        .toList();
  }

  public ReferenceValuesType getReferenceValuesType() {
    return ReferenceValuesType.OAK;
  }
}
