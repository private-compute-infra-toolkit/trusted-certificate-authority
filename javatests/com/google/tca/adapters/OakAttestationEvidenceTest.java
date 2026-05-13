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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.oak.Variant;
import com.google.oak.attestation.v1.ContainerEndorsement;
import com.google.oak.attestation.v1.Endorsement;
import com.google.oak.attestation.v1.Endorsements;
import com.google.oak.attestation.v1.Evidence;
import com.google.oak.attestation.v1.SignedEndorsement;
import com.google.protobuf.ByteString;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class OakAttestationEvidenceTest {

  @Test
  public void getRawBinaryEndorsement_successful() {
    ByteString endorsementPayload = ByteString.copyFromUtf8("test-endorsement");
    Endorsements endorsements =
        Endorsements.newBuilder()
            .addEvents(
                Variant.newBuilder()
                    .setId(OakAttestationEvidence.CONTAINER_ENDORSEMENT_ID)
                    .setValue(
                        ContainerEndorsement.newBuilder()
                            .setBinary(
                                SignedEndorsement.newBuilder()
                                    .setEndorsement(
                                        Endorsement.newBuilder().setSerialized(endorsementPayload)))
                            .build()
                            .toByteString()))
            .build();
    OakAttestationEvidence evidence =
        OakAttestationEvidence.create(
            Evidence.getDefaultInstance(), endorsements, ByteString.EMPTY);

    assertThat(evidence.getRawBinaryEndorsement()).isEqualTo(endorsementPayload);
  }

  @Test
  public void getRawBinaryEndorsement_missingEndorsement_throws() {
    Endorsements endorsements = Endorsements.newBuilder().build();
    OakAttestationEvidence evidence =
        OakAttestationEvidence.create(
            Evidence.getDefaultInstance(), endorsements, ByteString.EMPTY);

    RuntimeException e =
        assertThrows(RuntimeException.class, () -> evidence.getRawBinaryEndorsement());
    assertThat(e).hasMessageThat().contains("exactly 1 container endorsement, got 0");
  }

  @Test
  public void getRawBinaryEndorsement_multipleEndorsements_throws() {
    Variant event =
        Variant.newBuilder().setId(OakAttestationEvidence.CONTAINER_ENDORSEMENT_ID).build();
    Endorsements endorsements = Endorsements.newBuilder().addEvents(event).addEvents(event).build();
    OakAttestationEvidence evidence =
        OakAttestationEvidence.create(
            Evidence.getDefaultInstance(), endorsements, ByteString.EMPTY);

    RuntimeException e =
        assertThrows(RuntimeException.class, () -> evidence.getRawBinaryEndorsement());
    assertThat(e).hasMessageThat().contains("exactly 1 container endorsement, got 2");
  }
}
