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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import com.google.common.collect.ImmutableMap;
import com.google.oak.attestation.v1.Endorsements;
import com.google.oak.attestation.v1.Evidence;
import com.google.protobuf.ByteString;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class AttestationVerifierProviderImplTest {

  private AttestationVerifierProviderImpl provider;

  private AttestationVerifier mockGcpVerifier;
  private AttestationVerifier mockAwsVerifier;
  private AttestationVerifier mockOakVerifier;

  @Before
  public void setUp() {
    mockGcpVerifier = mock(AttestationVerifier.class);
    mockAwsVerifier = mock(AttestationVerifier.class);
    mockOakVerifier = mock(AttestationVerifier.class);

    ImmutableMap<Class<? extends AttestationEvidence>, AttestationVerifier> verifiers =
        ImmutableMap.of(
            OakAttestationEvidence.class, mockOakVerifier,
            AwsAttestationEvidence.class, mockAwsVerifier,
            GcpAttestationEvidence.class, mockGcpVerifier);

    provider = new AttestationVerifierProviderImpl(verifiers);
  }

  @Test
  public void getVerifier_oakEvidence_returnsOakVerifier() {
    OakAttestationEvidence evidence =
        OakAttestationEvidence.create(
            Evidence.getDefaultInstance(), Endorsements.getDefaultInstance(), ByteString.EMPTY);

    Optional<AttestationVerifier> result = provider.getVerifier(evidence);

    assertTrue(result.isPresent());
    assertEquals(mockOakVerifier, result.get());
  }

  @Test
  public void getVerifier_gcpEvidence_returnsGcpVerifier() {
    GcpAttestationEvidence evidence = GcpAttestationEvidence.create(ByteString.EMPTY);

    Optional<AttestationVerifier> result = provider.getVerifier(evidence);

    assertTrue(result.isPresent());
    assertEquals(mockGcpVerifier, result.get());
  }

  @Test
  public void getVerifier_awsEvidence_returnsAwsVerifier() {
    AwsAttestationEvidence evidence = AwsAttestationEvidence.create(ByteString.EMPTY);

    Optional<AttestationVerifier> result = provider.getVerifier(evidence);

    assertTrue(result.isPresent());
    assertEquals(mockAwsVerifier, result.get());
  }
}
