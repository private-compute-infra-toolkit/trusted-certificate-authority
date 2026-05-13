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

import com.google.protobuf.ByteString;
import com.google.tca.domain.CertificateIssuanceRequest;
import com.google.tca.v1.AttestationEvidence;
import com.google.tca.v1.GcpAttestationEvidence;
import com.google.tca.v1.IssueCertificateRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CertificateIssuanceRequestMapperTest {

  @Test
  public void toDomain_mapsCorrectly() {
    String attestationToken = "test-token";
    ByteString csr = ByteString.copyFromUtf8("test-csr");

    GcpAttestationEvidence gcpEvidence =
        GcpAttestationEvidence.newBuilder()
            .setAttestationToken(ByteString.copyFromUtf8(attestationToken))
            .build();

    AttestationEvidence evidence =
        AttestationEvidence.newBuilder().setGcpAttestationEvidence(gcpEvidence).build();

    IssueCertificateRequest protoRequest =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(evidence)
            .setCertificateSigningRequest(csr)
            .build();

    CertificateIssuanceRequest domainRequest =
        CertificateIssuanceRequestMapper.toDomain(protoRequest);

    com.google.tca.domain.attestation.AttestationEvidence expectedEvidence =
        com.google.tca.adapters.GcpAttestationEvidence.create(
            ByteString.copyFromUtf8(attestationToken));

    assertEquals(expectedEvidence, domainRequest.getAttestationEvidence());
    assertEquals(csr, domainRequest.getCertificateSigningRequest());
  }
}
