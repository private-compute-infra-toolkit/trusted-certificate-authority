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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.oak.attestation.v1.AttestationResults;
import com.google.tca.attestation.oak.OakAttestationVerifier.AttestationVerificationException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class OakEvidenceVerifierTest {
  private static final String TESTDATA_BASE_PATH =
      "javatests/com/google/tca/attestation/oak/testdata/";
  private static final String MILAN_TESTDATA_PATH = TESTDATA_BASE_PATH + "milan_oc_release_";
  private static final String FAKE_TESTDATA_PATH = TESTDATA_BASE_PATH + "fake_";
  // 2025-07-01T00:00:00Z
  private static final long TIMESTAMP_WITHIN_EVIDENCE_VALIDITY_PERIOD = 1751328000000L;

  private static byte[] readTestFile(String path) throws Exception {
    return Files.readAllBytes(Paths.get(path));
  }

  @Test
  public void testOakVerifier_successful() throws Exception {
    OakEvidenceVerifier verifier = new OakEvidenceVerifier();
    byte[] evidence = readTestFile(MILAN_TESTDATA_PATH + "evidence.binarypb");
    byte[] endorsements = readTestFile(MILAN_TESTDATA_PATH + "endorsements.binarypb");
    byte[] referenceValues = readTestFile(MILAN_TESTDATA_PATH + "reference_values.binarypb");

    AttestationResults results =
        verifier.verify(
            TIMESTAMP_WITHIN_EVIDENCE_VALIDITY_PERIOD, evidence, endorsements, referenceValues);

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void testOakVerifier_referenceValueMismatch() throws Exception {
    OakEvidenceVerifier verifier = new OakEvidenceVerifier();
    byte[] evidence = readTestFile(FAKE_TESTDATA_PATH + "evidence.binarypb");
    byte[] endorsements = readTestFile(FAKE_TESTDATA_PATH + "endorsements.binarypb");
    byte[] referenceValues = readTestFile(FAKE_TESTDATA_PATH + "reference_values.binarypb");

    AttestationVerificationException e =
        assertThrows(
            AttestationVerificationException.class,
            () ->
                verifier.verify(
                    TIMESTAMP_WITHIN_EVIDENCE_VALIDITY_PERIOD,
                    evidence,
                    endorsements,
                    referenceValues));

    assertThat(e.getMessage())
        .matches(
            ".*(matching endorsement not found for reference value|event log was not provided|no"
                + " platform endorsement).*");
  }

  @Test
  public void testOakVerifier_emptyInput() {
    OakEvidenceVerifier verifier = new OakEvidenceVerifier();
    assertThrows(
        AttestationVerificationException.class,
        () -> verifier.verify(System.currentTimeMillis(), new byte[0], new byte[0], new byte[0]));
  }
}
