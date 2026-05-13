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

package com.google.tca.attestation.aws;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import COSE.MessageTag;
import COSE.Sign1Message;
import com.google.common.io.Resources;
import com.google.protobuf.ByteString;
import com.google.tca.adapters.AwsAttestationEvidence;
import com.google.tca.adapters.KeyDecoderImpl;
import com.google.tca.domain.KeyDecoder;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.policy.ReferenceValues;
import com.upokecenter.cbor.CBORObject;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class AwsAttestationVerifierTest {

  private static final String SAMPLE_ATTESTATION_PATH =
      "com/google/tca/attestation/aws/resources/sample_attestation.b64";
  private static final String TCA_ROOT_CERT_PATH =
      "com/google/tca/attestation/aws/resources/tca_root_certificate.pem";
  private AwsAttestationVerifier verifier;
  private String sampleAttestationDocBase64;
  X509Certificate rootCertificate;
  private final KeyDecoder keyDecoder = new KeyDecoderImpl();
  private final ReferenceValues unused = null;

  @Before
  public void setUp() throws Exception {
    sampleAttestationDocBase64 =
        Resources.toString(Resources.getResource(SAMPLE_ATTESTATION_PATH), UTF_8)
            .replaceAll("\\s", "");
    byte[] sampleAttestationDoc = Base64.getDecoder().decode(sampleAttestationDocBase64);
    // Extract nonce and validity date from the document payload
    Sign1Message sign1Message =
        (Sign1Message) Sign1Message.DecodeFromBytes(sampleAttestationDoc, MessageTag.Sign1);
    CBORObject payloadCbor = CBORObject.DecodeFromBytes(sign1Message.GetContent());

    byte[] leafCertBytes = payloadCbor.get("certificate").GetByteString();
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    X509Certificate leafCert =
        (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(leafCertBytes));
    Instant validityDate = leafCert.getNotBefore().toInstant();

    rootCertificate =
        (X509Certificate)
            certFactory.generateCertificate(
                Resources.asByteSource(Resources.getResource(TCA_ROOT_CERT_PATH)).openStream());

    // Adjust verifier to use the specific validity date
    verifier = new AwsAttestationVerifier(validityDate, keyDecoder);
  }

  private PublicKey getPublicKey() {
    try {
      byte[] sampleAttestationDoc = Base64.getDecoder().decode(sampleAttestationDocBase64);
      Sign1Message sign1Message =
          (Sign1Message) Sign1Message.DecodeFromBytes(sampleAttestationDoc, MessageTag.Sign1);
      CBORObject payloadCbor = CBORObject.DecodeFromBytes(sign1Message.GetContent());
      byte[] publicKeyBytes = payloadCbor.get("public_key").GetByteString();
      return keyDecoder.decodeRawPublicKey(publicKeyBytes);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void verifyAttestation_success() {
    boolean success =
        verifier.verify(createAwsEvidence(sampleAttestationDocBase64), getPublicKey(), unused);

    assertThat(success).isTrue();
  }

  @Test
  public void verifyAttestation_invalidBase64_returnsEmpty() {
    boolean success = verifier.verify(createAwsEvidence("invalid base64"), getPublicKey(), null);
    assertThat(success).isFalse();
  }

  @Test
  public void verifyAttestation_corruptedDocument_returnsEmpty() {
    byte[] corruptedDocBytes = Base64.getDecoder().decode(sampleAttestationDocBase64);
    corruptedDocBytes[corruptedDocBytes.length - 10] ^= 0xFF; // Corrupt the signature part
    String corruptedBase64 = Base64.getEncoder().encodeToString(corruptedDocBytes);
    boolean success = verifier.verify(createAwsEvidence(corruptedBase64), getPublicKey(), unused);
    assertThat(success).isFalse();
  }

  @Test
  public void verifyAttestation_keyMismatch_returnsEmpty() {
    // Generate a random key that is different from the one in the attestation doc
    PublicKey differentKey = rootCertificate.getPublicKey();

    // Generate a new random key pair.
    try {
      java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      differentKey = keyGen.generateKeyPair().getPublic();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    boolean success =
        verifier.verify(createAwsEvidence(sampleAttestationDocBase64), differentKey, unused);
    assertThat(success).isFalse();
  }

  private AttestationEvidence createAwsEvidence(String token) {
    return AwsAttestationEvidence.create(ByteString.copyFromUtf8(token));
  }
}
