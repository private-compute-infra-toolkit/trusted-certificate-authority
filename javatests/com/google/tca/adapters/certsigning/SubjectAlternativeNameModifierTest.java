/*
 * Copyright 2026 Google LLC
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

package com.google.tca.adapters.certsigning;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.domain.policy.ReferenceValuesType;
import com.google.tca.domain.policy.X509CertificateAttributes;
import com.google.tca.domain.policy.X509Extensions;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SubjectAlternativeNameModifierTest {

  private X509v3CertificateBuilder builder;
  private ContentSigner signer;

  @Before
  public void setUp() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();

    builder =
        new JcaX509v3CertificateBuilder(
            new X500Name("CN=Issuer"),
            BigInteger.ONE,
            new Date(),
            new Date(System.currentTimeMillis() + 100000),
            new X500Name("CN=Subject"),
            keyPair.getPublic());

    signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
  }

  @Test
  public void apply_addsSubjectAlternativeNameExtension() throws Exception {
    Policy policy =
        new Policy(
            "test-publisher",
            "test-app",
            "example.org",
            "test-operator",
            List.of(new ReferenceValues(ReferenceValuesType.GCP, ByteString.EMPTY)),
            new X509CertificateAttributes(
                Duration.ofHours(1), new X509Extensions(Optional.empty(), Optional.empty())));

    SubjectAlternativeNameModifier modifier = new SubjectAlternativeNameModifier(policy);

    modifier.apply(builder);

    X509CertificateHolder holder = builder.build(signer);
    Extension ext = holder.getExtension(Extension.subjectAlternativeName);
    assertThat(ext).isNotNull();

    GeneralNames names = GeneralNames.getInstance(ext.getParsedValue());
    GeneralName[] namesArray = names.getNames();
    assertThat(namesArray).hasLength(1);
    assertThat(namesArray[0].getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(namesArray[0].getName().toString())
        .isEqualTo(
            "spiffe://example.org/operator/test-operator/publisher/test-publisher/workload/test-app");
  }

  @Test
  public void apply_throwsRuntimeExceptionOnCertIOException() throws Exception {
    Policy policy =
        new Policy(
            "test-publisher",
            "test-app",
            "example.org",
            "test-operator",
            List.of(new ReferenceValues(ReferenceValuesType.GCP, ByteString.EMPTY)),
            new X509CertificateAttributes(
                Duration.ofHours(1), new X509Extensions(Optional.empty(), Optional.empty())));

    SubjectAlternativeNameModifier modifier = new SubjectAlternativeNameModifier(policy);

    X509v3CertificateBuilder mockBuilder = mock(X509v3CertificateBuilder.class);
    when(mockBuilder.addExtension(
            any(ASN1ObjectIdentifier.class), anyBoolean(), any(ASN1Encodable.class)))
        .thenThrow(new CertIOException("Test exception"));

    RuntimeException thrown =
        assertThrows(RuntimeException.class, () -> modifier.apply(mockBuilder));
    assertThat(thrown)
        .hasMessageThat()
        .isEqualTo("Error occurred during application of SAN certificate extension");
    assertThat(thrown).hasCauseThat().isInstanceOf(CertIOException.class);
  }
}
