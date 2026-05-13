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

package com.google.tca.adapters;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.when;

import com.google.tca.adapters.certsigning.BasicConstraintsModifier;
import com.google.tca.adapters.certsigning.NameConstraintsModifier;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.policy.BasicConstraints;
import com.google.tca.domain.policy.BasicConstraintsType;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class CertificateSignerImplTest {

  @Mock private TimeProvider mockTimeProvider;

  private CertificateSignerImpl certificateSigner;
  private KeyPair issuerKeyPair;
  private X509Certificate issuerCert;

  private final Instant testTime = Instant.parse("2000-01-01T12:34:56Z");

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    certificateSigner = new CertificateSignerImpl(mockTimeProvider);
    when(mockTimeProvider.now()).thenReturn(testTime);

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    issuerKeyPair = keyGen.generateKeyPair();

    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(
            new X500Name("CN=Issuer CA"),
            BigInteger.ONE,
            java.util.Date.from(testTime.minus(Duration.ofDays(1))),
            java.util.Date.from(testTime.plus(Duration.ofDays(10))),
            new X500Name("CN=Issuer CA"),
            issuerKeyPair.getPublic());

    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate());
    issuerCert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
  }

  @Test
  public void signCsr_leafCertificate_succeedsWithCorrectExtensions() throws Exception {
    KeyPair clientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

    JcaPKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(
            new X500Name("CN=TestWorkload"), clientKeyPair.getPublic());
    ContentSigner clientSigner =
        new JcaContentSignerBuilder("SHA256withRSA").build(clientKeyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(clientSigner);

    X509Certificate signedCert =
        certificateSigner.signCsr(
            csr.getEncoded(),
            issuerCert,
            issuerKeyPair.getPrivate(),
            testTime,
            testTime.plus(Duration.ofHours(1)),
            List.of(),
            /* isCa= */ false);

    assertThat(signedCert).isNotNull();
    signedCert.verify(issuerKeyPair.getPublic());
    assertThat(signedCert.getSubjectX500Principal().getName()).isEqualTo("CN=TestWorkload");

    boolean[] keyUsage = signedCert.getKeyUsage();
    assertThat(keyUsage).isNotNull();
    assertThat(keyUsage[0]).isTrue(); // digitalSignature
    assertThat(keyUsage[2]).isTrue(); // keyEncipherment
    assertThat(keyUsage[5]).isFalse(); // keyCertSign (not a CA)
    assertThat(signedCert.getBasicConstraints()).isEqualTo(-1);
  }

  @Test
  public void signCsr_caCertificate_succeedsWithCorrectExtensions() throws Exception {
    KeyPair clientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

    JcaPKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(
            new X500Name("CN=TestCA"), clientKeyPair.getPublic());
    ContentSigner clientSigner =
        new JcaContentSignerBuilder("SHA256withRSA").build(clientKeyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(clientSigner);

    X509Certificate signedCert =
        certificateSigner.signCsr(
            csr.getEncoded(),
            issuerCert,
            issuerKeyPair.getPrivate(),
            testTime,
            testTime.plus(Duration.ofHours(1)),
            List.of(),
            /* isCa= */ true);

    assertThat(signedCert).isNotNull();
    signedCert.verify(issuerKeyPair.getPublic());
    assertThat(signedCert.getSubjectX500Principal().getName()).isEqualTo("CN=TestCA");

    boolean[] keyUsage = signedCert.getKeyUsage();
    assertThat(keyUsage).isNotNull();
    assertThat(keyUsage[0]).isFalse(); // digitalSignature
    assertThat(keyUsage[2]).isFalse(); // keyEncipherment
    assertThat(keyUsage[5]).isTrue(); // keyCertSign (is a CA)
  }

  @Test
  public void signCsr_withModifiers_appliesModifiers() throws Exception {
    KeyPair clientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

    JcaPKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(
            new X500Name("CN=TestCA"), clientKeyPair.getPublic());
    ContentSigner clientSigner =
        new JcaContentSignerBuilder("SHA256withRSA").build(clientKeyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(clientSigner);

    BasicConstraints bcConfig = new BasicConstraints(BasicConstraintsType.CA, 3);
    BasicConstraintsModifier bcModifier = new BasicConstraintsModifier(bcConfig);

    List<String> permittedSubtrees = List.of("permitted.example.com");
    NameConstraintsModifier ncModifier = new NameConstraintsModifier(permittedSubtrees);

    X509Certificate signedCert =
        certificateSigner.signCsr(
            csr.getEncoded(),
            issuerCert,
            issuerKeyPair.getPrivate(),
            testTime,
            testTime.plus(Duration.ofHours(1)),
            List.of(bcModifier, ncModifier),
            /* isCa= */ true);

    assertThat(signedCert).isNotNull();
    signedCert.verify(issuerKeyPair.getPublic());
    assertThat(signedCert.getSubjectX500Principal().getName()).isEqualTo("CN=TestCA");

    boolean[] keyUsage = signedCert.getKeyUsage();
    assertThat(keyUsage).isNotNull();
    assertThat(keyUsage[0]).isFalse(); // digitalSignature
    assertThat(keyUsage[2]).isFalse(); // keyEncipherment
    assertThat(keyUsage[5]).isTrue(); // keyCertSign (is a CA)

    assertThat(signedCert.getBasicConstraints()).isEqualTo(3);

    byte[] ncExtensionValue =
        signedCert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.nameConstraints.getId());
    assertThat(ncExtensionValue).isNotNull();

    org.bouncycastle.asn1.x509.NameConstraints nc =
        org.bouncycastle.asn1.x509.NameConstraints.getInstance(
            org.bouncycastle.asn1.ASN1OctetString.getInstance(ncExtensionValue).getOctets());

    assertThat(nc.getPermittedSubtrees()).isNotNull();
    assertThat(nc.getPermittedSubtrees()).hasLength(1);
    org.bouncycastle.asn1.x509.GeneralSubtree subtree = nc.getPermittedSubtrees()[0];
    assertThat(subtree.getBase().getTagNo())
        .isEqualTo(org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier);
    assertThat(subtree.getBase().getName().toString()).isEqualTo("permitted.example.com");
  }
}
