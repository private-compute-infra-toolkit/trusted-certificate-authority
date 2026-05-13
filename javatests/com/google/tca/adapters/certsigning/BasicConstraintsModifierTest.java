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

import com.google.tca.domain.policy.BasicConstraintsType;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
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
public class BasicConstraintsModifierTest {

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
  public void apply_caWithMaxPathLen_setsCorrectExtension() {
    com.google.tca.domain.policy.BasicConstraints constraints =
        new com.google.tca.domain.policy.BasicConstraints(BasicConstraintsType.CA, 5);
    BasicConstraintsModifier modifier = new BasicConstraintsModifier(constraints);

    modifier.apply(builder);

    X509CertificateHolder holder = builder.build(signer);
    Extension ext = holder.getExtension(Extension.basicConstraints);
    assertThat(ext).isNotNull();

    BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
    assertThat(bc.isCA()).isTrue();
    assertThat(bc.getPathLenConstraint().intValue()).isEqualTo(5);
  }

  @Test
  public void apply_leaf_setsCorrectExtension() {
    com.google.tca.domain.policy.BasicConstraints constraints =
        new com.google.tca.domain.policy.BasicConstraints(BasicConstraintsType.LEAF, 0);
    BasicConstraintsModifier modifier = new BasicConstraintsModifier(constraints);

    modifier.apply(builder);

    X509CertificateHolder holder = builder.build(signer);
    Extension ext = holder.getExtension(Extension.basicConstraints);
    assertThat(ext).isNotNull();

    BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
    assertThat(bc.isCA()).isFalse();
    assertThat(bc.getPathLenConstraint()).isNull();
  }
}
