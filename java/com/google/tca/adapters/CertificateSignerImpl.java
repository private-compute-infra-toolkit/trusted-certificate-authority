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

import com.google.tca.domain.CertificateModifier;
import com.google.tca.domain.CertificateSigner;
import com.google.tca.domain.TimeProvider;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

@Singleton
public class CertificateSignerImpl implements CertificateSigner {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private final TimeProvider timeProvider;

  @Inject
  public CertificateSignerImpl(TimeProvider timeProvider) {
    this.timeProvider = timeProvider;
  }

  @Override
  public X509Certificate signCsr(
      byte[] csrBytes,
      X509Certificate issuerCert,
      PrivateKey issuerPrivateKey,
      Instant notBefore,
      Instant notAfter,
      List<CertificateModifier> modifiers,
      boolean isCa)
      throws CertificateException, IOException {
    try {
      PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

      BigInteger serial = BigInteger.valueOf(timeProvider.now().toEpochMilli());

      X509v3CertificateBuilder certBuilder =
          new JcaX509v3CertificateBuilder(
              new X500Name(issuerCert.getSubjectX500Principal().getName()),
              serial,
              Date.from(notBefore),
              Date.from(notAfter),
              csr.getSubject(),
              new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo()));

      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
      AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(issuerCert.getPublicKey());
      SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo());

      certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
      certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
      if (isCa) {
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
      } else {
        certBuilder.addExtension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
      }

      modifiers.forEach(modifier -> modifier.apply(certBuilder));

      ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);

      return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    } catch (OperatorCreationException | GeneralSecurityException e) {
      throw new CertificateException(e);
    }
  }
}
