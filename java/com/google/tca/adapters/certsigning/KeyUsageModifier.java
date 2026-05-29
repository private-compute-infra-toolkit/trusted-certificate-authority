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

import com.google.tca.domain.CertificateModifier;
import com.google.tca.domain.policy.BasicConstraints;
import com.google.tca.domain.policy.BasicConstraintsType;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class KeyUsageModifier implements CertificateModifier {

  private final BasicConstraints constraints;

  public KeyUsageModifier(BasicConstraints constraints) {
    this.constraints = constraints;
  }

  @Override
  public void apply(X509v3CertificateBuilder builder) {
    boolean isCa = constraints.type() == BasicConstraintsType.CA;
    try {
      if (isCa) {
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
      } else {
        builder.addExtension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
      }
    } catch (Exception e) {
      throw new RuntimeException("Failed to add key usage", e);
    }
  }
}
