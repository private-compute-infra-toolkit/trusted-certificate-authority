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
import com.google.tca.domain.policy.BasicConstraintsType;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class BasicConstraintsModifier implements CertificateModifier {

  private final com.google.tca.domain.policy.BasicConstraints constraints;

  public BasicConstraintsModifier(com.google.tca.domain.policy.BasicConstraints constraints) {
    this.constraints = constraints;
  }

  @Override
  public void apply(X509v3CertificateBuilder builder) {
    boolean isCa = constraints.type() == BasicConstraintsType.CA;
    BasicConstraints basicConstraints;

    if (isCa) {
      basicConstraints = new BasicConstraints(constraints.pathLenConstraint());
    } else {
      basicConstraints = new BasicConstraints(false);
    }

    try {
      builder.addExtension(Extension.basicConstraints, true, basicConstraints);
    } catch (Exception e) {
      throw new RuntimeException("Failed to add basic constraints", e);
    }
  }
}
