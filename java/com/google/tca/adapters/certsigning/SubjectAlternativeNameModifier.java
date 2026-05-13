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
import com.google.tca.domain.policy.Policy;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class SubjectAlternativeNameModifier implements CertificateModifier {

  private final Policy policy;

  public SubjectAlternativeNameModifier(Policy policy) {
    this.policy = policy;
  }

  @Override
  public void apply(X509v3CertificateBuilder builder) {
    String san =
        String.format(
            "spiffe://%s/operator/%s/publisher/%s/workload/%s",
            policy.trustDomain(), policy.operator(), policy.publisherId(), policy.workloadId());

    try {
      builder.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, san)));
    } catch (CertIOException e) {
      throw new RuntimeException(
          "Error occurred during application of SAN certificate extension", e);
    }
  }
}
