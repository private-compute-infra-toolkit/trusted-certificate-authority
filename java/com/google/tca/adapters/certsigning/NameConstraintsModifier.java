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
import com.google.tca.domain.policy.DnsNameConstraintInTrustDomain;
import com.google.tca.domain.policy.NameConstraint;
import com.google.tca.domain.policy.UriNameConstraint;
import com.google.tca.domain.policy.UriNameConstraintInTrustDomain;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class NameConstraintsModifier implements CertificateModifier {

  private final List<NameConstraint> permitted;
  private final String trustDomain;

  public NameConstraintsModifier(List<NameConstraint> permitted, String trustDomain) {
    this.permitted = permitted;
    this.trustDomain = trustDomain;
  }

  @Override
  public void apply(X509v3CertificateBuilder builder) {
    List<GeneralSubtree> permittedSubtrees = new ArrayList<>();
    for (NameConstraint constraint : permitted) {
      if (constraint instanceof UriNameConstraint uri) {
        permittedSubtrees.add(
            new GeneralSubtree(
                new GeneralName(GeneralName.uniformResourceIdentifier, uri.domain())));
      } else if (constraint instanceof UriNameConstraintInTrustDomain uri) {
        permittedSubtrees.add(
            new GeneralSubtree(
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    String.format("%s.%s", uri.domain(), trustDomain))));
      } else if (constraint instanceof DnsNameConstraintInTrustDomain dns) {
        permittedSubtrees.add(
            new GeneralSubtree(
                new GeneralName(
                    GeneralName.dNSName, String.format("%s.%s", dns.domain(), trustDomain))));
      } else {
        throw new IllegalArgumentException(
            "Unsupported name constraint type: " + constraint.getClass().getName());
      }
    }

    final GeneralSubtree[] noExcludedSubtrees = {};

    NameConstraints nameConstraints =
        new NameConstraints(permittedSubtrees.toArray(new GeneralSubtree[0]), noExcludedSubtrees);
    try {
      builder.addExtension(Extension.nameConstraints, true, nameConstraints);
    } catch (Exception e) {
      throw new RuntimeException("Failed to assign name constraints", e);
    }
  }
}
