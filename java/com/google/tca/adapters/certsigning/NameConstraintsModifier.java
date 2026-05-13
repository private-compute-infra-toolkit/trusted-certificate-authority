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
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class NameConstraintsModifier implements CertificateModifier {

  List<String> permitted;

  public NameConstraintsModifier(List<String> permitted) {
    this.permitted = permitted;
  }

  @Override
  public void apply(X509v3CertificateBuilder builder) {

    List<GeneralSubtree> permittedSubtrees =
        this.permitted.stream()
            .map(
                uri ->
                    new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, uri)))
            .toList();

    GeneralSubtree[] permitted = permittedSubtrees.toArray(new GeneralSubtree[0]);
    GeneralSubtree[] excluded = {};

    NameConstraints nameConstraints = new NameConstraints(permitted, excluded);
    try {
      builder.addExtension(Extension.nameConstraints, true, nameConstraints);
    } catch (Exception e) {
      throw new RuntimeException("Failed to assign name constraints", e);
    }
  }
}
