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

package com.google.tca.domain.policy;

import com.google.auto.value.AutoBuilder;
import java.util.List;

/**
 * Represents the validation requirements that a specific workload should pass and the certificate
 * properties which should be applied to the certificate generated for such workload by TCA.
 */
public record Policy(
    String publisherId,
    String workloadId,
    String operatorDomain,
    String operatorRole,
    List<ReferenceValues> referenceValuesList,
    X509CertificateAttributes certificateAttributes) {

  public static Builder builder() {
    return new AutoBuilder_Policy_Builder();
  }

  /** Builder for {@link Policy}. */
  @AutoBuilder
  public interface Builder {
    Builder setPublisherId(String publisherId);

    Builder setWorkloadId(String workloadId);

    Builder setOperatorDomain(String operatorDomain);

    Builder setOperatorRole(String operatorRole);

    Builder setReferenceValuesList(List<ReferenceValues> referenceValuesList);

    Builder setCertificateAttributes(X509CertificateAttributes certificateAttributes);

    Policy build();
  }
}
