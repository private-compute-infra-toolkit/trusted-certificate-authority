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

import java.util.List;

/**
 * Represents the validation requirements that a specific workload should pass and the certificate
 * properties which should be applied to the certificate generated for such workload by TCA.
 */
public record Policy(
    String publisherId,
    String workloadId,
    String trustDomain,
    String operator,
    List<ReferenceValues> referenceValuesList,
    X509CertificateAttributes certificateAttributes) {}
