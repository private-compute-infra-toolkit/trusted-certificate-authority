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

import java.util.Map;

/**
 * Policies is a collection of {@link Policy} objects.
 *
 * @param issuer the expected issuer of the OIDC token for this set of policies.
 * @param subject the expected subject of the OIDC token for this set of policies.
 * @param policiesMap a map where the key is in the format {@code <publisher_id>/<workload_id>} and
 *     the value is the corresponding {@link Policy}.
 */
public record Policies(String issuer, String subject, Map<String, Policy> policiesMap) {
  public Policy get(String key) {
    return policiesMap.get(key);
  }
}
