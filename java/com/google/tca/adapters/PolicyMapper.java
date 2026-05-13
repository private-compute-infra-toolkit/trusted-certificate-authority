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

import static com.google.tca.domain.policy.ReferenceValuesType.OAK;

import com.google.common.flogger.FluentLogger;
import com.google.protobuf.ByteString;
import com.google.tca.domain.policy.BasicConstraints;
import com.google.tca.domain.policy.BasicConstraintsType;
import com.google.tca.domain.policy.InvalidPolicyException;
import com.google.tca.domain.policy.NameConstraints;
import com.google.tca.domain.policy.Policies;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.domain.policy.ReferenceValuesType;
import com.google.tca.domain.policy.X509CertificateAttributes;
import com.google.tca.domain.policy.X509Extensions;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class PolicyMapper {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  public static Policies toDomain(com.google.tca.policy.v1.Policies proto) {

    Map<String, Policy> policiesMap;

    try {
      policiesMap =
          proto.getPoliciesMap().entrySet().stream()
              .collect(Collectors.toMap(Map.Entry::getKey, entry -> toDomain(entry.getValue())));
    } catch (IllegalArgumentException e) {
      throw new InvalidPolicyException("Error occurred during policy parsing", e);
    }

    logger.atInfo().log(
        "Loaded %d policies for issuer %s and subject %s",
        policiesMap.size(), proto.getIssuer(), proto.getSubject());
    return new Policies(proto.getIssuer(), proto.getSubject(), policiesMap);
  }

  static Policy toDomain(com.google.tca.policy.v1.Policy proto) {

    if (!proto.hasCertificateAttributes())
      throw new IllegalArgumentException("Missing CertificateAttributes field, proto: " + proto);

    if (proto.getReferenceValuesCount() < 1)
      throw new IllegalArgumentException(
          "Policy should have at least one Reference Values, proto:\n" + proto);

    return new Policy(
        proto.getPublisherId(),
        proto.getWorkloadId(),
        proto.getTrustDomain(),
        proto.getOperator(),
        proto.getReferenceValuesList().stream()
            .map(PolicyMapper::toDomain)
            .collect(Collectors.toList()),
        toDomain(proto.getCertificateAttributes()));
  }

  private static X509CertificateAttributes toDomain(
      com.google.tca.policy.v1.X509CertificateAttributes proto) {
    return new X509CertificateAttributes(
        Duration.ofSeconds(
            proto.getMaxCertificateValidity().getSeconds(),
            proto.getMaxCertificateValidity().getNanos()),
        toDomain(proto.getX509Extensions()));
  }

  private static X509Extensions toDomain(com.google.tca.policy.v1.X509Extensions proto) {
    return new X509Extensions(
        proto.hasBasicConstraints()
            ? Optional.of(toDomain(proto.getBasicConstraints()))
            : Optional.empty(),
        proto.hasNameConstraints()
            ? Optional.of(toDomain(proto.getNameConstraints()))
            : Optional.empty());
  }

  private static BasicConstraints toDomain(com.google.tca.policy.v1.BasicConstraints proto) {
    return switch (proto.getConstraintCase()) {
      case CA_CERTIFICATE ->
          new BasicConstraints(
              BasicConstraintsType.CA, proto.getCaCertificate().getPathLenConstraint());
      case LEAF_CERTIFICATE -> new BasicConstraints(BasicConstraintsType.LEAF, 0);
      default ->
          throw new IllegalArgumentException("Unsupported or missing certificate type: " + proto);
    };
  }

  private static NameConstraints toDomain(com.google.tca.policy.v1.NameConstraints proto) {
    return new NameConstraints(proto.getPermittedSubtreeList());
  }

  private static ReferenceValues toDomain(com.google.tca.policy.v1.ReferenceValues proto) {
    ByteString raw =
        switch (proto.getValuesCase()) {
          case OAK_REFERENCE_VALUES -> proto.getOakReferenceValues().toByteString();
          default ->
              throw new IllegalArgumentException(
                  "Unsupported or missing reference values type: " + proto);
        };
    ReferenceValuesType type = toDomain(proto.getValuesCase());
    return new ReferenceValues(type, raw);
  }

  private static ReferenceValuesType toDomain(
      com.google.tca.policy.v1.ReferenceValues.ValuesCase proto) {
    return switch (proto) {
      case OAK_REFERENCE_VALUES -> OAK;
      default ->
          throw new IllegalArgumentException(
              "Unsupported or missing reference values type: " + proto);
    };
  }
}
