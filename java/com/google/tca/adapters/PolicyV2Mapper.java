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
import com.google.tca.domain.policy.DnsNameConstraintInTrustDomain;
import com.google.tca.domain.policy.InvalidPolicyException;
import com.google.tca.domain.policy.NameConstraint;
import com.google.tca.domain.policy.NameConstraints;
import com.google.tca.domain.policy.Policies;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.domain.policy.ReferenceValuesType;
import com.google.tca.domain.policy.UriNameConstraintInTrustDomain;
import com.google.tca.domain.policy.X500NameAttributes;
import com.google.tca.domain.policy.X509CertificateAttributes;
import com.google.tca.domain.policy.X509Extensions;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class PolicyV2Mapper {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  public static Policies toDomain(com.google.tca.policy.v2.Policies proto) {

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

  static Policy toDomain(com.google.tca.policy.v2.Policy proto) {

    if (!proto.hasCertificateAttributes())
      throw new IllegalArgumentException("Missing CertificateAttributes field, proto: " + proto);

    if (proto.getReferenceValuesCount() < 1)
      throw new IllegalArgumentException(
          "Policy should have at least one Reference Values, proto:\n" + proto);

    return Policy.builder()
        .setPublisherId(proto.getPublisherId())
        .setWorkloadId(proto.getWorkloadId())
        .setOperatorDomain(proto.getOperatorDomain())
        .setOperatorRole(proto.getOperatorRole())
        .setReferenceValuesList(
            proto.getReferenceValuesList().stream()
                .map(PolicyV2Mapper::toDomain)
                .collect(Collectors.toList()))
        .setCertificateAttributes(toDomain(proto.getCertificateAttributes()))
        .build();
  }

  private static X509CertificateAttributes toDomain(
      com.google.tca.policy.v2.X509CertificateAttributes proto) {
    return new X509CertificateAttributes(
        Duration.ofSeconds(
            proto.getMaxCertificateValidity().getSeconds(),
            proto.getMaxCertificateValidity().getNanos()),
        toDomain(proto.getX509Extensions()),
        toDomain(proto.getCertificateSubject()));
  }

  private static X500NameAttributes toDomain(com.google.tca.policy.v2.X500NameAttributes proto) {
    return new X500NameAttributes(proto.getAttributesMap());
  }

  private static X509Extensions toDomain(com.google.tca.policy.v2.X509Extensions proto) {
    return new X509Extensions(
        proto.hasBasicConstraints()
            ? Optional.of(toDomain(proto.getBasicConstraints()))
            : Optional.empty(),
        proto.hasNameConstraints()
            ? Optional.of(toDomain(proto.getNameConstraints()))
            : Optional.empty());
  }

  private static BasicConstraints toDomain(com.google.tca.policy.v2.BasicConstraints proto) {
    return switch (proto.getConstraintCase()) {
      case CA_CERTIFICATE ->
          new BasicConstraints(
              BasicConstraintsType.CA, proto.getCaCertificate().getPathLenConstraint());
      case LEAF_CERTIFICATE -> new BasicConstraints(BasicConstraintsType.LEAF, 0);
      default ->
          throw new IllegalArgumentException("Unsupported or missing certificate type: " + proto);
    };
  }

  private static NameConstraints toDomain(com.google.tca.policy.v2.NameConstraints proto) {
    java.util.List<NameConstraint> subtrees =
        proto.getPermittedSubtreesList().stream()
            .map(PolicyV2Mapper::toDomain)
            .collect(Collectors.toList());
    return new NameConstraints(subtrees);
  }

  private static NameConstraint toDomain(com.google.tca.policy.v2.NameConstraint proto) {
    return switch (proto.getNameConstraintCase()) {
      case URI -> new UriNameConstraintInTrustDomain(proto.getUri().getSubdomainInTcaDomain());
      case DNS -> new DnsNameConstraintInTrustDomain(proto.getDns().getSubdomainInTcaDomain());
      default ->
          throw new IllegalArgumentException(
              "Unsupported or missing name constraint type: " + proto);
    };
  }

  private static ReferenceValues toDomain(com.google.tca.policy.v2.ReferenceValues proto) {
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
      com.google.tca.policy.v2.ReferenceValues.ValuesCase proto) {
    return switch (proto) {
      case OAK_REFERENCE_VALUES -> OAK;
      default ->
          throw new IllegalArgumentException(
              "Unsupported or missing reference values type: " + proto);
    };
  }
}
