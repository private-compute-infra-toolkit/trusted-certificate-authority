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

import static com.google.common.truth.Truth.assertThat;
import static com.google.tca.domain.policy.BasicConstraintsType.CA;
import static org.junit.Assert.assertThrows;

import com.google.protobuf.TextFormat;
import com.google.tca.domain.policy.InvalidPolicyException;
import com.google.tca.domain.policy.Policies;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.ReferenceValuesType;
import com.google.tca.domain.policy.X509Extensions;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(Enclosed.class)
public class PolicyMapperTest {

  @RunWith(JUnit4.class)
  public static class TestConversionFromTextProtoFile {

    private static String readTestFile(String path) throws Exception {
      return Files.readString(Paths.get(path));
    }

    @Test
    public void toDomain_fromTextProto_mapsCorrectly() throws Exception {
      String textProto =
          readTestFile("javatests/com/google/tca/adapters/resources/test_policies.textproto");

      com.google.tca.policy.v1.Policies.Builder builder =
          com.google.tca.policy.v1.Policies.newBuilder();
      TextFormat.getParser().merge(textProto, builder);
      com.google.tca.policy.v1.Policies proto = builder.build();

      Policies domainPolicies = PolicyMapper.toDomain(proto);

      assertThat(domainPolicies.policiesMap()).hasSize(2);
      assertThat(domainPolicies.policiesMap()).containsKey("test-policy");

      Policy firstPolicy = domainPolicies.policiesMap().get("test-policy");
      assertThat(firstPolicy.publisherId()).isEqualTo("publisher-1@testpublisher.com");
      assertThat(firstPolicy.certificateAttributes().certificateSubject().attributes())
          .containsExactly("2.5.4.3", "test");
      assertThat(firstPolicy.referenceValuesList()).hasSize(2);
      assertThat(firstPolicy.referenceValuesList().get(0).type())
          .isEqualTo(ReferenceValuesType.OAK);
      assertThat(firstPolicy.referenceValuesList().get(1).type())
          .isEqualTo(ReferenceValuesType.OAK);

      assertThat(firstPolicy.certificateAttributes().maxCertificateValidity())
          .isEqualTo(java.time.Duration.ofSeconds(3600));

      X509Extensions extensions = firstPolicy.certificateAttributes().extensions();
      assertThat(extensions.basicConstraints()).isPresent();
      assertThat(extensions.basicConstraints().get().type()).isEqualTo(CA);
      assertThat(extensions.basicConstraints().get().pathLenConstraint()).isEqualTo(1);
      assertThat(extensions.nameConstraints()).isPresent();
      assertThat(extensions.nameConstraints().get().permittedSubtrees().size()).isEqualTo(2);
      assertThat(extensions.nameConstraints().get().permittedSubtrees().get(0))
          .isEqualTo(".example1.org");
      assertThat(extensions.nameConstraints().get().permittedSubtrees().get(1))
          .isEqualTo(".example2.org");
    }

    @Test
    public void toDomain_fromInvalidTextProto_throwsException() throws Exception {
      String textProto =
          readTestFile(
              "javatests/com/google/tca/adapters/resources/invalid_reference_values.textproto");

      com.google.tca.policy.v1.Policies.Builder builder =
          com.google.tca.policy.v1.Policies.newBuilder();
      TextFormat.getParser().merge(textProto, builder);
      com.google.tca.policy.v1.Policies proto = builder.build();

      assertThrows(InvalidPolicyException.class, () -> PolicyMapper.toDomain(proto));
    }
  }

  @RunWith(JUnit4.class)
  public static class TestConversionFromManualProto {
    @Test
    public void toDomain_policies_mapsCorrectly() {
      com.google.oak.attestation.v1.ReferenceValues oakRef =
          com.google.oak.attestation.v1.ReferenceValues.getDefaultInstance();
      com.google.tca.policy.v1.ReferenceValues referenceValuesProto =
          com.google.tca.policy.v1.ReferenceValues.newBuilder()
              .setOakReferenceValues(oakRef)
              .build();

      com.google.tca.policy.v1.Policy policyProto =
          com.google.tca.policy.v1.Policy.newBuilder()
              .setPublisherId("pub1")
              .setWorkloadId("work1")
              .setTrustDomain("trust.domain.com")
              .addReferenceValues(referenceValuesProto)
              .setCertificateAttributes(
                  com.google.tca.policy.v1.X509CertificateAttributes.newBuilder()
                      .setMaxCertificateValidity(
                          com.google.protobuf.Duration.newBuilder().setSeconds(3600).build())
                      .setX509Extensions(
                          com.google.tca.policy.v1.X509Extensions.newBuilder().build())
                      .setCertificateSubject(
                          com.google.tca.policy.v1.X500NameAttributes.newBuilder()
                              .putAttributes("2.5.4.3", "manual-subject")
                              .build())
                      .build())
              .build();

      com.google.tca.policy.v1.Policies policiesProto =
          com.google.tca.policy.v1.Policies.newBuilder()
              .putPolicies("test-policy", policyProto)
              .build();

      Policies domainPolicies = PolicyMapper.toDomain(policiesProto);

      assertThat(domainPolicies.policiesMap()).hasSize(1);
      assertThat(domainPolicies.policiesMap()).containsKey("test-policy");

      Policy domainPolicy = domainPolicies.policiesMap().get("test-policy");
      assertThat(domainPolicy.publisherId()).isEqualTo("pub1");
      assertThat(domainPolicy.workloadId()).isEqualTo("work1");
      assertThat(domainPolicy.trustDomain()).isEqualTo("trust.domain.com");
      assertThat(domainPolicy.certificateAttributes().certificateSubject().attributes())
          .containsExactly("2.5.4.3", "manual-subject");

      assertThat(domainPolicy.referenceValuesList()).hasSize(1);
      assertThat(domainPolicy.referenceValuesList().get(0).type())
          .isEqualTo(ReferenceValuesType.OAK);
      assertThat(domainPolicy.referenceValuesList().get(0).raw())
          .isEqualTo(referenceValuesProto.getOakReferenceValues().toByteString());

      assertThat(domainPolicy.certificateAttributes().maxCertificateValidity())
          .isEqualTo(java.time.Duration.ofSeconds(3600));
      assertThat(domainPolicy.certificateAttributes().extensions()).isNotNull();
      assertThat(domainPolicy.certificateAttributes().extensions().basicConstraints()).isEmpty();
    }

    @Test
    public void toDomain_policyWithFullExtensions_mapsCorrectly() {

      com.google.oak.attestation.v1.ReferenceValues oakRef =
          com.google.oak.attestation.v1.ReferenceValues.getDefaultInstance();
      com.google.tca.policy.v1.ReferenceValues referenceValuesProto =
          com.google.tca.policy.v1.ReferenceValues.newBuilder()
              .setOakReferenceValues(oakRef)
              .build();

      com.google.tca.policy.v1.Policy policyProto =
          com.google.tca.policy.v1.Policy.newBuilder()
              .setPublisherId("pub1")
              .addReferenceValues(referenceValuesProto)
              .setCertificateAttributes(
                  com.google.tca.policy.v1.X509CertificateAttributes.newBuilder()
                      .setX509Extensions(
                          com.google.tca.policy.v1.X509Extensions.newBuilder()
                              .setBasicConstraints(
                                  com.google.tca.policy.v1.BasicConstraints.newBuilder()
                                      .setCaCertificate(
                                          com.google.tca.policy.v1.CaCertificate.newBuilder()
                                              .setPathLenConstraint(2)
                                              .build())
                                      .build())
                              .setNameConstraints(
                                  com.google.tca.policy.v1.NameConstraints.newBuilder()
                                      .addPermittedSubtree("some.subdomain.example.com")
                                      .build())
                              .build())
                      .setCertificateSubject(
                          com.google.tca.policy.v1.X500NameAttributes.newBuilder()
                              .putAttributes("2.5.4.3", "full-extensions-subject")
                              .build())
                      .build())
              .build();

      Policy domainPolicy = PolicyMapper.toDomain(policyProto);

      com.google.tca.domain.policy.X509Extensions extensions =
          domainPolicy.certificateAttributes().extensions();

      // Basic Constraints
      assertThat(extensions.basicConstraints()).isPresent();
      assertThat(extensions.basicConstraints().get().type()).isEqualTo(CA);
      assertThat(extensions.basicConstraints().get().pathLenConstraint()).isEqualTo(2);

      // Name Constraints
      assertThat(extensions.nameConstraints()).isPresent();
      assertThat(extensions.nameConstraints().get().permittedSubtrees().get(0))
          .isEqualTo("some.subdomain.example.com");
    }

    @Test
    public void toDomain_policyWithSomeExtensions_mapsCorrectly() {

      com.google.oak.attestation.v1.ReferenceValues oakRef =
          com.google.oak.attestation.v1.ReferenceValues.getDefaultInstance();
      com.google.tca.policy.v1.ReferenceValues referenceValuesProto =
          com.google.tca.policy.v1.ReferenceValues.newBuilder()
              .setOakReferenceValues(oakRef)
              .build();

      com.google.tca.policy.v1.Policy policyProto =
          com.google.tca.policy.v1.Policy.newBuilder()
              .setPublisherId("pub1")
              .setTrustDomain("td1")
              .setWorkloadId("wl1")
              .addReferenceValues(referenceValuesProto)
              .setCertificateAttributes(
                  com.google.tca.policy.v1.X509CertificateAttributes.newBuilder()
                      .setX509Extensions(
                          com.google.tca.policy.v1.X509Extensions.newBuilder()
                              .setBasicConstraints(
                                  com.google.tca.policy.v1.BasicConstraints.newBuilder()
                                      .setLeafCertificate(
                                          com.google.tca.policy.v1.LeafCertificate.newBuilder()
                                              .build()))
                              .build())
                      .setCertificateSubject(
                          com.google.tca.policy.v1.X500NameAttributes.newBuilder()
                              .putAttributes("2.5.4.3", "some-extensions-subject")
                              .build())
                      .build())
              .build();

      Policy domainPolicy = PolicyMapper.toDomain(policyProto);

      assertThat(domainPolicy.certificateAttributes().extensions().basicConstraints()).isPresent();
      assertThat(domainPolicy.certificateAttributes().extensions().nameConstraints()).isEmpty();
    }
  }

  @RunWith(JUnit4.class)
  public static class TestConversionErrors {

    private com.google.tca.policy.v1.Policies.Builder createValidPoliciesBuilder() {
      com.google.oak.attestation.v1.ReferenceValues oakRef =
          com.google.oak.attestation.v1.ReferenceValues.getDefaultInstance();
      com.google.tca.policy.v1.ReferenceValues referenceValuesProto =
          com.google.tca.policy.v1.ReferenceValues.newBuilder()
              .setOakReferenceValues(oakRef)
              .build();

      com.google.tca.policy.v1.Policy policyProto =
          com.google.tca.policy.v1.Policy.newBuilder()
              .setPublisherId("pub1")
              .setWorkloadId("work1")
              .setTrustDomain("trust.domain.com")
              .addReferenceValues(referenceValuesProto)
              .setCertificateAttributes(
                  com.google.tca.policy.v1.X509CertificateAttributes.newBuilder()
                      .setMaxCertificateValidity(
                          com.google.protobuf.Duration.newBuilder().setSeconds(3600).build())
                      .setX509Extensions(
                          com.google.tca.policy.v1.X509Extensions.newBuilder().build())
                      .setCertificateSubject(
                          com.google.tca.policy.v1.X500NameAttributes.newBuilder()
                              .putAttributes("2.5.4.3", "valid-subject")
                              .build())
                      .build())
              .build();

      return com.google.tca.policy.v1.Policies.newBuilder().putPolicies("test-policy", policyProto);
    }

    @Test
    public void toDomain_missingCertificateAttributes_throwsException() {
      com.google.tca.policy.v1.Policies.Builder builder = createValidPoliciesBuilder();
      com.google.tca.policy.v1.Policy.Builder policyBuilder =
          builder.getPoliciesOrThrow("test-policy").toBuilder();
      policyBuilder.clearCertificateAttributes();

      assertThrows(
          IllegalArgumentException.class, () -> PolicyMapper.toDomain(policyBuilder.build()));
    }

    @Test
    public void toDomain_emptyReferenceValues_throwsException() {
      com.google.tca.policy.v1.Policies.Builder builder = createValidPoliciesBuilder();
      com.google.tca.policy.v1.Policy.Builder policyBuilder =
          builder.getPoliciesOrThrow("test-policy").toBuilder();
      policyBuilder.clearReferenceValues();

      assertThrows(
          IllegalArgumentException.class, () -> PolicyMapper.toDomain(policyBuilder.build()));
    }

    @Test
    public void toDomain_unsupportedBasicConstraints_throwsException() {
      com.google.tca.policy.v1.Policies.Builder builder = createValidPoliciesBuilder();
      com.google.tca.policy.v1.Policy.Builder policyBuilder =
          builder.getPoliciesOrThrow("test-policy").toBuilder();

      policyBuilder
          .getCertificateAttributesBuilder()
          .getX509ExtensionsBuilder()
          .setBasicConstraints(com.google.tca.policy.v1.BasicConstraints.newBuilder().build());

      builder.putPolicies("test-policy", policyBuilder.build());
      com.google.tca.policy.v1.Policies proto = builder.build();

      assertThrows(InvalidPolicyException.class, () -> PolicyMapper.toDomain(proto));
    }

    @Test
    public void toDomain_unsupportedReferenceValues_throwsException() {
      com.google.tca.policy.v1.Policies.Builder builder = createValidPoliciesBuilder();
      com.google.tca.policy.v1.Policy.Builder policyBuilder =
          builder.getPoliciesOrThrow("test-policy").toBuilder();

      policyBuilder
          .clearReferenceValues()
          .addReferenceValues(com.google.tca.policy.v1.ReferenceValues.newBuilder().build());

      builder.putPolicies("test-policy", policyBuilder.build());
      com.google.tca.policy.v1.Policies proto = builder.build();

      assertThrows(InvalidPolicyException.class, () -> PolicyMapper.toDomain(proto));
    }
  }
}
