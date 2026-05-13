# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_java//java:defs.bzl", "java_test")

java_test(
    name = "AttestationVerifierProviderImplTest",
    size = "small",
    srcs = ["AttestationVerifierProviderImplTest.java"],
    test_class = "com.google.tca.adapters.AttestationVerifierProviderImplTest",
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/attestation/oak",
        "//java/com/google/tca/domain/attestation",
        "@com_google_protobuf//java/core",
        "@maven//:com_google_guava_guava",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
    ],
)

java_test(
    name = "CertificateIssuanceRequestMapperTest",
    size = "small",
    srcs = ["CertificateIssuanceRequestMapperTest.java"],
    test_class = "com.google.tca.adapters.CertificateIssuanceRequestMapperTest",
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/proto:trusted_certificate_authority_java_proto",
        "@com_google_protobuf//java/core",
        "@maven//:junit_junit",
    ],
)

java_test(
    name = "CertificateSignerImplTest",
    size = "small",
    srcs = ["CertificateSignerImplTest.java"],
    test_class = "com.google.tca.adapters.CertificateSignerImplTest",
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "OakAttestationEvidenceTest",
    size = "small",
    srcs = ["OakAttestationEvidenceTest.java"],
    test_class = "com.google.tca.adapters.OakAttestationEvidenceTest",
    deps = [
        "//java/com/google/tca/adapters",
        "@com_google_protobuf//java/core",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@oak//proto:variant_java_proto",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
    ],
)

java_test(
    name = "PolicyMapperTest",
    size = "small",
    srcs = ["PolicyMapperTest.java"],
    data = glob(["resources/*.textproto"]),
    test_class = "com.google.tca.adapters.PolicyMapperTest",
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/domain/policy",
        "@com_google_protobuf//java/core",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@oak//proto/attestation:reference_value_java_proto",
        "@pcit_api//google/tca/policy/v1:tca_policy_java_proto",
    ],
)
