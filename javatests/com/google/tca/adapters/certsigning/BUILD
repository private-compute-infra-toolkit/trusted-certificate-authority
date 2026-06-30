# Copyright 2026 Google LLC
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
    name = "BasicConstraintsModifierTest",
    srcs = ["BasicConstraintsModifierTest.java"],
    test_class = "com.google.tca.adapters.certsigning.BasicConstraintsModifierTest",
    deps = [
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)

java_test(
    name = "CertificateModifiersCreatorImplTest",
    srcs = ["CertificateModifiersCreatorImplTest.java"],
    test_class = "com.google.tca.adapters.certsigning.CertificateModifiersCreatorImplTest",
    deps = [
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
    ],
)

java_test(
    name = "KeyUsageModifierTest",
    srcs = ["KeyUsageModifierTest.java"],
    test_class = "com.google.tca.adapters.certsigning.KeyUsageModifierTest",
    deps = [
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)

java_test(
    name = "SubjectAlternativeNameModifierTest",
    srcs = ["SubjectAlternativeNameModifierTest.java"],
    test_class = "com.google.tca.adapters.certsigning.SubjectAlternativeNameModifierTest",
    deps = [
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "NameConstraintsModifierTest",
    srcs = ["NameConstraintsModifierTest.java"],
    test_class = "com.google.tca.adapters.certsigning.NameConstraintsModifierTest",
    deps = [
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
    ],
)
