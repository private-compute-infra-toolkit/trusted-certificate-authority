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

load("@rules_java//java:defs.bzl", "java_library", "java_plugin")

package(default_visibility = ["//visibility:public"])

java_plugin(
    name = "auto_builder_plugin",
    processor_class = "com.google.auto.value.processor.AutoBuilderProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_library(
    name = "policy",
    srcs = [
        "BasicConstraints.java",
        "BasicConstraintsType.java",
        "DnsNameConstraintInTrustDomain.java",
        "FileLoadException.java",
        "InvalidPolicyException.java",
        "NameConstraint.java",
        "NameConstraints.java",
        "Policies.java",
        "Policy.java",
        "ReferenceValues.java",
        "ReferenceValuesType.java",
        "UriNameConstraint.java",
        "UriNameConstraintInTrustDomain.java",
        "X500NameAttributes.java",
        "X509CertificateAttributes.java",
        "X509Extensions.java",
    ],
    plugins = [
        ":auto_builder_plugin",
    ],
    deps = [
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_protobuf_protobuf_java",
    ],
)
