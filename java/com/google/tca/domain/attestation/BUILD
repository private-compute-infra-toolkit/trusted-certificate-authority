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

load("@rules_java//java:defs.bzl", "java_library", "java_plugin")

package(default_visibility = ["//visibility:public"])

java_plugin(
    name = "auto_value_plugin",
    processor_class = "com.google.auto.value.processor.AutoValueProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_library(
    name = "attestation",
    srcs = [
        "AttestationEvidence.java",
        "AttestationPlatform.java",
        "AttestationVerifier.java",
        "AttestationVerifierProvider.java",
        "EndorsementAnnotations.java",
        "IncorrectEndorsementFormatException.java",
        "Validity.java",
    ],
    plugins = [":auto_value_plugin"],
    deps = [
        "//java/com/google/tca/domain/policy",
        "@com_google_protobuf//java/core",
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_guava_guava",
        "@maven//:jakarta_inject_jakarta_inject_api",
    ],
)
