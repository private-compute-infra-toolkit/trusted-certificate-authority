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

load("@rules_java//java:defs.bzl", "java_library")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "oak",
    srcs = [
        "OakAttestation.java",
        "OakAttestationVerifier.java",
        "OakEvidenceVerifier.java",
    ],
    runtime_deps = [
        "//java/com/google/tca/attestation/oak/jni:oak_attestation_verifier_jni",
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_crypto_tink_tink",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_guice",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@oak//proto/attestation:reference_value_java_proto",
        "@oak//proto/attestation:verification_java_proto",
    ],
)
