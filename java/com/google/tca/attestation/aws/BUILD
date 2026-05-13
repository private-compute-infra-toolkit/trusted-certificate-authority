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
    name = "aws",
    srcs = [
        "AwsAttestationVerifier.java",
    ],
    resources = [
        "//java/com/google/tca/attestation/aws/res:aws_root_cert",
    ],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/attestation/common",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_augustcellars_cose_cose_java",
        "@maven//:com_fasterxml_jackson_dataformat_jackson_dataformat_cbor",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:com_upokecenter_cbor",
        "@maven//:jakarta_inject_jakarta_inject_api",
    ],
)
