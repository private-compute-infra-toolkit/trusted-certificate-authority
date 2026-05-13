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

load("@rules_java//java:defs.bzl", "java_library")

java_library(
    name = "certsigning",
    srcs = [
        "BasicConstraintsModifier.java",
        "CertificateModifiersCreatorImpl.java",
        "NameConstraintsModifier.java",
        "SubjectAlternativeNameModifier.java",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/policy",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)
