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

# Main BUILD file for the TCA project.

load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("//:build_defs/tca_aws_enclave.bzl", "tca_aws_eif_and_ami")

package(default_visibility = ["//visibility:public"])

exports_files(["java/com/google/tca/logback.xml"])

string_flag(
    name = "ami_name_flag",
    build_setting_default = "tca-enclave",
)

string_flag(
    name = "aws_region_flag",
    build_setting_default = "us-east-1",
)

string_flag(
    name = "subnet_id_flag",
    build_setting_default = "",
)

tca_aws_eif_and_ami(
    name = "tca_aws_dev",
    enable_worker_debug_mode = True,
)

tca_aws_eif_and_ami(
    name = "tca_aws_release",
)

tca_aws_eif_and_ami(
    name = "tca_aws_integration_test",
    enable_worker_debug_mode = True,
    jar_args = [
        "kms",
        "--config-bucket-prefix=tca-integration-tests-configuration",
        "--kms-key-suffix=alias/tca-integration-tests-key-encryption-key",
        "--cert-backup-bucket-prefix=tca-integration-tests-key-backup",
        "--key-backup-bucket-prefix=tca-integration-tests-key-backup",
    ],
)
