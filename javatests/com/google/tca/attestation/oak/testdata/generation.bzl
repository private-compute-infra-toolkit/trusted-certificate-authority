# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Macro for generating attestation data.
def generate_attestation_data(name, file_name_prefix):
    """Generates attestation data from textproto files.

    Args:
      name: The name of the filegroup target.
      file_name_prefix: The prefix of the input textproto files (e.g. "milan_oc_release").
    """
    genrule_name = "generate_" + name

    native.genrule(
        name = genrule_name,
        srcs = [
            file_name_prefix + "_endorsements.textproto",
            file_name_prefix + "_evidence.textproto",
            file_name_prefix + "_reference_values.textproto",
            "@oak//proto/attestation:endorsement.proto",
            "@oak//proto/attestation:evidence.proto",
            "@oak//proto/attestation:eventlog.proto",
            "@oak//proto/attestation:reference_value.proto",
            "@oak//proto/attestation:tcb_version.proto",
            "@oak//proto/crypto:certificate.proto",
            "@oak//proto:digest.proto",
            "@oak//proto:variant.proto",
            "@oak//proto:validity.proto",
            "@com_google_protobuf//:well_known_type_protos",
        ],
        outs = [
            file_name_prefix + "_endorsements.binarypb",
            file_name_prefix + "_evidence.binarypb",
            file_name_prefix + "_reference_values.binarypb",
        ],
        cmd = """
            $(location @com_google_protobuf//:protoc) \
            --encode=oak.attestation.v1.ReferenceValues \
            -Iexternal/oak+ \
            -Iexternal/protobuf+/src \
            -I. \
            $(location @oak//proto/attestation:reference_value.proto) \
            $(location @oak//proto/attestation:tcb_version.proto) \
            $(location @oak//proto:digest.proto) \
            $(locations @com_google_protobuf//:well_known_type_protos) \
            < $(location {file_name_prefix}_reference_values.textproto) \
            > $(location {file_name_prefix}_reference_values.binarypb) && \

            $(location @com_google_protobuf//:protoc) \
            --encode=oak.attestation.v1.Endorsements \
            -Iexternal/oak+ \
            -Iexternal/protobuf+/src \
            -I. \
            $(location @oak//proto/attestation:endorsement.proto) \
            $(location @oak//proto:variant.proto) \
            $(location @oak//proto/crypto:certificate.proto) \
            $(location @oak//proto:validity.proto) \
            $(location @oak//proto:digest.proto) \
            $(locations @com_google_protobuf//:well_known_type_protos) \
            < $(location {file_name_prefix}_endorsements.textproto) \
            > $(location {file_name_prefix}_endorsements.binarypb) && \

            $(location @com_google_protobuf//:protoc) \
            --encode=oak.attestation.v1.Evidence \
            -Iexternal/oak+ \
            -Iexternal/protobuf+/src \
            -I. \
            $(location @oak//proto/attestation:evidence.proto) \
            $(location @oak//proto/attestation:eventlog.proto) \
            $(location @oak//proto:digest.proto) \
            $(locations @com_google_protobuf//:well_known_type_protos) \
            < $(location {file_name_prefix}_evidence.textproto) \
            > $(location {file_name_prefix}_evidence.binarypb)
        """.format(file_name_prefix = file_name_prefix),
        tools = ["@com_google_protobuf//:protoc"],
    )

    native.filegroup(
        name = name,
        srcs = [":" + genrule_name],
    )
