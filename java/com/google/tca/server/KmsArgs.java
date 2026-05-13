/*
 * Copyright 2025 Google LLC
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

package com.google.tca.server;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

@Parameters(
    commandNames = KmsArgs.COMMAND_NAME,
    commandDescription = "Run in KMS mode with AWS dependencies (default when no args passed).",
    separators = "=")
public class KmsArgs {

  public static final String COMMAND_NAME = "kms";

  @Parameter(
      names = "--cert-backup-bucket-prefix",
      description = "The prefix for the S3 bucket for TCA public artifacts.")
  private String certBackupBucketPrefix = "tca-root-cert-backup";

  @Parameter(
      names = "--key-backup-bucket-prefix",
      description = "The prefix for the S3 bucket for TCA root key backup.")
  private String keyBackupBucketPrefix = "tca-root-key-backup";

  @Parameter(
      names = "--kms-key-suffix",
      description = "The suffix (alias) of the KMS key to use for root key protection.")
  private String kmsKeySuffix = "alias/tca-key-encryption-key";

  @Parameter(
      names = "--config-bucket-prefix",
      description = "The prefix for the S3 bucket for storing the TCA configuration file.")
  private String configBucketPrefix = "tca-configuration";

  public String getCertBackupBucketPrefix() {
    return certBackupBucketPrefix;
  }

  public String getKeyBackupBucketPrefix() {
    return keyBackupBucketPrefix;
  }

  public String getKmsKeySuffix() {
    return kmsKeySuffix;
  }

  public String getConfigBucketPrefix() {
    return configBucketPrefix;
  }
}
