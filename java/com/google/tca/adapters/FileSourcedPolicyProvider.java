/*
 * Copyright 2026 Google LLC
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

package com.google.tca.adapters;

import com.google.common.flogger.FluentLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.TextFormat;
import com.google.tca.domain.CallerIdentity;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.PolicyProvider;
import com.google.tca.domain.policy.FileLoadException;
import com.google.tca.domain.policy.Policies;
import com.google.tca.domain.policy.Policy;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Optional;

@Singleton
public class FileSourcedPolicyProvider implements PolicyProvider {
  private final FileFetcher fileFetcher;
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @Inject
  public FileSourcedPolicyProvider(FileFetcher fileFetcher) {
    this.fileFetcher = fileFetcher;
  }

  @Override
  public Optional<Policy> getPolicy(
      CallerIdentity identity, String publisherId, String workloadId) {
    String clientId = identity.getClientId();
    Optional<ByteString> rawFileOpt;
    try {
      rawFileOpt = fileFetcher.fetchFile(clientId);
    } catch (FileLoadException e) {
      logger.atWarning().log(
          "Failed to get file for [%s, %s], exception: %s",
          identity.issuer(), identity.subject(), e);
      return Optional.empty();
    }

    if (rawFileOpt.isEmpty()) {
      logger.atWarning().log("File not found for [%s, %s]", identity.issuer(), identity.subject());
      return Optional.empty();
    }
    ByteString rawFile = rawFileOpt.get();

    com.google.tca.policy.v1.Policies.Builder builder =
        com.google.tca.policy.v1.Policies.newBuilder();

    try {
      TextFormat.getParser().merge(rawFile.toStringUtf8(), builder);
    } catch (TextFormat.ParseException e) {
      logger.atWarning().log("Failed to parse file for clientId = %s", clientId);
      return Optional.empty();
    }
    com.google.tca.policy.v1.Policies proto = builder.build();
    Policies domainPolicies = PolicyMapper.toDomain(proto);

    if (!domainPolicies.issuer().equals(identity.issuer())
        || !domainPolicies.subject().equals(identity.subject())) {
      throw new IllegalArgumentException(
          String.format(
              "Policy identity mismatch. File for %s has issuer: %s, subject: %s, but request has"
                  + " issuer: %s, subject: %s",
              clientId,
              domainPolicies.issuer(),
              domainPolicies.subject(),
              identity.issuer(),
              identity.subject()));
    }

    String key = publisherId + "/" + workloadId;
    Policy policy = domainPolicies.get(key);

    if (null == policy) {
      logger.atWarning().log(
          "Policy file for clientId = %s exists, but does not contain records for key = %s",
          clientId, key);
      return Optional.empty();
    }
    return Optional.of(policy);
  }
}
