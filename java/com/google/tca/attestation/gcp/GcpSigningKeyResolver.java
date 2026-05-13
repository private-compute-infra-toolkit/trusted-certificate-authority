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

package com.google.tca.attestation.gcp;

import com.google.common.flogger.FluentLogger;
import com.google.tca.adapters.oidc.OidcJwksKeyFetcher;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import java.security.Key;
import java.util.Optional;

/** A signing key resolver for GCP attestation tokens. */
public final class GcpSigningKeyResolver implements SigningKeyResolver {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final OidcJwksKeyFetcher keyFetcher;

  public GcpSigningKeyResolver(OidcJwksKeyFetcher keyFetcher) {
    this.keyFetcher = keyFetcher;
  }

  @Override
  public Key resolveSigningKey(JwsHeader header, Claims claims) {
    return resolveSigningKey(header, (byte[]) null);
  }

  @Override
  public Key resolveSigningKey(JwsHeader header, byte[] content) {
    logger.atInfo().log("resolveSigningKey with byte[] content");
    String keyId = header.getKeyId();
    if (keyId == null) {
      logger.atWarning().log("Missing 'kid' in JWT header");
      throw new IllegalArgumentException("Missing 'kid' in JWT header");
    }
    logger.atInfo().log("Resolving key for kid: %s", keyId);
    Optional<Key> key = keyFetcher.getKey(keyId);
    if (key.isPresent()) {
      logger.atInfo().log("Key found for kid: %s", keyId);
      return key.get();
    } else {
      logger.atWarning().log("Key not found for kid: %s", keyId);
      throw new IllegalArgumentException("Key not found for kid: " + keyId);
    }
  }
}
