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

package com.google.tca.adapters.oidc;

import com.google.common.flogger.FluentLogger;
import com.google.common.io.BaseEncoding;
import com.google.tca.domain.AudienceBindingValidator;
import com.google.tca.domain.CallerIdentity;
import jakarta.inject.Inject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Set;

/** OIDC-specific implementation of audience binding validation. */
public final class OidcAudienceBindingValidator implements AudienceBindingValidator {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final String audienceHostname;

  @Inject
  public OidcAudienceBindingValidator(@AudienceHostname String audienceHostname) {
    this.audienceHostname = audienceHostname;
  }

  @Override
  public void validate(PublicKey csrPublicKey, CallerIdentity callerIdentity) {
    String digest;
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hash = md.digest(csrPublicKey.getEncoded());
      digest = BaseEncoding.base16().lowerCase().encode(hash);
    } catch (NoSuchAlgorithmException e) {
      logger.atSevere().withCause(e).log("SHA-256 algorithm not found.");
      return;
    }

    String expectedAudience =
        String.format(
            "https://%s/v1/certificates:issue?pubkey_sha256=%s", audienceHostname, digest);
    Set<String> audiences = callerIdentity.audiences();

    if (!audiences.contains(expectedAudience)) {
      logger.atSevere().log(
          "OIDC audience binding mismatch. Expected an audience of: %s. Found audiences: %s",
          expectedAudience, audiences);
      // TODO: We should throw exception here
    }
  }
}
