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

import com.google.common.io.BaseEncoding;
import com.google.tca.domain.CallerIdentity;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class OidcAudienceBindingValidatorTest {
  private OidcAudienceBindingValidator validator;
  private KeyPair keyPair;

  @Before
  public void setUp() throws Exception {
    validator = new OidcAudienceBindingValidator("tca.pcit.goog");
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
  }

  @Test
  public void validate_validBinding_succeeds() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience = "https://tca.pcit.goog/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    // Should not throw or log errors (can't easily check logs here but at least doesn't crash)
    validator.validate(keyPair.getPublic(), callerIdentity);
  }

  @Test
  public void validate_mismatchedBinding_logsError() throws Exception {
    String audience = "https://tca.pcit.goog/v1/certificates:issue?pubkey_sha256=wrong-digest";
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    // Should not throw, but logs error
    // TODO: SHould throw here after update
    validator.validate(keyPair.getPublic(), callerIdentity);
  }

  @Test
  public void validate_missingBinding_logsError() throws Exception {
    CallerIdentity callerIdentity =
        new CallerIdentity("issuer", "subject", Set.of("other-audience"));

    // Should not throw, but logs error
    // TODO: Should throw here after update
    validator.validate(keyPair.getPublic(), callerIdentity);
  }

  @Test
  public void validate_multipleAudiences_oneValid_succeeds() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String validAudience = "https://tca.pcit.goog/v1/certificates:issue?pubkey_sha256=" + digest;
    String invalidAudience =
        "https://tca.pcit.goog/v1/certificates:issue?pubkey_sha256=wrong-digest";
    // Using a set that might return invalidAudience first
    CallerIdentity callerIdentity =
        new CallerIdentity("issuer", "subject", Set.of(invalidAudience, validAudience));

    validator.validate(keyPair.getPublic(), callerIdentity);
  }

  private String computeDigest(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(data);
    return BaseEncoding.base16().lowerCase().encode(hash);
  }
}
