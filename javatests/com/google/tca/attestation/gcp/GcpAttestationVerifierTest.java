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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import com.google.tca.adapters.GcpAttestationEvidence;
import com.google.tca.adapters.KeyDecoderImpl;
import com.google.tca.adapters.oidc.OidcJwksKeyFetcher;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.policy.ReferenceValues;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class GcpAttestationVerifierTest {
  private static final String TEST_PROJECT_ID = "test-project";
  private static final String TEST_INSTANCE_ID = "test-instance";
  private static final String TEST_INSTANCE_NAME = "test-instance-name";
  private static final String TEST_ZONE = "test-zone";
  private static final String TEST_KEY_ID = "test-key-id";
  private static final String TEST_NONCE = "test-nonce";
  private static final String TEST_IMAGE_DIGEST =
      "sha256:58ddcf75918a7f9d8b86bcf1df084f626c44eda2dfc1b7638e5e3cbbe515a984";

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  private KeyPair keyPair;
  private GcpAttestationVerifier verifier;
  private final ReferenceValues unused = null;

  @Mock private OidcJwksKeyFetcher mockKeyFetcher;

  @Before
  public void setUp() throws NoSuchAlgorithmException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    keyPair = keyGen.generateKeyPair();
    verifier = new GcpAttestationVerifier(mockKeyFetcher, new KeyDecoderImpl());
  }

  @Test
  public void verify_validToken_returnsIdentity() {
    when(mockKeyFetcher.getKey(TEST_KEY_ID)).thenReturn(Optional.of(keyPair.getPublic()));

    byte[] publicKeyDer = keyPair.getPublic().getEncoded();
    String publicKeyB64 = Base64.getEncoder().encodeToString(publicKeyDer);
    List<String> nonceChunks = chunkString(publicKeyB64, 80);

    String jwt =
        Jwts.builder()
            .setHeaderParam("kid", TEST_KEY_ID)
            .setIssuer("https://confidentialcomputing.googleapis.com")
            .claim("eat_nonce", nonceChunks)
            .claim(
                "submods",
                Map.of(
                    "gce",
                    Map.of(
                        "project_id",
                        TEST_PROJECT_ID,
                        "instance_id",
                        TEST_INSTANCE_ID,
                        "instance_name",
                        TEST_INSTANCE_NAME,
                        "zone",
                        TEST_ZONE),
                    "container",
                    Map.of("image_digest", TEST_IMAGE_DIGEST)))
            .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
            .compact();

    boolean success = verifier.verify(createGcpEvidence(jwt), keyPair.getPublic(), unused);

    assertThat(success).isTrue();
  }

  @Test
  public void verify_invalidIssuer_returnsEmpty() {
    when(mockKeyFetcher.getKey(TEST_KEY_ID)).thenReturn(Optional.of(keyPair.getPublic()));
    String jwt =
        Jwts.builder()
            .setHeaderParam("kid", TEST_KEY_ID)
            .setIssuer("https://example.com")
            .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
            .compact();

    boolean success = verifier.verify(createGcpEvidence(jwt), keyPair.getPublic(), unused);

    assertThat(success).isFalse();
  }

  @Test
  public void verify_submodsNotMap_returnsEmpty() {
    when(mockKeyFetcher.getKey(TEST_KEY_ID)).thenReturn(Optional.of(keyPair.getPublic()));
    String jwt =
        Jwts.builder()
            .setHeaderParam("kid", TEST_KEY_ID)
            .setIssuer("https://confidentialcomputing.googleapis.com")
            .claim("submods", "a string")
            .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
            .compact();

    boolean success = verifier.verify(createGcpEvidence(jwt), keyPair.getPublic(), unused);

    assertThat(success).isFalse();
  }

  @Test
  public void verify_keyMismatch_returnsEmpty() {
    when(mockKeyFetcher.getKey(TEST_KEY_ID)).thenReturn(Optional.of(keyPair.getPublic()));

    // Create a token signed with the correct key, but we will pass a different key as "expected".
    byte[] publicKeyDer = keyPair.getPublic().getEncoded();
    String publicKeyB64 = Base64.getEncoder().encodeToString(publicKeyDer);
    List<String> nonceChunks = chunkString(publicKeyB64, 80);

    String jwt =
        Jwts.builder()
            .setHeaderParam("kid", TEST_KEY_ID)
            .setIssuer("https://confidentialcomputing.googleapis.com")
            .claim("eat_nonce", nonceChunks)
            .claim(
                "submods",
                Map.of(
                    "gce",
                    Map.of(
                        "project_id", TEST_PROJECT_ID,
                        "instance_id", TEST_INSTANCE_ID,
                        "instance_name", TEST_INSTANCE_NAME,
                        "zone", TEST_ZONE),
                    "container",
                    Map.of("image_digest", TEST_IMAGE_DIGEST)))
            .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
            .compact();

    // Generate a different key to pass as "expected"
    KeyPair otherKeyPair;
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      otherKeyPair = keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    boolean success = verifier.verify(createGcpEvidence(jwt), otherKeyPair.getPublic(), unused);

    assertThat(success).isFalse();
  }

  private AttestationEvidence createGcpEvidence(String token) {
    return GcpAttestationEvidence.create(ByteString.copyFromUtf8(token));
  }

  private List<String> chunkString(String str, int chunkSize) {
    List<String> chunks = new ArrayList<>();
    for (int i = 0; i < str.length(); i += chunkSize) {
      chunks.add(str.substring(i, Math.min(str.length(), i + chunkSize)));
    }
    return chunks;
  }
}
