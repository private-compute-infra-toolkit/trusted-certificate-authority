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

import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.FluentLogger;
import com.google.tca.adapters.GcpAttestationEvidence;
import com.google.tca.adapters.oidc.OidcJwksKeyFetcher;
import com.google.tca.domain.KeyDecoder;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.policy.ReferenceValues;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.inject.Inject;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Verifier for GCP attestation tokens. */
public final class GcpAttestationVerifier implements AttestationVerifier {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final String GCP_ISSUER = "https://confidentialcomputing.googleapis.com";
  private static final String GCP_ORIGIN_PREFIX = "gcp:projects/";
  public static final String JWKS_URI =
      "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";

  private final JwtParser jwtParser;
  private final KeyDecoder keyDecoder;

  @Inject
  GcpAttestationVerifier(@GcpAttestation OidcJwksKeyFetcher keyFetcher, KeyDecoder keyDecoder) {
    this.jwtParser =
        Jwts.parser().setSigningKeyResolver(new GcpSigningKeyResolver(keyFetcher)).build();
    this.keyDecoder = keyDecoder;
  }

  /**
   * Verifies a GCP attestation evidence.
   *
   * @param evidence the attestation evidence to verify.
   * @param claimedPublicKey the public key embedded in the CSR.
   * @return true if the token is valid, otherwise false.
   */
  @Override
  public boolean verify(
      AttestationEvidence evidence, PublicKey claimedPublicKey, ReferenceValues unused) {
    GcpAttestationEvidence gcpEvidence = (GcpAttestationEvidence) evidence;
    if (gcpEvidence == null) {
      return false;
    }
    return verify(gcpEvidence.getAttestationToken().toStringUtf8(), claimedPublicKey);
  }

  /**
   * Verifies a GCP attestation token.
   *
   * @param token the attestation token to verify.
   * @param claimedPublicKey the public key embedded in the CSR.
   * @return true if the token is valid, otherwise false.
   */
  public boolean verify(String token, PublicKey claimedPublicKey) {
    try {
      Jws<Claims> jws = jwtParser.parseClaimsJws(token);

      Claims claims = jws.getBody();
      if (!GCP_ISSUER.equals(claims.getIssuer())) {
        logger.atWarning().log("Invalid issuer: %s", claims.getIssuer());
        return false;
      }

      // The "eat_nonce" claim is expected to be a list of strings.
      // These strings are chunks of the Base64 encoded DER-serialized SubjectPublicKeyInfo
      // of the public key. Each chunk must be between 8 and 88 characters long to satisfy
      // GCP's nonce constraints. The verifier concatenates these chunks to rebuild the
      // original Base64 string before decoding.
      List<String> nonces = claims.get("eat_nonce", List.class);
      if (nonces == null || nonces.isEmpty()) {
        logger.atWarning().log("Nonce list cannot be null or empty.");
        return false;
      }

      // Concatenate all nonce strings to reassemble the full Base64 encoded key.
      String combinedBase64Key = String.join("", nonces);

      PublicKey publicKey = keyDecoder.decodeBase64PublicKey(combinedBase64Key);

      if (!publicKey.equals(claimedPublicKey)) {
        logger.atWarning().log(
            "Key binding mismatch. Token key: %s, Expected key: %s", publicKey, claimedPublicKey);
        return false;
      }

      Object submodsRaw = claims.get("submods");
      if (!(submodsRaw instanceof Map)) {
        throw new IllegalArgumentException("Invalid attestation token: missing submods.");
      }

      Map<String, Object> submodsMap = (Map<String, Object>) submodsRaw;

      Map<String, Object> gceMap =
          Optional.ofNullable(submodsMap.get("gce"))
              .filter(Map.class::isInstance)
              .map(m -> (Map<String, Object>) m)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          "Invalid attestation token: missing or invalid 'gce' map."));

      String projectId = getRequiredString(gceMap, "project_id");
      String instanceId = getRequiredString(gceMap, "instance_id");
      String instanceName = getRequiredString(gceMap, "instance_name");
      String zone = getRequiredString(gceMap, "zone");

      String origin = GCP_ORIGIN_PREFIX + projectId;

      ImmutableMap<String, String> metadata =
          ImmutableMap.of(
              "gcp_instance_id", instanceId, "gcp_instance_name", instanceName, "gcp_zone", zone);

      Map<String, Object> containerMap =
          Optional.ofNullable(submodsMap.get("container"))
              .filter(Map.class::isInstance)
              .map(m -> (Map<String, Object>) m)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          "Invalid attestation token: missing or invalid 'container' map."));

      String imageDigest = getRequiredString(containerMap, "image_digest");

      return true;
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to verify attestation token.");
      return false;
    }
  }

  private static String getRequiredString(Map<String, Object> map, String key) {
    return Optional.ofNullable(map.get(key))
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Invalid attestation token: missing or invalid '" + key + "' in 'gce' map."));
  }
}
