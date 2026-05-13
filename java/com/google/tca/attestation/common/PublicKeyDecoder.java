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

package com.google.tca.attestation.common;

import com.google.common.flogger.FluentLogger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for decoding public keys from attestation nonces. Expects keys to be DER-encoded
 * SubjectPublicKeyInfo (X.509) for an RSA key, then Base64 encoded.
 */
public final class PublicKeyDecoder {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  /**
   * Decodes a base64 encoded string containing a DER-encoded RSA SubjectPublicKeyInfo.
   *
   * @param base64PublicKey The base64 encoded public key.
   * @return An RSAPublicKey object.
   * @throws Exception if decoding or key generation fails, or if the key is not RSA.
   */
  public static PublicKey decodeBase64PublicKey(String base64PublicKey) {
    byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
    return decodeRawPublicKey(keyBytes);
  }

  /**
   * Decodes raw bytes representing a DER-encoded RSA SubjectPublicKeyInfo.
   *
   * @param keyBytes The raw public key bytes.
   * @return An RSAPublicKey object.
   * @throws Exception if decoding or key generation fails, or if the key is not RSA.
   */
  public static PublicKey decodeRawPublicKey(byte[] keyBytes) {
    if (keyBytes == null || keyBytes.length == 0) {
      throw new IllegalArgumentException("Public key bytes cannot be null or empty.");
    }
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
    logger.atFine().log(
        "KeySpec algorithm: %s, format: %s", keySpec.getAlgorithm(), keySpec.getFormat());

    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePublic(keySpec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException rsaException) {
      throw new IllegalArgumentException("Failed to decode public key as RSA.", rsaException);
    }
  }

  private PublicKeyDecoder() {}
}
