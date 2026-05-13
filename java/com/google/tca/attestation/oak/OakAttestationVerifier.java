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

package com.google.tca.attestation.oak;

import com.google.common.flogger.FluentLogger;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.oak.attestation.v1.AttestationResults;
import com.google.tca.adapters.OakAttestationEvidence;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;

/** Verifies attestation evidence from Oak components using a native Rust library. */
public class OakAttestationVerifier implements AttestationVerifier {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  public static final String OAK_SIGNING_PUBLIC_KEY_ECDSA_P_256 =
      "oak-signing-public-key:ecdsa-p256";

  /** Exception thrown when attestation verification fails. */
  public static class AttestationVerificationException extends Exception {
    public AttestationVerificationException(String message) {
      super(message);
    }
  }

  private final OakEvidenceVerifier oakEvidenceVerifier;
  private final TimeProvider timeProvider;

  @Inject
  public OakAttestationVerifier(
      OakEvidenceVerifier oakEvidenceVerifier, TimeProvider timeProvider) {
    this.oakEvidenceVerifier = oakEvidenceVerifier;
    this.timeProvider = timeProvider;
  }

  /**
   * Verifies the provided attestation evidence.
   *
   * @param evidence The attestation evidence to verify. Must be an instance of {@link
   *     OakAttestationEvidence}.
   * @param claimedPublicKey The public key embedded in the CSR.
   * @return true if verification is successful, or false if verification fails.
   * @throws IllegalArgumentException if the evidence is not of type {@link OakAttestationEvidence}.
   */
  @Override
  public boolean verify(
      AttestationEvidence evidence,
      PublicKey claimedPublicKey,
      com.google.tca.domain.policy.ReferenceValues referenceValues) {
    OakAttestationEvidence oakEvidence = (OakAttestationEvidence) evidence;

    logger.atInfo().log("Verification of Oak evidence ");

    try {

      AttestationResults results =
          oakEvidenceVerifier.verify(
              timeProvider.currentTimeMillis(),
              oakEvidence.getEvidence().toByteArray(),
              oakEvidence.getEndorsements().toByteArray(),
              referenceValues.toByteArray());

      verifyBinding(results, oakEvidence.getSignedPublicKey().toByteArray(), claimedPublicKey);

      return true;
    } catch (AttestationVerificationException | GeneralSecurityException e) {
      logger.atWarning().withCause(e).log("Attestation verification failed");
      return false;
    }
  }

  private void verifyBinding(
      AttestationResults results, byte[] signedPublicKey, PublicKey claimedPublicKey)
      throws AttestationVerificationException, GeneralSecurityException {
    List<byte[]> instanceSigningKeys =
        results.getEventAttestationResultsList().stream()
            .flatMap(ear -> ear.getArtifactsMap().entrySet().stream())
            .filter(entry -> entry.getKey().equals(OAK_SIGNING_PUBLIC_KEY_ECDSA_P_256))
            .map(entry -> entry.getValue().toByteArray())
            .toList();

    if (instanceSigningKeys.size() != 1) {
      throw new AttestationVerificationException(
          String.format(
              "Attestation results must contain exactly one signing public key, but found %d",
              instanceSigningKeys.size()));
    }

    PublicKey instanceSigningKey = decodeEcPublicKey(instanceSigningKeys.get(0));

    // The instance signing key is ECDSA, and the original Oak implementation in Rust
    // generates signatures in P1363 format (raw r|s), so we must use the corresponding
    // algorithm in Java.
    Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
    signature.initVerify(instanceSigningKey);
    signature.update(claimedPublicKey.getEncoded());

    if (!signature.verify(signedPublicKey)) {
      throw new AttestationVerificationException(
          "CSR public key binding verification failed: Invalid signature.");
    }
  }

  private PublicKey decodeEcPublicKey(byte[] keyBytes) throws GeneralSecurityException {
    return EllipticCurves.getEcPublicKey(
        EllipticCurves.CurveType.NIST_P256, EllipticCurves.PointFormatType.UNCOMPRESSED, keyBytes);
  }
}
