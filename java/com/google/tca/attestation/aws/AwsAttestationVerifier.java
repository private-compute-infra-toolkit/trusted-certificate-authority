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

package com.google.tca.attestation.aws;

import COSE.CoseException;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.FluentLogger;
import com.google.common.io.BaseEncoding;
import com.google.tca.adapters.AwsAttestationEvidence;
import com.google.tca.domain.KeyDecoder;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.policy.ReferenceValues;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Attestation verifier for AWS Nitro Enclaves. */
public class AwsAttestationVerifier implements AttestationVerifier {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final String AWS_NITRO_ENCLAVES_ROOT_CERT_PATH =
      "com/google/tca/attestation/aws/res/AWS_NitroEnclaves_Root-G1.pem";
  private final X509Certificate rootCertificate;
  private final TrustAnchor trustAnchor;
  private final CertificateFactory certFactory;
  private final Optional<Instant> validationDateOverride;
  private final KeyDecoder keyDecoder;

  @Inject
  public AwsAttestationVerifier(KeyDecoder keyDecoder) {
    this(Optional.empty(), keyDecoder);
  }

  // Constructor for testing to allow overriding the validation date
  AwsAttestationVerifier(Instant validationDateOverride, KeyDecoder keyDecoder) {
    this(Optional.of(validationDateOverride), keyDecoder);
  }

  private AwsAttestationVerifier(Optional<Instant> validationDateOverride, KeyDecoder keyDecoder) {
    this.rootCertificate = loadRootCertificate();
    this.trustAnchor = new TrustAnchor(rootCertificate, null);
    this.validationDateOverride = validationDateOverride;
    this.keyDecoder = keyDecoder;
    try {
      this.certFactory = CertificateFactory.getInstance("X.509");
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize CertificateFactory", e);
    }
  }

  private X509Certificate loadRootCertificate() {
    try (InputStream certInputStream =
        getClass().getClassLoader().getResourceAsStream(AWS_NITRO_ENCLAVES_ROOT_CERT_PATH)) {
      if (certInputStream == null) {
        throw new RuntimeException(
            "Could not find AWS root certificate: " + AWS_NITRO_ENCLAVES_ROOT_CERT_PATH);
      }
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      return (X509Certificate) certFactory.generateCertificate(certInputStream);
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Failed to load AWS root certificate.");
      throw new RuntimeException("Failed to load AWS root certificate.", e);
    }
  }

  private X509Certificate bytesToCertificate(byte[] certBytes) {
    try {
      return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
    } catch (Exception e) {
      throw new RuntimeException("Failed to parse certificate from bytes", e);
    }
  }

  private void validateCertificateChain(List<X509Certificate> chain) {
    try {
      logger.atFine().log("Validating certificate chain with %d certs.", chain.size());
      CertPath certPath = certFactory.generateCertPath(chain);
      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      PKIXParameters params = new PKIXParameters(Collections.singleton(trustAnchor));
      params.setRevocationEnabled(false); // Revocation checking is not implemented here
      validationDateOverride.ifPresent(
          instant -> {
            logger.atFine().log("Setting validation date override: %s.", instant);
            params.setDate(java.util.Date.from(instant));
          });
      validator.validate(certPath, params);
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Certificate chain validation failed.");
      throw new RuntimeException("Certificate chain validation failed.", e);
    }
  }

  /**
   * Verifies an AWS Nitro Enclaves attestation evidence.
   *
   * @param evidence The attestation evidence to verify.
   * @param claimedPublicKey The public key embedded in the CSR.
   * @return true if the document is valid, or false otherwise.
   */
  @Override
  public boolean verify(
      AttestationEvidence evidence, PublicKey claimedPublicKey, ReferenceValues unused) {
    AwsAttestationEvidence awsEvidence = (AwsAttestationEvidence) evidence;
    if (awsEvidence == null) {
      return false;
    }
    return verify(awsEvidence.getAttestationToken().toStringUtf8(), claimedPublicKey);
  }

  /**
   * Verifies an AWS Nitro Enclaves attestation document.
   *
   * @param token The base64-encoded attestation document.
   * @param claimedPublicKey The public key embedded in the CSR.
   * @return true if the document is valid, or false otherwise.
   */
  public boolean verify(String token, PublicKey claimedPublicKey) {
    try {
      byte[] attestationDocument = Base64.getDecoder().decode(token);
      Sign1Message sign1Message =
          (Sign1Message) Sign1Message.DecodeFromBytes(attestationDocument, MessageTag.Sign1);

      byte[] payload = sign1Message.GetContent();
      CBORObject payloadCbor = CBORObject.DecodeFromBytes(payload);

      // Extract certificates from payload
      byte[] leafCertBytes = payloadCbor.get("certificate").GetByteString();
      X509Certificate leafCert = bytesToCertificate(leafCertBytes);

      CBORObject caBundleCbor = payloadCbor.get("cabundle");
      List<X509Certificate> chain = new ArrayList<>();
      chain.add(leafCert); // Target first

      if (caBundleCbor != null && caBundleCbor.getType() == CBORType.Array) {
        List<X509Certificate> intermediates = new ArrayList<>();
        for (int i = 0; i < caBundleCbor.getValues().size(); i++) {
          X509Certificate cert = bytesToCertificate(caBundleCbor.get(i).GetByteString());
          // Exclude the root from the chain to be validated
          if (!cert.getSubjectX500Principal().equals(rootCertificate.getSubjectX500Principal())) {
            intermediates.add(cert);
          }
        }
        // The cabundle is ordered from root to intermediate. For CertPathValidator, the order
        // must be from target to intermediate, so we reverse the list of intermediates.
        Collections.reverse(intermediates);
        chain.addAll(intermediates);
      }

      validateCertificateChain(chain);

      PublicKey signerPublicKey = leafCert.getPublicKey();
      OneKey coseKey = new OneKey(signerPublicKey, null);

      if (!sign1Message.validate(coseKey)) {
        logger.atWarning().log("Attestation document signature verification failed.");
        return false;
      }

      // Extract claims
      CBORObject moduleIdCbor = payloadCbor.get("module_id");
      String moduleId = moduleIdCbor.AsString();

      Map<String, String> pcrs = new HashMap<>();
      CBORObject pcrMap = payloadCbor.get("pcrs");
      for (CBORObject key : pcrMap.getKeys()) {
        pcrs.put(
            key.toString(),
            BaseEncoding.base16().lowerCase().encode(pcrMap.get(key).GetByteString()));
      }

      String pcr0 = pcrs.get("0");
      if (pcr0 == null) {
        logger.atWarning().log("PCR0 not found in attestation document.");
        return false;
      }

      CBORObject publicKeyCbor = payloadCbor.get("public_key");
      byte[] publicKeyBytes = null;
      if (publicKeyCbor != null && publicKeyCbor.getType() == CBORType.ByteString) {
        publicKeyBytes = publicKeyCbor.GetByteString();
      }
      if (publicKeyBytes == null) {
        logger.atWarning().log("Public key not found in attestation document.");
        return false;
      }
      PublicKey enclavePublicKey = keyDecoder.decodeRawPublicKey(publicKeyBytes);

      if (!enclavePublicKey.equals(claimedPublicKey)) {
        logger.atWarning().log(
            "Key binding mismatch. Enclave key: %s, Expected key: %s",
            enclavePublicKey, claimedPublicKey);
        return false;
      }

      CBORObject nonceCbor = payloadCbor.get("nonce");
      byte[] nonce = null;
      if (nonceCbor != null && nonceCbor.getType() == CBORType.ByteString) {
        nonce = nonceCbor.GetByteString();
      }

      ImmutableMap.Builder<String, String> metadata = ImmutableMap.builder();
      metadata.put("moduleId", moduleId);
      metadata.put("pcrs", pcrs.toString());
      if (nonce != null) {
        metadata.put("challengeNonce", BaseEncoding.base16().lowerCase().encode(nonce));
      }
      metadata.put(
          "enclavePublicKey",
          BaseEncoding.base16().lowerCase().encode(enclavePublicKey.getEncoded()));

      return true;

    } catch (CoseException e) {
      logger.atSevere().withCause(e).log("Failed to decode or verify COSE message.");
      return false;
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Error during attestation verification.");
      return false;
    }
  }
}
