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

package com.google.tca.domain;

import static com.google.common.collect.Comparators.max;
import static com.google.common.collect.Comparators.min;

import com.google.common.flogger.FluentLogger;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.attestation.AttestationVerifierProvider;
import com.google.tca.domain.attestation.EndorsementAnnotations;
import com.google.tca.domain.attestation.Validity;
import com.google.tca.domain.policy.BasicConstraintsType;
import com.google.tca.domain.policy.Policy;
import jakarta.inject.Inject;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class TrustedCaService {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private final X509Certificate rootCertificate;
  private final PrivateKey privateKey;
  private final AttestationVerifierProvider verifierProvider;
  private final CertificateSigner certificateSigner;
  private final KeyDecoder keyDecoder;
  private final PolicyProvider policyProvider;
  private final TimeProvider timeProvider;
  private final EndorsementMetadataProvider endorsementMetadataProvider;
  private final CertificateModifiersCreator certificateModifiersCreator;
  private final AudienceBindingValidator audienceBindingValidator;

  @Inject
  public TrustedCaService(
      X509Certificate rootCertificate,
      PrivateKey privateKey,
      AttestationVerifierProvider verifierProvider,
      CertificateSigner certificateSigner,
      KeyDecoder keyDecoder,
      PolicyProvider policyProvider,
      TimeProvider timeProvider,
      EndorsementMetadataProvider endorsementMetadataProvider,
      CertificateModifiersCreator certificateModifiersCreator,
      AudienceBindingValidator audienceBindingValidator) {
    this.rootCertificate = rootCertificate;
    this.privateKey = privateKey;
    this.verifierProvider = verifierProvider;
    this.certificateSigner = certificateSigner;
    this.keyDecoder = keyDecoder;
    this.policyProvider = policyProvider;
    this.timeProvider = timeProvider;
    this.endorsementMetadataProvider = endorsementMetadataProvider;
    this.certificateModifiersCreator = certificateModifiersCreator;
    this.audienceBindingValidator = audienceBindingValidator;
  }

  public X509Certificate issueCertificate(
      CertificateIssuanceRequest request, CallerIdentity callerIdentity)
      throws java.io.IOException, CertificateException {
    PublicKey csrPublicKey = extractPublicKey(request);
    audienceBindingValidator.validate(csrPublicKey, callerIdentity);
    AttestationEvidence evidence = request.getAttestationEvidence();
    EndorsementAnnotations annotations =
        endorsementMetadataProvider.getAnnotations(evidence.getRawBinaryEndorsement());
    Validity validity = endorsementMetadataProvider.getValidity(evidence.getRawBinaryEndorsement());
    Optional<Policy> policyOpt =
        policyProvider.getPolicy(
            callerIdentity, annotations.publisherId(), annotations.workloadId());
    if (policyOpt.isEmpty()) {
      throw new IllegalArgumentException(
          String.format(
              "No policy supports requested workload: {clientId = %s, publisherId = %s,"
                  + " workloadId = %s}",
              callerIdentity.getClientId(), annotations.publisherId(), annotations.workloadId()));
    }
    Policy policy = policyOpt.get();

    Optional<AttestationVerifier> verifierOpt = verifierProvider.getVerifier(evidence);
    if (verifierOpt.isEmpty()) {
      throw new IllegalArgumentException("Unsupported attestation platform");
    }
    AttestationVerifier verifier = verifierOpt.get();

    boolean hasBeenVerified =
        policy.referenceValuesList().stream()
            .filter(rv -> rv.type() == evidence.getReferenceValuesType())
            .anyMatch(rv -> verifier.verify(evidence, csrPublicKey, rv));

    if (!hasBeenVerified) {
      throw new IllegalArgumentException("Attestation token is not valid");
    }

    // Determine certificate validity
    Instant now = timeProvider.now();
    Instant expiration = now.plus(policy.certificateAttributes().maxCertificateValidity());
    Instant certificateValidityEnd = min(expiration, validity.notAfter());
    Instant certificateValidityStart = max(now, validity.notBefore());

    if (certificateValidityStart.isAfter(certificateValidityEnd)) {
      throw new IllegalArgumentException("Incorrect certificate validity");
    }

    List<CertificateModifier> modifiers = certificateModifiersCreator.create(policy);
    boolean isCa =
        policy
            .certificateAttributes()
            .extensions()
            .basicConstraints()
            .map(bc -> bc.type() == BasicConstraintsType.CA)
            .orElse(false);
    return certificateSigner.signCsr(
        request.getCertificateSigningRequest().toByteArray(),
        rootCertificate,
        privateKey,
        certificateValidityStart,
        certificateValidityEnd,
        modifiers,
        isCa);
  }

  private PublicKey extractPublicKey(CertificateIssuanceRequest request) throws IOException {
    PKCS10CertificationRequest csr =
        new PKCS10CertificationRequest(request.getCertificateSigningRequest().toByteArray());
    byte[] csrPublicKeyBytes = csr.getSubjectPublicKeyInfo().getEncoded();
    return keyDecoder.decodeRawPublicKey(csrPublicKeyBytes);
  }
}
