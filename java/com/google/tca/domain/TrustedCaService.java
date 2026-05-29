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
import static com.google.tca.domain.metric.ProcessingStatus.INCORRECT_CERTIFICATE_VALIDITY;
import static com.google.tca.domain.metric.ProcessingStatus.INVALID_ATTESTATION_TOKEN;
import static com.google.tca.domain.metric.ProcessingStatus.MISSING_POLICY;
import static com.google.tca.domain.metric.ProcessingStatus.MISSING_VERIFIER;
import static com.google.tca.domain.metric.ProcessingStatus.SUCCESS;

import com.google.common.flogger.FluentLogger;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.attestation.AttestationVerifierProvider;
import com.google.tca.domain.attestation.EndorsementAnnotations;
import com.google.tca.domain.attestation.Validity;
import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.X500NameAttributes;
import jakarta.inject.Inject;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
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
  private final Metrics metrics;

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
      AudienceBindingValidator audienceBindingValidator,
      Metrics metrics) {
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
    this.metrics = metrics;
  }

  public List<X509Certificate> issueCertificate(
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
      metrics.incrementProcessingCounter(MISSING_POLICY);
      throw new IllegalArgumentException(
          String.format(
              "No policy supports requested workload: {clientId = %s, publisherId = %s,"
                  + " workloadId = %s}",
              callerIdentity.getClientId(), annotations.publisherId(), annotations.workloadId()));
    }
    Policy policy = policyOpt.get();

    Optional<AttestationVerifier> verifierOpt = verifierProvider.getVerifier(evidence);
    if (verifierOpt.isEmpty()) {
      metrics.incrementProcessingCounter(MISSING_VERIFIER);
      throw new IllegalArgumentException("Unsupported attestation platform");
    }
    AttestationVerifier verifier = verifierOpt.get();

    boolean hasBeenVerified =
        policy.referenceValuesList().stream()
            .filter(rv -> rv.type() == evidence.getReferenceValuesType())
            .anyMatch(rv -> verifier.verify(evidence, csrPublicKey, rv));

    if (!hasBeenVerified) {
      metrics.incrementProcessingCounter(INVALID_ATTESTATION_TOKEN);
      throw new IllegalArgumentException("Attestation token is not valid");
    }

    // Determine certificate validity
    Instant now = timeProvider.now();
    Instant expiration = now.plus(policy.certificateAttributes().maxCertificateValidity());
    Instant certificateValidityEnd = min(expiration, validity.notAfter());
    Instant certificateValidityStart = max(now, validity.notBefore());

    if (certificateValidityStart.isAfter(certificateValidityEnd)) {
      metrics.incrementProcessingCounter(INCORRECT_CERTIFICATE_VALIDITY);
      throw new IllegalArgumentException("Incorrect certificate validity");
    }

    List<CertificateModifier> modifiers = certificateModifiersCreator.create(policy);
    X509Certificate signedCertificate =
        certificateSigner.signCsr(
            request.getCertificateSigningRequest().toByteArray(),
            rootCertificate,
            privateKey,
            certificateValidityStart,
            certificateValidityEnd,
            modifiers,
            createSubjectPrincipal(policy.certificateAttributes().certificateSubject()));
    metrics.incrementProcessingCounter(SUCCESS);
    return List.of(signedCertificate, rootCertificate);
  }

  private X500Principal createSubjectPrincipal(X500NameAttributes subject) throws IOException {
    X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
    for (Map.Entry<String, String> entry : subject.attributes().entrySet()) {
      subjectBuilder.addRDN(new ASN1ObjectIdentifier(entry.getKey()), entry.getValue());
    }
    return new X500Principal(subjectBuilder.build().getEncoded());
  }

  private PublicKey extractPublicKey(CertificateIssuanceRequest request) throws IOException {
    PKCS10CertificationRequest csr =
        new PKCS10CertificationRequest(request.getCertificateSigningRequest().toByteArray());
    byte[] csrPublicKeyBytes = csr.getSubjectPublicKeyInfo().getEncoded();
    return keyDecoder.decodeRawPublicKey(csrPublicKeyBytes);
  }
}
