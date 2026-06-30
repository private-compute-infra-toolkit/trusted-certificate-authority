/*
 * Copyright 2026 Google LLC
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

package com.google.tca.server;

import com.google.common.flogger.FluentLogger;
import com.google.protobuf.ByteString;
import com.google.tca.adapters.CertificateIssuanceRequestMapper;
import com.google.tca.domain.AudienceValidationException;
import com.google.tca.domain.CallerIdentity;
import com.google.tca.domain.CertificateIssuanceRequest;
import com.google.tca.domain.TransparentCaService;
import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.v1.IssueCertificateRequest;
import com.google.tca.v1.IssueCertificateResponse;
import com.google.tca.v1.TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityImplBase;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import jakarta.inject.Inject;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

public class TransparentCertificateAuthorityGrpcHandler
    extends TransparentCertificateAuthorityImplBase {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final TransparentCaService transparentCaService;
  private final Metrics metrics;

  @Inject
  public TransparentCertificateAuthorityGrpcHandler(
      TransparentCaService transparentCaService, Metrics metrics) {
    this.transparentCaService = transparentCaService;
    this.metrics = metrics;
  }

  @Override
  public void issueCertificate(
      IssueCertificateRequest request, StreamObserver<IssueCertificateResponse> responseObserver) {
    String issuer = JwtInterceptor.ISSUER_CONTEXT_KEY.get();
    String subject = JwtInterceptor.SUBJECT_CONTEXT_KEY.get();
    Set<String> audiences = JwtInterceptor.AUDIENCE_CONTEXT_KEY.get();

    if (issuer == null || subject == null || audiences == null) {
      responseObserver.onError(
          Status.UNAUTHENTICATED.withDescription("Missing JWT token").asRuntimeException());
      return;
    }

    CallerIdentity callerIdentity = new CallerIdentity(issuer, subject, audiences);
    CertificateIssuanceRequest domainRequest;
    try {
      domainRequest = CertificateIssuanceRequestMapper.toDomain(request);
    } catch (IllegalArgumentException e) {
      logger.atWarning().log("Invalid request: %s", e.getMessage());
      metrics.incrementProcessingCounter(ProcessingStatus.INVALID_EVIDENCE);
      responseObserver.onError(
          Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
      return;
    }

    try {
      logger.atInfo().log(
          "Received a request with evidence of type %s",
          request.getAttestationEvidence().getEvidenceCase());

      List<X509Certificate> certificateChain =
          transparentCaService.issueCertificate(domainRequest, callerIdentity);

      IssueCertificateResponse.Builder responseBuilder = IssueCertificateResponse.newBuilder();
      for (X509Certificate cert : certificateChain) {
        responseBuilder.addSignedCertificates(ByteString.copyFrom(cert.getEncoded()));
      }
      IssueCertificateResponse response = responseBuilder.build();

      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (AudienceValidationException e) {
      logger.atWarning().log("Audience validation failed: %s", e.getMessage());
      responseObserver.onError(
          Status.PERMISSION_DENIED.withDescription(e.getMessage()).asRuntimeException());
    } catch (IllegalArgumentException e) {
      logger.atWarning().log("Illegal argument during validation: %s", e.getMessage());
      responseObserver.onError(
          Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
    } catch (IllegalStateException e) {
      responseObserver.onError(
          Status.FAILED_PRECONDITION.withDescription(e.getMessage()).asRuntimeException());
    } catch (IOException e) {
      // A bad CSR leads to an IOException during parsing. This is a client error.
      logger.atWarning().log("Failed to parse CSR: %s.", e.getMessage());
      responseObserver.onError(
          Status.INVALID_ARGUMENT.withDescription("Invalid CSR").asRuntimeException());
    } catch (CertificateException e) {
      // A signing error is an internal server error.
      logger.atSevere().withCause(e).log("Failed to sign certificate");
      responseObserver.onError(
          Status.INTERNAL.withDescription("Failed to sign certificate").asRuntimeException());
    }
  }
}
