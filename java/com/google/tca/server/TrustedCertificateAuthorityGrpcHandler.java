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

package com.google.tca.server;

import com.google.tca.v1.IssueCertificateRequest;
import com.google.tca.v1.IssueCertificateResponse;
import com.google.tca.v1.TrustedCertificateAuthorityGrpc.TrustedCertificateAuthorityImplBase;
import io.grpc.stub.StreamObserver;
import jakarta.inject.Inject;

/**
 * gRPC handler for the deprecated TrustedCertificateAuthority service. Delegates all calls directly
 * to the TransparentCertificateAuthorityGrpcHandler to ensure a zero-downtime transition period.
 */
@Deprecated
public class TrustedCertificateAuthorityGrpcHandler extends TrustedCertificateAuthorityImplBase {
  private final TransparentCertificateAuthorityGrpcHandler delegate;

  @Inject
  public TrustedCertificateAuthorityGrpcHandler(
      TransparentCertificateAuthorityGrpcHandler delegate) {
    this.delegate = delegate;
  }

  @Override
  public void issueCertificate(
      IssueCertificateRequest request, StreamObserver<IssueCertificateResponse> responseObserver) {
    delegate.issueCertificate(request, responseObserver);
  }
}
