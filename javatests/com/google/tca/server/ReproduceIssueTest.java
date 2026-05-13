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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.util.Modules;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.tca.adapters.PolicyBucket;
import com.google.tca.domain.TimeProvider;
import com.linecorp.armeria.client.WebClient;
import com.linecorp.armeria.common.AggregatedHttpResponse;
import com.linecorp.armeria.common.HttpData;
import com.linecorp.armeria.common.HttpMethod;
import com.linecorp.armeria.common.HttpRequest;
import com.linecorp.armeria.common.HttpStatus;
import com.linecorp.armeria.common.RequestHeaders;
import com.linecorp.armeria.server.Server;
import io.jsonwebtoken.Locator;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import software.amazon.awssdk.services.s3.S3Client;

@RunWith(JUnit4.class)
public class ReproduceIssueTest {

  private static Server server;
  private static WebClient client;

  @BeforeClass
  public static void beforeClass() throws Exception {
    Injector injector =
        Guice.createInjector(
            Modules.override(new TrustedCaModule(), new LocalModeModule(new LocalArgs()))
                .with(
                    new AbstractModule() {
                      @Override
                      protected void configure() {
                        bind(String.class)
                            .annotatedWith(PolicyBucket.class)
                            .toInstance("test-bucket");
                        bind(S3Client.class).toInstance(mock(S3Client.class));
                        bind(TimeProvider.class).toInstance(mock(TimeProvider.class));
                        bind(MeasurementBoundCertificate.class)
                            .toInstance(mock(MeasurementBoundCertificate.class));
                        bind(X509Certificate.class).toInstance(mock(X509Certificate.class));
                        bind(PrivateKey.class).toInstance(mock(PrivateKey.class));
                        bind(new com.google.inject.TypeLiteral<Locator<Key>>() {})
                            .annotatedWith(JwtAuth.class)
                            .toInstance(header -> mock(Key.class));
                      }
                    }));

    int port = 0; // random port
    TrustedCertificateAuthorityGrpcHandler service =
        injector.getInstance(TrustedCertificateAuthorityGrpcHandler.class);
    JwtInterceptor jwtInterceptor = injector.getInstance(JwtInterceptor.class);
    server = new TcaServer(port, service, jwtInterceptor).getServer();
    server.start().join();
    client = WebClient.of("http://127.0.0.1:" + server.activeLocalPort());
  }

  @AfterClass
  public static void afterClass() {
    if (server != null) {
      server.stop().join();
    }
  }

  @Test
  public void reproduceJsonParseExceptionWithNullByte() {
    // We want to reproduce:
    // com.fasterxml.jackson.core.JsonParseException: Illegal unquoted character ((CTRL-CHAR, code
    // 0)): has to be escaped using backslash to be included in string value
    // around column: 31465

    StringBuilder sb = new StringBuilder();
    sb.append(
        "{\"attestation_evidence\": {\"gcp_attestation_evidence\": {\"attestation_token\": \"");
    for (int i = 0; i < 1000; i++) {
      sb.append("a");
    }
    sb.append("\0"); // Null byte
    sb.append("rest_of_token\"}}}");

    byte[] jsonBytes = sb.toString().getBytes();

    AggregatedHttpResponse res =
        client
            .execute(
                HttpRequest.of(
                    RequestHeaders.of(
                        HttpMethod.POST,
                        "/v1/certificates:issue",
                        "content-type",
                        "application/json"),
                    HttpData.wrap(jsonBytes)))
            .aggregate()
            .join();

    // The server rejects the request with a 400 Bad Request due to the Jackson parse error.
    // The Armeria default response body for 400 is "Status: 400\nDescription: Bad Request",
    // while the actual exception is logged by our new decorator.
    assertThat(res.status()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  @Test
  public void reproduceJsonParseExceptionWithControlChar4AndLargeBody() {
    // We want to reproduce:
    // com.fasterxml.jackson.core.JsonParseException: Illegal unquoted character ((CTRL-CHAR, code
    // 4)): has to be escaped using backslash to be included in string value

    StringBuilder sb = new StringBuilder();
    sb.append(
        "{\"attestation_evidence\": {\"gcp_attestation_evidence\": {\"attestation_token\": \"");
    for (int i = 0; i < 50000; i++) {
      sb.append("a");
    }
    sb.append((char) 4); // CTRL-CHAR, code 4
    sb.append("rest_of_token\"}}}");

    byte[] jsonBytes = sb.toString().getBytes();

    AggregatedHttpResponse res =
        client
            .execute(
                HttpRequest.of(
                    RequestHeaders.of(
                        HttpMethod.POST,
                        "/v1/certificates:issue",
                        "content-type",
                        "application/json"),
                    HttpData.wrap(jsonBytes)))
            .aggregate()
            .join();

    assertThat(res.status()).isEqualTo(HttpStatus.BAD_REQUEST);
  }
}
