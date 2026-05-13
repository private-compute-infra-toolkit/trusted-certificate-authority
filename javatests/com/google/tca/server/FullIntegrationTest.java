/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.server;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.when;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.util.Modules;
import com.google.mbs.MbsCertificateFactory;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.tca.adapters.PolicyBucket;
import com.google.tca.domain.TimeProvider;
import com.google.tca.v1.IssueCertificateRequest;
import com.google.tca.v1.IssueCertificateResponse;
import com.google.tca.v1.TrustedCertificateAuthorityGrpc;
import io.grpc.Metadata;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.grpc.testing.GrpcCleanupRule;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

@RunWith(JUnit4.class)
public class FullIntegrationTest {

  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @Mock private TimeProvider timeProvider;

  private static S3Client s3Client;
  private static final String BUCKET_NAME = "test-bucket";

  private Injector injector;
  private TrustedCertificateAuthorityGrpc.TrustedCertificateAuthorityBlockingStub client;

  public static LocalStackContainer localstack =
      new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.14.0"))
          .withServices(LocalStackContainer.Service.S3)
          .withStartupTimeout(Duration.ofSeconds(120));

  @BeforeClass
  public static void setUpClass() {
    localstack.start();
    initializeS3Client();
  }

  @AfterClass
  public static void cleanUpClass() {
    localstack.stop();
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    createS3TestBucket();
    setupServerAndClient();
  }

  private void setupServerAndClient() throws CertificateException, IOException {
    LocalArgs localArgs = new LocalArgs();

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    // Create the MeasurementBoundCertificate instance to be used as a singleton in the test
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                new MbsCertificateFactory.CertSignatureSpec("RSA", 4096, "SHA256withRSA"),
                new X500Name("CN=Standalone CA"),
                Duration.ofDays(30),
                Optional.empty(),
                KeyUsage.keyCertSign)
            .generate();

    AttestationToken dummyToken = AttestationToken.fromBytes(new byte[0]);
    final MeasurementBoundCertificate mbs =
        new MeasurementBoundCertificate(
            certAndKey.certificate(), certAndKey.privateKey(), dummyToken);

    java.security.KeyPair jwtKeyPair;
    try {
      java.security.KeyPairGenerator keyPairGenerator =
          java.security.KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      jwtKeyPair = keyPairGenerator.generateKeyPair();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    java.security.PrivateKey jwtPrivateKey = jwtKeyPair.getPrivate();
    java.security.PublicKey jwtPublicKey = jwtKeyPair.getPublic();

    injector =
        Guice.createInjector(
            Modules.override(new TrustedCaModule(), new LocalModeModule(localArgs))
                .with(
                    new AbstractModule() {
                      @Override
                      protected void configure() {
                        bind(TimeProvider.class).toInstance(timeProvider);
                        bind(S3Client.class).toInstance(s3Client);
                        bind(String.class)
                            .annotatedWith(PolicyBucket.class)
                            .toInstance(BUCKET_NAME);
                        bind(MeasurementBoundCertificate.class).toInstance(mbs);
                        bind(X509Certificate.class).toInstance(mbs.getCertificate());
                        bind(java.security.PrivateKey.class).toInstance(mbs.getPrivateKey());
                        bind(new com.google.inject.TypeLiteral<
                                io.jsonwebtoken.Locator<java.security.Key>>() {})
                            .annotatedWith(JwtAuth.class)
                            .toInstance(header -> jwtPublicKey);
                      }
                    }));

    TrustedCertificateAuthorityGrpcHandler service =
        injector.getInstance(TrustedCertificateAuthorityGrpcHandler.class);
    JwtInterceptor jwtInterceptor = injector.getInstance(JwtInterceptor.class);

    String serverName = "test-server";
    grpcCleanup.register(
        io.grpc.inprocess.InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(ServerInterceptors.intercept(service, jwtInterceptor))
            .build()
            .start());

    client =
        TrustedCertificateAuthorityGrpc.newBlockingStub(
            grpcCleanup.register(
                io.grpc.inprocess.InProcessChannelBuilder.forName(serverName)
                    .directExecutor()
                    .build()));

    Metadata metadata = new Metadata();
    metadata.put(
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
        "Bearer " + RequestUtils.createJwtToken(jwtPrivateKey));

    client = client.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
  }

  private static void initializeS3Client() {
    s3Client =
        S3Client.builder()
            .endpointOverride(localstack.getEndpointOverride(LocalStackContainer.Service.S3))
            .credentialsProvider(
                StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(
                        localstack.getAccessKey(), localstack.getSecretKey())))
            .forcePathStyle(true)
            .region(Region.of(localstack.getRegion()))
            .build();
  }

  private void createS3TestBucket() {
    ListObjectsV2Request listReq = ListObjectsV2Request.builder().bucket(BUCKET_NAME).build();
    try {
      ListObjectsV2Response listRes = s3Client.listObjectsV2(listReq);
      for (S3Object s3Object : listRes.contents()) {
        s3Client.deleteObject(
            DeleteObjectRequest.builder().bucket(BUCKET_NAME).key(s3Object.key()).build());
      }
    } catch (Exception e) {
      // Bucket does not exist on the first run
    }

    try {
      s3Client.createBucket(b -> b.bucket(BUCKET_NAME));
    } catch (Exception e) {
      // Bucket exists on following runs
    }
  }

  @Test
  public void issueCertificate_validRequest_succeeds() throws Exception {

    GoldenRequest goldenRequest = new GoldenRequest();

    uploadPolicyToS3(goldenRequest.getPublisherId(), goldenRequest.getWorkloadId());
    Instant testTime =
        goldenRequest.getNotBefore().plusSeconds(10000).truncatedTo(ChronoUnit.SECONDS);
    IssueCertificateRequest request = goldenRequest.getRequestBody();

    when(timeProvider.currentTimeMillis()).thenReturn(testTime.toEpochMilli());
    when(timeProvider.now()).thenReturn(Instant.ofEpochMilli(testTime.toEpochMilli()));

    IssueCertificateResponse response = client.issueCertificate(request);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    assertEquals(1, response.getSignedCertificatesCount());

    X509Certificate signedCert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(response.getSignedCertificates(0).toByteArray()));

    X509Certificate rootCert = injector.getInstance(X509Certificate.class);

    signedCert.verify(rootCert.getPublicKey());
    assertEquals("CN=OakWorkload", signedCert.getSubjectX500Principal().getName());

    // Verify certificate validity
    assertThat(signedCert.getNotBefore().toInstant()).isEqualTo(testTime);
    assertThat(signedCert.getNotAfter().toInstant()).isEqualTo(testTime.plusSeconds(3600));

    String expectedSpiffeId =
        "spiffe://example.org/operator/test_operator/publisher/"
            + goldenRequest.getPublisherId()
            + "/workload/"
            + goldenRequest.getWorkloadId();

    // Verify the SAN extension
    GeneralNames names =
        GeneralNames.getInstance(
            ASN1OctetString.getInstance(
                    signedCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
                .getOctets());
    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);

    // Verify the Name Constraints extension
    byte[] nameConstraintsBytes = signedCert.getExtensionValue(Extension.nameConstraints.getId());
    assertThat(nameConstraintsBytes).isNotNull();

    try (ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(nameConstraintsBytes))) {
      ASN1OctetString octetString = (ASN1OctetString) is.readObject();
      NameConstraints nameConstraints = NameConstraints.getInstance(octetString.getOctets());

      GeneralSubtree[] permitted = nameConstraints.getPermittedSubtrees();
      assertThat(permitted).hasLength(2);
      GeneralName generalName1 = permitted[0].getBase();
      assertThat(generalName1.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
      assertThat(generalName1.getName().toString()).isEqualTo(".example1.org");
      GeneralName generalName2 = permitted[1].getBase();
      assertThat(generalName2.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
      assertThat(generalName2.getName().toString()).isEqualTo(".example2.org");
    }

    // Verify the Basic Constraints extension
    BasicConstraints basicConstraints =
        BasicConstraints.getInstance(
            ASN1OctetString.getInstance(
                    signedCert.getExtensionValue(Extension.basicConstraints.getId()))
                .getOctets());
    assertThat(basicConstraints.isCA()).isTrue();
    assertThat(basicConstraints.getPathLenConstraint().intValue()).isEqualTo(1);
  }

  @Test
  public void issueCertificate_validRequest_fails_when_missing_policy_file() throws Exception {

    GoldenRequest goldenRequest = new GoldenRequest();
    IssueCertificateRequest request = goldenRequest.getRequestBody();

    StatusRuntimeException thrown =
        assertThrows(StatusRuntimeException.class, () -> client.issueCertificate(request));
    assertEquals(Status.Code.INVALID_ARGUMENT, thrown.getStatus().getCode());
    assertThat(thrown.getStatus().getDescription())
        .contains("No policy supports requested workload");
  }

  private static String readTestFile(String path) throws Exception {
    return Files.readString(Paths.get(path));
  }

  private void uploadFileToS3(String key, String content) throws Exception {
    s3Client.putObject(
        PutObjectRequest.builder().bucket(BUCKET_NAME).key(key).build(),
        RequestBody.fromString(content));
  }

  private void uploadPolicyToS3(String publisher_id, String workload_id) throws Exception {
    String policy = readTestFile("javatests/com/google/tca/server/testdata/policy.textproto");
    String oakContainersReferenceValues =
        readTestFile("javatests/com/google/tca/server/testdata/reference_values.textproto");
    policy =
        policy
            .replace("{publisher_id_to_replace}", publisher_id)
            .replace("{workload_id_to_replace}", workload_id)
            .replace("{oak_containers_reference_values}", oakContainersReferenceValues);
    uploadFileToS3("https_003a_002f_002faccounts.google.com/jwt-token-test-sub", policy);
  }
}
