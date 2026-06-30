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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.KmsGeneratedKey;
import com.google.mbs.KeyBackupBucketProperties;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.MeasurementBoundCertificateProvider;
import com.google.mbs.Metrics;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.tlog.TlogEntry;
import com.google.tlog.TransparencyLogClient;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

@RunWith(JUnit4.class)
public class KmsModeModuleTest {

  private KmsClientInterface kmsClient;
  private S3Client s3Client;
  private TransparencyLogClient tlogClient;
  private AttestationCollector attestationCollector;
  private KeyBackupBucketProperties bucketProperties;

  @Before
  public void setUp() {
    kmsClient = mock(KmsClientInterface.class);
    s3Client = mock(S3Client.class);
    tlogClient = mock(TransparencyLogClient.class);
    attestationCollector = mock(AttestationCollector.class);
    bucketProperties = mock(KeyBackupBucketProperties.class);

    when(bucketProperties.getPublicBucketName()).thenReturn("test-public-bucket");
    when(bucketProperties.getPrivateBucketName()).thenReturn("test-private-bucket");
    when(bucketProperties.getCertPath()).thenReturn("cert.pem");
    when(bucketProperties.getKmsEncryptedDataKeyPath()).thenReturn("data-key.enc");
    when(bucketProperties.getAesEncryptedPrivateKeyPath()).thenReturn("key.enc");
    when(bucketProperties.getAttestationDocPath()).thenReturn("attestation.doc");
    when(bucketProperties.getTlogEntryPath()).thenReturn("tlog.json");
  }

  @Test
  public void provideCertificateProvider_generatesCertificateWithCorrectSpiffeIdInSan()
      throws Exception {
    // 1. Setup module with test metadata
    String testEnv = "testenv";
    String testDomain = "testdomain";
    AwsInstanceMetadata awsInstanceMetadata =
        AwsInstanceMetadata.builder()
            .setRegion("us-east-1")
            .setAccountId("123456789012")
            .setEnvironment(testEnv)
            .setDomain(testDomain)
            .build();
    KmsArgs kmsArgs = new KmsArgs();
    KmsModeModule module = new KmsModeModule(kmsArgs, awsInstanceMetadata);

    // 2. Get the provider
    Metrics mockMetrics = mock(Metrics.class);
    MeasurementBoundCertificateProvider provider =
        module.provideCertificateProvider(
            kmsClient, s3Client, bucketProperties, tlogClient, attestationCollector, mockMetrics);

    // 3. Setup mocks to trigger the certificate generation path
    when(s3Client.getObject(any(GetObjectRequest.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    byte[] mockPlaintextKey = new byte[32];
    new java.security.SecureRandom().nextBytes(mockPlaintextKey);
    KmsGeneratedKey mockGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(mockPlaintextKey)
            .setCiphertext(new byte[32])
            .build();
    when(kmsClient.generateDataKey(anyString())).thenReturn(mockGeneratedKey);

    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes(new byte[0]));

    when(tlogClient.recordCertificate(any(), any())).thenReturn(new TlogEntry("{}"));

    // 4. Load (generate) certificate
    MeasurementBoundCertificate mbsCert = provider.loadOrGenerateCertificate();
    X509Certificate rootCert = mbsCert.getCertificate();

    // 5. Verify subject principal
    assertThat(rootCert.getSubjectX500Principal().getName())
        .isEqualTo("CN=TCA Root,O=Google LLC,C=US");

    // 6. Verify the constructed SPIFFE ID in the SAN extension
    String expectedSpiffeId =
        "spiffe://tca.testenv.testdomain/operator/pcit.goog/123456789012/publisher/google.com/pcit-release-bot/workload/transparent-certificate-authority";

    byte[] sanExtensionValue = rootCert.getExtensionValue(Extension.subjectAlternativeName.getId());
    assertThat(sanExtensionValue).isNotNull();

    GeneralNames names =
        GeneralNames.getInstance(ASN1OctetString.getInstance(sanExtensionValue).getOctets());
    assertThat(names.getNames()).hasLength(1);

    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);
  }

  @Test
  public void provideCertificateProvider_prodEnv_stripsAwsSubdomainAndOmitEnv() throws Exception {
    // 1. Setup module with prod metadata and "aws." subdomain
    String testEnv = "prod";
    String testDomain = "aws.pcit.goog";
    AwsInstanceMetadata awsInstanceMetadata =
        AwsInstanceMetadata.builder()
            .setRegion("us-east-1")
            .setAccountId("123456789012")
            .setEnvironment(testEnv)
            .setDomain(testDomain)
            .build();
    KmsArgs kmsArgs = new KmsArgs();
    KmsModeModule module = new KmsModeModule(kmsArgs, awsInstanceMetadata);

    // 2. Get the provider
    Metrics mockMetrics = mock(Metrics.class);
    MeasurementBoundCertificateProvider provider =
        module.provideCertificateProvider(
            kmsClient, s3Client, bucketProperties, tlogClient, attestationCollector, mockMetrics);

    // 3. Setup mocks to trigger the certificate generation path
    when(s3Client.getObject(any(GetObjectRequest.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    byte[] mockPlaintextKey = new byte[32];
    new java.security.SecureRandom().nextBytes(mockPlaintextKey);
    KmsGeneratedKey mockGeneratedKey =
        KmsGeneratedKey.builder()
            .setPlaintext(mockPlaintextKey)
            .setCiphertext(new byte[32])
            .build();
    when(kmsClient.generateDataKey(anyString())).thenReturn(mockGeneratedKey);

    when(attestationCollector.collectBoundToPubkey(any(), any()))
        .thenReturn(AttestationToken.fromBytes(new byte[0]));

    when(tlogClient.recordCertificate(any(), any())).thenReturn(new TlogEntry("{}"));

    // 4. Load (generate) certificate
    MeasurementBoundCertificate mbsCert = provider.loadOrGenerateCertificate();
    X509Certificate rootCert = mbsCert.getCertificate();

    // 5. Verify subject principal
    assertThat(rootCert.getSubjectX500Principal().getName())
        .isEqualTo("CN=TCA Root,O=Google LLC,C=US");

    // 6. Verify the constructed SPIFFE ID in the SAN extension (should be tca.pcit.goog)
    String expectedSpiffeId =
        "spiffe://tca.pcit.goog/operator/pcit.goog/123456789012/publisher/google.com/pcit-release-bot/workload/transparent-certificate-authority";

    byte[] sanExtensionValue = rootCert.getExtensionValue(Extension.subjectAlternativeName.getId());
    assertThat(sanExtensionValue).isNotNull();

    GeneralNames names =
        GeneralNames.getInstance(ASN1OctetString.getInstance(sanExtensionValue).getOctets());
    assertThat(names.getNames()).hasLength(1);

    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);
  }
}
