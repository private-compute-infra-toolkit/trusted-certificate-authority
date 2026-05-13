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

import com.google.common.flogger.FluentLogger;
import com.google.gson.Gson;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.kmsclient.KmsClientInterface;
import com.google.kmsclient.aws.AwsKmsClientModule;
import com.google.mbs.KeyBackupBucketProperties;
import com.google.mbs.KeyBackupBucketPropertiesFactory;
import com.google.mbs.KmsMeasurementBoundCertificateProvider;
import com.google.mbs.MbsCertificateFactory;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.MeasurementBoundCertificateProvider;
import com.google.mbs.attestationcollection.AttestationCollector;
import com.google.tca.adapters.PolicyBucket;
import com.google.tlog.TransparencyLogClient;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

/** Guice module for TCA KMS mode. */
public class KmsModeModule extends AbstractModule {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final AwsResourceNames awsResourceNames;
  private final AwsInstanceMetadata awsInstanceMetadata;

  public KmsModeModule(KmsArgs args) {
    this.awsInstanceMetadata = new ImdsClient().getAwsInstanceMetadata();
    AwsResourceNamesProvider provider = new AwsResourceNamesProvider(args, awsInstanceMetadata);
    this.awsResourceNames = provider.getRecord();
  }

  @Override
  protected void configure() {

    install(new AwsKmsClientModule(awsInstanceMetadata.region()));
    bind(String.class)
        .annotatedWith(PolicyBucket.class)
        .toInstance(awsResourceNames.configBucketName());
  }

  @Provides
  @Singleton
  S3Client provideS3Client() {
    Region region = Region.of(awsInstanceMetadata.region());
    logger.atInfo().log("Initializing S3Client with AWS region: %s", region.toString());
    return S3Client.builder().region(region).build();
  }

  @Provides
  @Singleton
  MeasurementBoundCertificateProvider provideCertificateProvider(
      KmsClientInterface kmsClient,
      S3Client s3Client,
      KeyBackupBucketProperties bucketProperties,
      TransparencyLogClient tlogClient,
      AttestationCollector attestationCollector) {
    String resourceNamesJson = new Gson().toJson(awsResourceNames);
    byte[] userData = resourceNamesJson.getBytes(StandardCharsets.UTF_8);
    Optional<GeneralNames> noSan = Optional.empty();
    return new KmsMeasurementBoundCertificateProvider(
        kmsClient,
        s3Client,
        bucketProperties,
        awsResourceNames.kmsKeyArn(),
        userData,
        tlogClient,
        attestationCollector,
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
            new MbsCertificateFactory.CertSignatureSpec("RSA", 4096, "SHA256withRSA"),
            new X500Name("C=US, O=Google LLC, CN=TCA Root"),
            Duration.ofDays(120),
            noSan,
            KeyUsage.keyCertSign));
  }

  @Provides
  @Singleton
  KeyBackupBucketProperties provideKeyBackupBucketProperties() {
    return new KeyBackupBucketPropertiesFactory(
            awsResourceNames.certBackupBucketName(), awsResourceNames.keyBackupBucketName())
        .create();
  }

  @Provides
  @Singleton
  MeasurementBoundCertificate provideMeasurementBoundCertificate(
      MeasurementBoundCertificateProvider certificateProvider) throws Exception {
    logger.atInfo().log("TCA Module: KMS-backed mode.");
    return certificateProvider.loadOrGenerateCertificate();
  }
}
