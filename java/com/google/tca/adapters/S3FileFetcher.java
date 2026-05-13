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

package com.google.tca.adapters;

import com.google.common.flogger.FluentLogger;
import com.google.protobuf.ByteString;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.policy.FileLoadException;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

@Singleton
public class S3FileFetcher implements FileFetcher {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final S3Client s3Client;
  private final String bucket;

  @Inject
  public S3FileFetcher(S3Client s3Client, @PolicyBucket String bucket) {
    this.s3Client = s3Client;
    this.bucket = bucket;
  }

  public ByteString fetchFile(String key) throws FileLoadException {
    ByteString bytes = loadFileFromS3(key);
    logger.atInfo().log("Successfully fetched file from S3 bucket: %s", key);
    return bytes;
  }

  private ByteString loadFileFromS3(String key) throws FileLoadException {
    try (ResponseInputStream<GetObjectResponse> fetchedObject =
        s3Client.getObject(GetObjectRequest.builder().bucket(bucket).key(key).build())) {
      return ByteString.readFrom(fetchedObject);
    } catch (Exception e) {
      throw new FileLoadException("Failed to load file " + key + " from S3 bucket: " + bucket, e);
    }
  }
}
