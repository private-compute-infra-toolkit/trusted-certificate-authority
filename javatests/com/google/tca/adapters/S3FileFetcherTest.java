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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import com.google.tca.domain.policy.FileLoadException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

@RunWith(JUnit4.class)
public class S3FileFetcherTest {

  @Mock private S3Client s3Client;

  private S3FileFetcher fileFetcher;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    fileFetcher = new S3FileFetcher(s3Client, "test-bucket");
  }

  private ResponseInputStream<GetObjectResponse> createS3Stream(String content) {
    return new ResponseInputStream<>(
        GetObjectResponse.builder().build(),
        new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  public void fetchFile_success_returnsOptionalOfByteString() throws Exception {
    when(s3Client.getObject(any(GetObjectRequest.class)))
        .thenReturn(createS3Stream("some-policy-data"));

    Optional<ByteString> result = fileFetcher.fetchFile("client-1");

    assertThat(result).isPresent();
    assertThat(result.get().toStringUtf8()).isEqualTo("some-policy-data");
    verify(s3Client, times(1)).getObject(any(GetObjectRequest.class));
  }

  @Test
  public void fetchFile_noSuchKeyException_returnsOptionalEmpty() throws Exception {
    when(s3Client.getObject(any(GetObjectRequest.class)))
        .thenThrow(NoSuchKeyException.builder().build());

    Optional<ByteString> result = fileFetcher.fetchFile("client-1");

    assertThat(result).isEmpty();
    verify(s3Client, times(1)).getObject(any(GetObjectRequest.class));
  }

  @Test
  public void fetchFile_otherException_throwsFileLoadException() {
    when(s3Client.getObject(any(GetObjectRequest.class)))
        .thenThrow(new RuntimeException("Transient connection issue"));

    assertThrows(FileLoadException.class, () -> fileFetcher.fetchFile("client-1"));
    verify(s3Client, times(1)).getObject(any(GetObjectRequest.class));
  }
}
