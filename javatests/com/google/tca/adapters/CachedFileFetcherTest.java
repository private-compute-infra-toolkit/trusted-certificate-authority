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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.policy.FileLoadException;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class CachedFileFetcherTest {

  @Mock private FileFetcher delegate;
  @Mock private InstantSource mockInstantSource;

  private CachedFileFetcher cachedFileFetcher;
  private Instant now;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    now = Instant.parse("2026-06-11T12:00:00Z");
    when(mockInstantSource.millis()).thenAnswer(inv -> now.toEpochMilli());
    cachedFileFetcher = new CachedFileFetcher(delegate, mockInstantSource);
  }

  @Test
  public void fetchFile_firstTime_callsDelegate() throws Exception {
    ByteString content = ByteString.copyFromUtf8("policy-data");
    when(delegate.fetchFile("client-1")).thenReturn(Optional.of(content));

    Optional<ByteString> result = cachedFileFetcher.fetchFile("client-1");

    assertThat(result).isPresent();
    assertThat(result.get().toStringUtf8()).isEqualTo("policy-data");
    verify(delegate, times(1)).fetchFile("client-1");
  }

  @Test
  public void fetchFile_secondTime_usesCacheHit() throws Exception {
    ByteString content = ByteString.copyFromUtf8("policy-data");
    when(delegate.fetchFile("client-1")).thenReturn(Optional.of(content));

    Optional<ByteString> result1 = cachedFileFetcher.fetchFile("client-1");
    Optional<ByteString> result2 = cachedFileFetcher.fetchFile("client-1");

    assertThat(result1).isPresent();
    assertThat(result2).isPresent();
    assertThat(result1.get()).isEqualTo(content);
    assertThat(result2.get()).isEqualTo(content);
    verify(delegate, times(1)).fetchFile("client-1");
  }

  @Test
  public void fetchFile_missCached_subsequentCallsReturnEmptyWithoutCallingDelegate()
      throws Exception {
    when(delegate.fetchFile("client-1")).thenReturn(Optional.empty());

    Optional<ByteString> result1 = cachedFileFetcher.fetchFile("client-1");
    Optional<ByteString> result2 = cachedFileFetcher.fetchFile("client-1");

    assertThat(result1).isEmpty();
    assertThat(result2).isEmpty();
    verify(delegate, times(1)).fetchFile("client-1");
  }

  @Test
  public void fetchFile_hitExpired_callsDelegateAgain() throws Exception {
    ByteString content1 = ByteString.copyFromUtf8("policy-data-1");
    ByteString content2 = ByteString.copyFromUtf8("policy-data-2");
    when(delegate.fetchFile("client-1"))
        .thenReturn(Optional.of(content1))
        .thenReturn(Optional.of(content2));

    Optional<ByteString> result1 = cachedFileFetcher.fetchFile("client-1");
    assertThat(result1.get()).isEqualTo(content1);

    // Advance time by 4 minutes and 59 seconds (no expiry yet)
    now = now.plusSeconds(299);
    Optional<ByteString> result2 = cachedFileFetcher.fetchFile("client-1");
    assertThat(result2.get()).isEqualTo(content1);
    verify(delegate, times(1)).fetchFile("client-1");

    // Advance time by 2 more seconds (total 5 minutes and 1 second - expired)
    now = now.plusSeconds(2);
    Optional<ByteString> result3 = cachedFileFetcher.fetchFile("client-1");
    assertThat(result3.get()).isEqualTo(content2);
    verify(delegate, times(2)).fetchFile("client-1");
  }

  @Test
  public void fetchFile_missExpired_callsDelegateAgain() throws Exception {
    when(delegate.fetchFile("client-1")).thenReturn(Optional.empty());

    Optional<ByteString> result1 = cachedFileFetcher.fetchFile("client-1");
    assertThat(result1).isEmpty();

    // Advance time by 4 minutes and 59 seconds (no expiry of miss yet)
    now = now.plusSeconds(299);
    Optional<ByteString> result2 = cachedFileFetcher.fetchFile("client-1");
    assertThat(result2).isEmpty();
    verify(delegate, times(1)).fetchFile("client-1");

    // Advance time by 2 more seconds (total 5 minutes and 1 second - expired)
    now = now.plusSeconds(2);
    Optional<ByteString> result3 = cachedFileFetcher.fetchFile("client-1");
    assertThat(result3.isEmpty()).isTrue();
    verify(delegate, times(2)).fetchFile("client-1");
  }

  @Test
  public void fetchFile_delegateThrowsException_doesNotCache() {
    when(delegate.fetchFile(anyString())).thenThrow(new FileLoadException("Transient exception"));

    // First call throws FileLoadException
    assertThrows(FileLoadException.class, () -> cachedFileFetcher.fetchFile("client-1"));

    // Second call should try delegate again immediately because exceptions are not cached
    assertThrows(FileLoadException.class, () -> cachedFileFetcher.fetchFile("client-1"));
    verify(delegate, times(2)).fetchFile("client-1");
  }
}
