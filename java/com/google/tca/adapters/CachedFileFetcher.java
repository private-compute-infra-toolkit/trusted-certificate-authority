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

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.flogger.FluentLogger;
import com.google.protobuf.ByteString;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.policy.FileLoadException;
import java.time.Duration;
import java.time.InstantSource;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class CachedFileFetcher implements FileFetcher {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final FileFetcher delegate;
  private final LoadingCache<String, Optional<ByteString>> cache;

  private static final Duration CACHE_DURATION = Duration.ofMinutes(5);

  public CachedFileFetcher(FileFetcher delegate, InstantSource instantSource) {
    this.delegate = delegate;
    this.cache =
        Caffeine.newBuilder()
            .ticker(() -> TimeUnit.MILLISECONDS.toNanos(instantSource.millis()))
            .expireAfterWrite(CACHE_DURATION)
            .build(this::loadFromDelegateOrThrow);
  }

  @Override
  public Optional<ByteString> fetchFile(String key) throws FileLoadException {
    return cache.get(key);
  }

  private Optional<ByteString> loadFromDelegateOrThrow(String key) throws FileLoadException {
    logger.atInfo().log("Cache miss for key: %s. Fetching from delegate.", key);
    return delegate.fetchFile(key);
  }
}
