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
import com.google.tca.domain.FileFetcher;
import java.util.Optional;

public class FileFetcherStub implements FileFetcher {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  ByteString content;

  public FileFetcherStub(ByteString fileContent) {
    this.content = fileContent;
  }

  public void setContent(ByteString content) {
    this.content = content;
  }

  @Override
  public Optional<ByteString> fetchFile(String path) {
    logger.atInfo().log(
        "Using FileFetcher::fetchFile stub with argument: %s and returning hardcoded valid policy"
            + " response",
        path);
    return Optional.ofNullable(content);
  }
}
