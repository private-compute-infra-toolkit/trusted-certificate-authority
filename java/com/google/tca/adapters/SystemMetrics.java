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

import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.domain.metric.Status;
import io.micrometer.core.instrument.Counter;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class SystemMetrics implements Metrics {

  private static final String PREFIX = "tca.";

  private final PrometheusMeterRegistry registry;
  private final Counter[] authorizationCounter;
  private final Counter[] processingCounter;

  @Inject
  public SystemMetrics(PrometheusMeterRegistry registry) {
    this.registry = registry;
    this.authorizationCounter =
        createCounters(PREFIX + "authorizationStatus", "status", Status.class);
    this.processingCounter =
        createCounters(PREFIX + "processingStatus", "status", ProcessingStatus.class);
  }

  private <E extends Enum<E>> Counter[] createCounters(
      String name, String tagKey, Class<E> enumClass) {
    E[] constants = enumClass.getEnumConstants();
    Counter[] array = new Counter[constants.length];
    for (E item : constants) {
      array[item.ordinal()] =
          Counter.builder(name)
              .tag(tagKey, item.name().toLowerCase())
              .description("Metrics tracking for " + name)
              .register(registry);
    }
    return array;
  }

  @Override
  public void incrementAuthorizationCounter(Status status) {
    if (status != null) {
      authorizationCounter[status.ordinal()].increment();
    }
  }

  @Override
  public void incrementProcessingCounter(ProcessingStatus status) {
    if (status != null) {
      processingCounter[status.ordinal()].increment();
    }
  }
}
