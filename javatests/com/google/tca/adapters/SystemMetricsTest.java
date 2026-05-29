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

import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.domain.metric.Status;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SystemMetricsTest {

  private PrometheusMeterRegistry registry;
  private SystemMetrics systemMetrics;

  @Before
  public void setUp() {
    registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    systemMetrics = new SystemMetrics(registry);
  }

  @Test
  public void constructor_preRegistersAllCountersWithZeroValue() {
    for (Status status : Status.values()) {
      double value =
          registry
              .get("tca.authorizationStatus")
              .tag("status", status.name().toLowerCase())
              .counter()
              .count();
      assertThat(value).isEqualTo(0.0);
    }

    for (ProcessingStatus status : ProcessingStatus.values()) {
      double value =
          registry
              .get("tca.processingStatus")
              .tag("status", status.name().toLowerCase())
              .counter()
              .count();
      assertThat(value).isEqualTo(0.0);
    }
  }

  @Test
  public void incrementAuthorizationCounter_succeeds() {
    systemMetrics.incrementAuthorizationCounter(Status.SUCCESS);
    systemMetrics.incrementAuthorizationCounter(Status.SUCCESS);
    systemMetrics.incrementAuthorizationCounter(Status.FAILURE);

    double successVal =
        registry.get("tca.authorizationStatus").tag("status", "success").counter().count();
    double failureVal =
        registry.get("tca.authorizationStatus").tag("status", "failure").counter().count();

    assertThat(successVal).isEqualTo(2.0);
    assertThat(failureVal).isEqualTo(1.0);
  }

  @Test
  public void incrementProcessingCounter_succeeds() {
    systemMetrics.incrementProcessingCounter(ProcessingStatus.MISSING_POLICY);
    systemMetrics.incrementProcessingCounter(ProcessingStatus.SUCCESS);
    systemMetrics.incrementProcessingCounter(ProcessingStatus.SUCCESS);

    double missingPolicyVal =
        registry.get("tca.processingStatus").tag("status", "missing_policy").counter().count();
    double successVal =
        registry.get("tca.processingStatus").tag("status", "success").counter().count();

    assertThat(missingPolicyVal).isEqualTo(1.0);
    assertThat(successVal).isEqualTo(2.0);
  }

  @Test
  public void increment_nullInputs_safelyIgnored() {
    systemMetrics.incrementAuthorizationCounter(null);
    systemMetrics.incrementProcessingCounter(null);

    double successA =
        registry.get("tca.authorizationStatus").tag("status", "success").counter().count();
    double successB =
        registry.get("tca.processingStatus").tag("status", "success").counter().count();

    assertThat(successA).isEqualTo(0.0);
    assertThat(successB).isEqualTo(0.0);
  }
}
