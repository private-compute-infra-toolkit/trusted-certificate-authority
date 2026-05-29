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

package com.google.tca.adapters.certsigning;

import static com.google.common.truth.Truth.assertThat;

import com.google.protobuf.ByteString;
import com.google.tca.domain.CertificateModifier;
import com.google.tca.domain.policy.BasicConstraints;
import com.google.tca.domain.policy.BasicConstraintsType;
import com.google.tca.domain.policy.NameConstraints;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.domain.policy.ReferenceValuesType;
import com.google.tca.domain.policy.X500NameAttributes;
import com.google.tca.domain.policy.X509CertificateAttributes;
import com.google.tca.domain.policy.X509Extensions;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CertificateModifiersCreatorImplTest {

  private CertificateModifiersCreatorImpl creator;

  @Before
  public void setUp() {
    creator = new CertificateModifiersCreatorImpl();
  }

  @Test
  public void create_withAllExtensions_returnsAllModifiers() {
    Policy policy =
        new Policy(
            "test-publisher",
            "test-app",
            "example.org",
            "test-operator",
            List.of(new ReferenceValues(ReferenceValuesType.GCP, ByteString.EMPTY)),
            new X509CertificateAttributes(
                Duration.ofHours(1),
                new X509Extensions(
                    Optional.of(new BasicConstraints(BasicConstraintsType.CA, 3)),
                    Optional.of(new NameConstraints(List.of("permitted.example.com")))),
                new X500NameAttributes(Map.of())));

    List<CertificateModifier> modifiers = creator.create(policy);

    assertThat(modifiers).hasSize(4);
    assertThat(modifiers.get(0)).isInstanceOf(NameConstraintsModifier.class);
    assertThat(modifiers.get(1)).isInstanceOf(BasicConstraintsModifier.class);
    assertThat(modifiers.get(2)).isInstanceOf(KeyUsageModifier.class);
    assertThat(modifiers.get(3)).isInstanceOf(SubjectAlternativeNameModifier.class);
  }
}
