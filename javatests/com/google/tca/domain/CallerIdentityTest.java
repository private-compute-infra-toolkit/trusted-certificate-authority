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

package com.google.tca.domain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.Collections;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CallerIdentityTest {
  @Test
  public void getClientId_returnsConcatenatedGcpIdentity() {
    CallerIdentity identity =
        new CallerIdentity(
            "https://accounts.google.com", "123456789012345678901", Collections.emptySet());
    assertEquals(
        "https_003a_002f_002faccounts.google.com/123456789012345678901", identity.getClientId());
  }

  @Test
  public void getClientId_escapesForwardSlashInIssuer() {
    CallerIdentity identity =
        new CallerIdentity("https://accounts.google.com/extra", "subject", Collections.emptySet());
    assertEquals(
        "https_003a_002f_002faccounts.google.com_002fextra/subject", identity.getClientId());
  }

  @Test
  public void getClientId_escapesUnderscore() {
    CallerIdentity identity = new CallerIdentity("my_issuer", "my_subject", Collections.emptySet());
    assertEquals("my_005fissuer/my_005fsubject", identity.getClientId());
  }

  @Test
  public void getClientId_isUnequivocal() {
    // If we had a literal slash in an escaped string, it would be ambiguous.
    // Here, 'a/b' and 'a_002fb' results in different identifiers.
    CallerIdentity identity1 = new CallerIdentity("a/b", "c", Collections.emptySet());
    CallerIdentity identity2 = new CallerIdentity("a_002fb", "c", Collections.emptySet());

    assertEquals("a_002fb/c", identity1.getClientId());
    assertEquals("a_005f002fb/c", identity2.getClientId());
  }

  @Test
  public void constructor_throwsOnEmptyIssuer() {
    assertThrows(IllegalArgumentException.class, () -> new CallerIdentity("", "subject", Set.of()));
  }

  @Test
  public void constructor_throwsOnBlankIssuer() {
    assertThrows(
        IllegalArgumentException.class, () -> new CallerIdentity("   ", "subject", Set.of()));
  }

  @Test
  public void constructor_throwsOnEmptySubject() {
    assertThrows(IllegalArgumentException.class, () -> new CallerIdentity("issuer", "", Set.of()));
  }

  @Test
  public void constructor_throwsOnBlankSubject() {
    assertThrows(
        IllegalArgumentException.class, () -> new CallerIdentity("issuer", "   ", Set.of()));
  }

  @Test
  public void getClientId_handlesSupplementaryCharacters() {
    // \uD800\uDC20 is the surrogate pair for U+10020
    CallerIdentity identity = new CallerIdentity("issuer", "\uD800\uDC20", Set.of());
    // Current implementation escapes each surrogate unit individually
    assertEquals("issuer/_d800_dc20", identity.getClientId());
  }

  @Test
  public void constructor_throwsOnNullIssuer() {
    assertThrows(NullPointerException.class, () -> new CallerIdentity(null, "subject", Set.of()));
  }

  @Test
  public void constructor_throwsOnNullSubject() {
    assertThrows(NullPointerException.class, () -> new CallerIdentity("issuer", null, Set.of()));
  }

  @Test
  public void constructor_throwsOnNullAudiences() {
    assertThrows(NullPointerException.class, () -> new CallerIdentity("issuer", "subject", null));
  }

  @Test
  public void audiences_returnsProvidedAudiences() {
    Set<String> audiences = Set.of("aud1", "aud2");
    CallerIdentity identity = new CallerIdentity("issuer", "subject", audiences);
    assertEquals(audiences, identity.audiences());
  }
}
