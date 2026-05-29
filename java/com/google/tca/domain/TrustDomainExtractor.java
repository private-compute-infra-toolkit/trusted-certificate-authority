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

package com.google.tca.domain;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.x509.GeneralName;

/** Utility class to extract SPIFFE ID trust domain from root certificates. */
public final class TrustDomainExtractor {

  // Java's X509Certificate.getSubjectAlternativeNames() returns a collection of lists,
  // where each list contains:
  // - index 0: Integer representing the GeneralName type tag (e.g. 6 for URI)
  // - index 1: Object representing the name value (String for URI/DNS/IP, byte array for others)
  private static final int SAN_TAG_INDEX = 0;
  private static final int SAN_VALUE_INDEX = 1;

  private TrustDomainExtractor() {}

  /**
   * Extracts the trust domain from the Subject Alternative Name (SAN) of the root certificate.
   *
   * @throws CertificateParsingException if the certificate cannot be parsed.
   * @throws IllegalArgumentException if the trust domain cannot be found.
   */
  public static String extract(X509Certificate rootCertificate)
      throws CertificateParsingException, java.net.URISyntaxException {
    Collection<List<?>> sans = rootCertificate.getSubjectAlternativeNames();
    if (sans != null) {
      for (List<?> san : sans) {
        Optional<String> trustDomain = tryParseTrustDomain(san);
        if (trustDomain.isPresent()) {
          return trustDomain.get();
        }
      }
    }
    throw new IllegalArgumentException(
        "Root certificate SAN does not contain a valid SPIFFE ID trust domain.");
  }

  private static Optional<String> tryParseTrustDomain(List<?> san)
      throws java.net.URISyntaxException {
    if (!isUriSan(san)) {
      return Optional.empty();
    }
    Object value = san.get(SAN_VALUE_INDEX);
    if (!(value instanceof String)) {
      return Optional.empty();
    }
    String spiffeId = (String) value;
    if (!spiffeId.startsWith("spiffe://")) {
      return Optional.empty();
    }
    return extractTrustDomainFromSpiffeId(spiffeId);
  }

  /**
   * Verifies if the SAN entry is of type URI.
   *
   * <p>Java's X509Certificate.getSubjectAlternativeNames() returns a list where: - Index 0
   * (SAN_TAG_INDEX) is the integer type tag (6 = uniformResourceIdentifier). - Index 1
   * (SAN_VALUE_INDEX) is the actual string value.
   */
  private static boolean isUriSan(List<?> san) {
    return san.size() >= 2
        && san.get(SAN_TAG_INDEX) instanceof Integer
        && (Integer) san.get(SAN_TAG_INDEX) == GeneralName.uniformResourceIdentifier;
  }

  private static Optional<String> extractTrustDomainFromSpiffeId(String spiffeId)
      throws java.net.URISyntaxException {
    java.net.URI uri = new java.net.URI(spiffeId);
    return extractTrustDomainFromHost(uri.getHost());
  }

  private static Optional<String> extractTrustDomainFromHost(String host) {
    if (host != null && host.startsWith("tca.")) {
      return Optional.of(host);
    }
    return Optional.empty();
  }
}
