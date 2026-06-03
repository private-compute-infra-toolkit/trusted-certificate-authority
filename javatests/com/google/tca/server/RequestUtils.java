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

import static com.google.tca.adapters.OakAttestationEvidence.CONTAINER_ENDORSEMENT_ID;

import com.google.oak.Variant;
import com.google.oak.attestation.v1.ContainerEndorsement;
import com.google.oak.attestation.v1.Endorsement;
import com.google.oak.attestation.v1.Endorsements;
import com.google.oak.attestation.v1.SignedEndorsement;
import com.google.protobuf.ByteString;
import io.jsonwebtoken.Jwts;
import java.security.PrivateKey;
import java.util.Date;

public class RequestUtils {
  String notBefore = "2026-03-05T10:00:00.000000Z";
  String notAfter = "3027-03-05T10:00:00.000000Z";

  public static String createJwtToken(PrivateKey privateKey) {
    String defaultAudience = "jwt-token-test-aud";
    return createJwtToken(privateKey, defaultAudience);
  }

  public static String createJwtToken(PrivateKey privateKey, String audience) {
    return Jwts.builder()
        .setAudience(audience)
        .claim("azp", "jwt-token-test-azp")
        .claim("email", "example@developer.gserviceaccount.com")
        .claim("email_verified", true)
        .setExpiration(new Date(2774051588000L))
        .setIssuedAt(new Date(1774047988000L))
        .setIssuer("https://accounts.google.com")
        .setSubject("jwt-token-test-sub")
        .signWith(privateKey)
        .compact();
  }

  static Endorsements createEndorsement(String inTotoStatement) {
    ByteString endorsementPayload = ByteString.copyFromUtf8(inTotoStatement);
    return Endorsements.newBuilder()
        .addEvents(createContainerEndorsement(endorsementPayload))
        .build();
  }

  private static Variant createContainerEndorsement(ByteString bytes) {
    ContainerEndorsement containerEndorsement =
        ContainerEndorsement.newBuilder()
            .setBinary(
                SignedEndorsement.newBuilder()
                    .setEndorsement(Endorsement.newBuilder().setSerialized(bytes)))
            .build();

    return Variant.newBuilder()
        .setId(CONTAINER_ENDORSEMENT_ID)
        .setValue(containerEndorsement.toByteString())
        .build();
  }

  static String correctInTotoStatement(String notBefore, String notAfter) {
    return String.format(
        """
            {
              "_type": "https://in-toto.io/Statement/v1",
              "subject": [
                {
                  "name": "my_application_binary",
                  "digest": {
                    "sha256": "1234567..."
                  }
                }
              ],
              "predicateType": "https://project-oak.github.io/oak/tr/endorsement/v1",
              "predicate": {
                "issuedOn": "2026-03-05T10:00:00.000000Z",
                "validity": {
                  "notBefore": "%s",
                  "notAfter": "%s"
                },
                "claims": [
                  {
                    "type": "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/publisher.md",
                    "annotations": {
                      "publisher_id": "default_publisher_id@example.com"
                    }
                  },
                  {
                    "type": "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/workload.md",
                    "annotations": {
                      "workload_id": "default_workload_id",
                      "version": "1"
                    }
                  },
                  {
                    "type": "https://github.com/project-oak/oak/blob/main/docs/tr/claim/85483.md"
                  }
                ]
              }
            }
        """
            .trim(),
        notBefore,
        notAfter);
  }

  static String incorrectInTotoStatementMissingValidityPart(String notBefore) {
    return String.format(
        """
            {
              "_type": "https://in-toto.io/Statement/v1",
              "subject": [
                {
                  "name": "my_application_binary",
                  "digest": {
                    "sha256": "1234567..."
                  }
                }
              ],
              "predicateType": "https://project-oak.github.io/oak/tr/endorsement/v1",
              "predicate": {
                "issuedOn": "2026-03-05T10:00:00.000000Z",
                "validity": {
                  "notBefore": "%s"
                },
                "claims": [
                  {
                    "type": "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/publisher.md",
                    "annotations": {
                      "publisher_id": "default_publisher_id@example.com"
                    }
                  },
                  {
                    "type": "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/workload.md",
                    "annotations": {
                      "workload_id": "default_workload_id",
                      "version": "1"
                    }
                  },
                  {
                    "type": "https://github.com/project-oak/oak/blob/main/docs/tr/claim/85483.md"
                  }
                ]
              }
            }
        """
            .trim(),
        notBefore);
  }

  static String correctInTotoStatementMissingClaimsPart(String notBefore, String notAfter) {
    return String.format(
        """
            {
              "_type": "https://in-toto.io/Statement/v1",
              "subject": [
                {
                  "name": "my_application_binary",
                  "digest": {
                    "sha256": "1234567..."
                  }
                }
              ],
              "predicateType": "https://project-oak.github.io/oak/tr/endorsement/v1",
              "predicate": {
                "issuedOn": "2026-03-05T10:00:00.000000Z",
                "validity": {
                  "notBefore": "%s",
                  "notAfter": "%s"
                }
              }
            }
        """
            .trim(),
        notBefore,
        notAfter);
  }

  static String incorrectInTotoStatementWrongValidityFormat() {
    return """
        {
          "_type": "https://in-toto.io/Statement/v1",
          "subject": [
            {
              "name": "my_application_binary",
              "digest": {
                "sha256": "1234567..."
              }
            }
          ],
          "predicateType": "https://project-oak.github.io/oak/tr/endorsement/v1",
          "predicate": {
            "issuedOn": "2026-03-05T10:00:00.000000Z",
            "validity": {
              "notBefore": "2026-03-05T10:00:00.__somewrongstring_0Z",
              "notAfter": "2026-03-05T10-00:00.000000Z"
            },
            "claims": [
              {
                "type": "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/publisher.md",
                "annotations": {
                  "publisher_id": "default_publisher_id@example.com"
                }
              },
              {
                "type": "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/workload.md",
                "annotations": {
                  "workload_id": "default_workload_id",
                  "version": "1"
                }
              },
              {
                "type": "https://github.com/project-oak/oak/blob/main/docs/tr/claim/85483.md"
              }
            ]
          }
        }
    """
        .trim();
  }
}
