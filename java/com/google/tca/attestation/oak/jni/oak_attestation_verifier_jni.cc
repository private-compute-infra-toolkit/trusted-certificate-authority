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

#include <jni.h>

#include <vector>

#include "java/com/google/tca/attestation/oak/rust/src/interface.rs.h"

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_tca_attestation_oak_OakEvidenceVerifier_nativeVerify(
    JNIEnv* env, jobject /* this */, jlong now_utc_millis,
    jbyteArray evidence_bytes, jbyteArray endorsements_bytes,
    jbyteArray reference_values_bytes) {
  // Convert Java byte arrays to rust::Slice for the FFI call.
  jsize evidence_len = env->GetArrayLength(evidence_bytes);
  jbyte* evidence_ptr = env->GetByteArrayElements(evidence_bytes, nullptr);
  rust::Slice<const uint8_t> evidence_slice(
      reinterpret_cast<const uint8_t*>(evidence_ptr), evidence_len);

  jsize endorsements_len = env->GetArrayLength(endorsements_bytes);
  jbyte* endorsements_ptr =
      env->GetByteArrayElements(endorsements_bytes, nullptr);
  rust::Slice<const uint8_t> endorsements_slice(
      reinterpret_cast<const uint8_t*>(endorsements_ptr), endorsements_len);

  jsize reference_values_len = env->GetArrayLength(reference_values_bytes);
  jbyte* reference_values_ptr =
      env->GetByteArrayElements(reference_values_bytes, nullptr);
  rust::Slice<const uint8_t> reference_values_slice(
      reinterpret_cast<const uint8_t*>(reference_values_ptr),
      reference_values_len);

  // Call the bridged Rust function from its C++ namespace.
  rust::Vec<uint8_t> result_vec =
      com::google::tca::attestation::oak::verify_attestation(
          now_utc_millis, evidence_slice, endorsements_slice,
          reference_values_slice);

  // Convert the returned Rust vector back to a Java byte array.
  jbyteArray result_array = env->NewByteArray(result_vec.size());
  env->SetByteArrayRegion(result_array, 0, result_vec.size(),
                          reinterpret_cast<const jbyte*>(result_vec.data()));

  // Release the memory for the byte array elements.
  env->ReleaseByteArrayElements(evidence_bytes, evidence_ptr, JNI_ABORT);
  env->ReleaseByteArrayElements(endorsements_bytes, endorsements_ptr,
                                JNI_ABORT);
  env->ReleaseByteArrayElements(reference_values_bytes, reference_values_ptr,
                                JNI_ABORT);

  return result_array;
}
