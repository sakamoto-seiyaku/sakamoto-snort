/* SPDX-License-Identifier: Apache-2.0 */

#include <jni.h>

#include "sakamoto_product_abi.h"
#include "sakamoto_product_core_ffi.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum
{
  STATUS_VALUE_COUNT = 14,
  CONNECT_VALUE_COUNT = STATUS_VALUE_COUNT + 1,
};

static void
status_reset (sakamoto_product_status_t *status, uint64_t generation)
{
  memset (status, 0, sizeof (*status));
  status->abi_version = SAKAMOTO_PRODUCT_ABI_VERSION;
  status->api_version = SAKAMOTO_PRODUCT_API_VERSION;
  status->generation = generation;
  status->status_code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  strncpy (status->error_detail, "invalid Product Core JNI arguments",
           sizeof (status->error_detail) - 1U);
}

static jobjectArray
status_values (JNIEnv *env, const sakamoto_product_status_t *status,
               jlong handle, int include_handle)
{
  jclass string_class = (*env)->FindClass (env, "java/lang/String");
  if (string_class == NULL)
    return NULL;
  const jsize length = include_handle ? CONNECT_VALUE_COUNT : STATUS_VALUE_COUNT;
  jobjectArray values = (*env)->NewObjectArray (env, length, string_class, NULL);
  (*env)->DeleteLocalRef (env, string_class);
  if (values == NULL)
    return NULL;

  char numeric[32];
  const char *fields[CONNECT_VALUE_COUNT];
  int index = 0;
  if (include_handle)
    {
      snprintf (numeric, sizeof (numeric), "%" PRId64, (int64_t) handle);
      fields[index++] = numeric;
    }

  char code[32];
  char generation[32];
  char core_ready[2];
  char adapter_available[2];
  char protection_running[2];
  char plugin_loaded[2];
  char vapi_handle_live[2];
  char generation_live[2];
  char abi_version[32];
  char api_version[32];
  snprintf (code, sizeof (code), "%" PRIu32, status->status_code);
  snprintf (generation, sizeof (generation), "%" PRIu64, status->generation);
  snprintf (abi_version, sizeof (abi_version), "%" PRIu32, status->abi_version);
  snprintf (api_version, sizeof (api_version), "%" PRIu32, status->api_version);
  core_ready[0] = status->core_ready ? '1' : '0';
  core_ready[1] = '\0';
  adapter_available[0] = status->adapter_available ? '1' : '0';
  adapter_available[1] = '\0';
  protection_running[0] = status->protection_running ? '1' : '0';
  protection_running[1] = '\0';
  plugin_loaded[0] = status->plugin_loaded ? '1' : '0';
  plugin_loaded[1] = '\0';
  vapi_handle_live[0] = status->vapi_handle_live ? '1' : '0';
  vapi_handle_live[1] = '\0';
  generation_live[0] = status->generation_live ? '1' : '0';
  generation_live[1] = '\0';

  fields[index++] = code;
  fields[index++] = generation;
  fields[index++] = core_ready;
  fields[index++] = adapter_available;
  fields[index++] = protection_running;
  fields[index++] = plugin_loaded;
  fields[index++] = vapi_handle_live;
  fields[index++] = generation_live;
  fields[index++] = status->artifact_id;
  fields[index++] = status->api_identity;
  fields[index++] = status->vpp_revision;
  fields[index++] = status->error_detail;
  fields[index++] = abi_version;
  fields[index++] = api_version;

  for (int value_index = 0; value_index < index; ++value_index)
    {
      jstring value = (*env)->NewStringUTF (env, fields[value_index]);
      if (value == NULL)
        return NULL;
      (*env)->SetObjectArrayElement (env, values, value_index, value);
      (*env)->DeleteLocalRef (env, value);
    }
  return values;
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeConnect (
    JNIEnv *env, jclass clazz, jstring api_socket, jlong generation)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *handle = NULL;
  const char *socket = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (api_socket != NULL && generation > 0)
    {
      socket = (*env)->GetStringUTFChars (env, api_socket, NULL);
      if (socket == NULL)
        return NULL;
      jsize socket_length = (*env)->GetStringUTFLength (env, api_socket);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) socket,
        .length = (uint32_t) socket_length,
      };
      code = sakamoto_product_core_connect (bytes, (uint64_t) generation,
                                            &handle, &status);
      (*env)->ReleaseStringUTFChars (env, api_socket, socket);
    }
  /* Keep the function return and status tag consistent at the JNI seam. */
  if (status.status_code != code)
    status.status_code = code;
  jobjectArray values = status_values (
      env, &status, (jlong) (intptr_t) handle, 1);
  if (values == NULL && handle != NULL)
    (void) sakamoto_product_core_destroy (handle);
  return values;
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeQuery (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  uint32_t code = sakamoto_product_core_query (
      native_handle, generation > 0 ? (uint64_t) generation : 0U, &status);
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeDisconnect (
    JNIEnv *env, jclass clazz, jlong handle)
{
  (void) env;
  (void) clazz;
  return (jint) sakamoto_product_core_disconnect (
      (sakamoto_product_core_handle_t *) (intptr_t) handle);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeDestroy (
    JNIEnv *env, jclass clazz, jlong handle)
{
  (void) env;
  (void) clazz;
  return (jint) sakamoto_product_core_destroy (
      (sakamoto_product_core_handle_t *) (intptr_t) handle);
}
