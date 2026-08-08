/* SPDX-License-Identifier: Apache-2.0 */

#include "sakamoto_vpp_control.h"

#include <jni.h>
#include <stdio.h>

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeQuery(
    JNIEnv *env, jclass clazz, jstring api_socket)
{
  const char *socket = NULL;
  sakamoto_vpp_core_status_t status;
  jobjectArray values;
  jclass string_class;
  jstring value;
  const char *fields[8];
  char numeric[32];
  char transport[32];
  char retval[32];
  int rc;
  int i;

  (void)clazz;
  if (api_socket == NULL)
    return NULL;
  socket = (*env)->GetStringUTFChars(env, api_socket, NULL);
  if (socket == NULL)
    return NULL;
  rc = sakamoto_vpp_core_status_get(socket, &status);
  (*env)->ReleaseStringUTFChars(env, api_socket, socket);

  snprintf(numeric, sizeof(numeric), "%u", status.control_abi_version);
  fields[0] = numeric;
  fields[1] = status.api_identity;
  fields[2] = status.program;
  fields[3] = status.version;
  fields[4] = status.build_date;
  fields[5] = status.build_directory;
  snprintf(transport, sizeof(transport), "%d", rc);
  snprintf(retval, sizeof(retval), "%d", status.vpp_retval);
  fields[6] = transport;
  fields[7] = retval;

  string_class = (*env)->FindClass(env, "java/lang/String");
  if (string_class == NULL)
    return NULL;
  values = (*env)->NewObjectArray(env, 8, string_class, NULL);
  if (values == NULL)
    return NULL;
  for (i = 0; i < 8; ++i)
    {
      value = (*env)->NewStringUTF(env, fields[i]);
      if (value == NULL)
        return NULL;
      (*env)->SetObjectArrayElement(env, values, i, value);
      (*env)->DeleteLocalRef(env, value);
    }
  return values;
}
