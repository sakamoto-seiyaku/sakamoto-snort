/* SPDX-License-Identifier: Apache-2.0 */

#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define CONTROL_PATH_SIZE 1024

extern int sakamoto_rust_vpp_control_probe (const char *api_sock,
                                            const char *log_path,
                                            int32_t block_owner_uid,
                                            int32_t rounds);
extern int sakamoto_rust_vpp_reconnect_probe (const char *api_sock,
                                              const char *log_path,
                                              const char *stale_marker,
                                              const char *reopen_marker,
                                              int32_t timeout_seconds);

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeRunRustVppControlProbe (
    JNIEnv *env, jclass clazz, jstring files_dir, jint block_owner_uid, jint rounds)
{
  const char *files = NULL;
  char api_sock[CONTROL_PATH_SIZE];
  char log_path[CONTROL_PATH_SIZE];
  int rc;

  (void) clazz;
  if (files_dir == NULL)
    return -1;
  files = (*env)->GetStringUTFChars (env, files_dir, NULL);
  if (files == NULL)
    return -2;
  if (snprintf (api_sock, sizeof (api_sock), "%s/vpp/runtime/api.sock", files)
          >= (int) sizeof (api_sock)
      || snprintf (log_path, sizeof (log_path),
                   "%s/vpp/logs/rust-vapi-control-probe.log", files)
             >= (int) sizeof (log_path))
    {
      (*env)->ReleaseStringUTFChars (env, files_dir, files);
      return -3;
    }

  rc = sakamoto_rust_vpp_control_probe (api_sock, log_path, block_owner_uid, rounds);
  (*env)->ReleaseStringUTFChars (env, files_dir, files);
  return rc;
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeRunRustVppReconnectProbe (
    JNIEnv *env, jclass clazz, jstring files_dir, jint timeout_seconds)
{
  const char *files = NULL;
  char api_sock[CONTROL_PATH_SIZE];
  char log_path[CONTROL_PATH_SIZE];
  char stale_marker[CONTROL_PATH_SIZE];
  char reopen_marker[CONTROL_PATH_SIZE];
  int rc;

  (void) clazz;
  if (files_dir == NULL)
    return -1;
  files = (*env)->GetStringUTFChars (env, files_dir, NULL);
  if (files == NULL)
    return -2;
  if (snprintf (api_sock, sizeof (api_sock), "%s/vpp/runtime/api.sock", files)
          >= (int) sizeof (api_sock)
      || snprintf (log_path, sizeof (log_path),
                   "%s/vpp/logs/rust-vapi-reconnect-probe.log", files)
             >= (int) sizeof (log_path)
      || snprintf (stale_marker, sizeof (stale_marker),
                   "%s/vpp/runtime/reconnect-stale", files)
             >= (int) sizeof (stale_marker)
      || snprintf (reopen_marker, sizeof (reopen_marker),
                   "%s/vpp/runtime/reconnect-reopen", files)
             >= (int) sizeof (reopen_marker))
    {
      (*env)->ReleaseStringUTFChars (env, files_dir, files);
      return -3;
    }

  rc = sakamoto_rust_vpp_reconnect_probe (api_sock, log_path, stale_marker,
                                           reopen_marker, timeout_seconds);
  (*env)->ReleaseStringUTFChars (env, files_dir, files);
  return rc;
}
