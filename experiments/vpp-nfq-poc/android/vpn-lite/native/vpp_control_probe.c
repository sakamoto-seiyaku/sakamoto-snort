/* SPDX-License-Identifier: Apache-2.0 */

#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tun_poc_control_shim.h"

#define CONTROL_PATH_SIZE 1024

static void
write_status (FILE *log, const char *label, const tun_poc_status_out_t *status)
{
  fprintf (log,
           "%s retval=%d enabled=%u mode=%u owner_cache=%u block_uid_set=%u "
           "block_uid=%d last_uid=%d rx=%llu tx=%llu shim_tx=%llu blocked=%llu "
           "resolver_queries=%llu resolver_hits=%llu owner_cache_hits=%llu "
           "uid_blocked=%llu\n",
           label, status->retval, status->enabled, status->mode,
           status->owner_cache_enabled, status->block_owner_uid_set,
           status->block_owner_uid, status->last_owner_uid,
           (unsigned long long) status->rx_packets,
           (unsigned long long) status->tx_packets,
           (unsigned long long) status->shim_tx_packets,
           (unsigned long long) status->blocked_packets,
           (unsigned long long) status->resolver_queries,
           (unsigned long long) status->resolver_hits,
           (unsigned long long) status->owner_cache_hits,
           (unsigned long long) status->uid_blocked_packets);
}

static int
run_control_round (FILE *log, const char *api_sock, int32_t block_owner_uid, int round)
{
  tun_poc_client_t *client = NULL;
  tun_poc_status_out_t status;
  tun_poc_owner_policy_t policy;
  int32_t vpp_retval = -1;
  int rc;

  fprintf (log, "round=%d begin\n", round);
  rc = tun_poc_client_open (api_sock, &client);
  fprintf (log, "round=%d open_rc=%d\n", round, rc);
  if (rc != 0)
    return rc;

  rc = tun_poc_client_status_get (client, &status);
  fprintf (log, "round=%d status_before_rc=%d\n", round, rc);
  if (rc != 0)
    goto close;
  write_status (log, "status_before", &status);

  memset (&policy, 0, sizeof (policy));
  policy.owner_cache_enabled = 1;
  policy.block_owner_uid_set = 1;
  policy.block_owner_uid = block_owner_uid;
  rc = tun_poc_client_owner_policy_set (client, &policy, &vpp_retval);
  fprintf (log, "round=%d policy_set_rc=%d policy_set_vpp_retval=%d\n",
           round, rc, vpp_retval);
  if (rc != 0 || vpp_retval != 0)
    goto close;

  rc = tun_poc_client_status_get (client, &status);
  fprintf (log, "round=%d status_set_rc=%d\n", round, rc);
  if (rc != 0)
    goto close;
  write_status (log, "status_set", &status);
  if (!status.owner_cache_enabled || !status.block_owner_uid_set
      || status.block_owner_uid != block_owner_uid)
    {
      rc = -20;
      goto close;
    }

  memset (&policy, 0, sizeof (policy));
  vpp_retval = -1;
  rc = tun_poc_client_owner_policy_set (client, &policy, &vpp_retval);
  fprintf (log, "round=%d policy_clear_rc=%d policy_clear_vpp_retval=%d\n",
           round, rc, vpp_retval);
  if (rc != 0 || vpp_retval != 0)
    goto close;

  rc = tun_poc_client_status_get (client, &status);
  fprintf (log, "round=%d status_after_rc=%d\n", round, rc);
  if (rc == 0)
    write_status (log, "status_after", &status);
  if (rc == 0 && (status.owner_cache_enabled || status.block_owner_uid_set))
    rc = -21;

close:
  fprintf (log, "round=%d close_rc=%d result=%s\n", round,
           tun_poc_client_close (client), rc == 0 ? "pass" : "fail");
  return rc;
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_vpnlite_SnortVpnService_nativeRunVppControlProbe (
    JNIEnv *env, jclass clazz, jstring files_dir, jint block_owner_uid, jint rounds)
{
  const char *files = NULL;
  char api_sock[CONTROL_PATH_SIZE];
  char log_path[CONTROL_PATH_SIZE];
  FILE *log = NULL;
  int result = 0;
  int i;

  (void) clazz;
  if (files_dir == NULL)
    return -1;
  files = (*env)->GetStringUTFChars (env, files_dir, NULL);
  if (files == NULL)
    return -2;
  if (snprintf (api_sock, sizeof (api_sock), "%s/vpp/runtime/api.sock", files)
      >= (int) sizeof (api_sock)
      || snprintf (log_path, sizeof (log_path), "%s/vpp/logs/vapi-control-probe.log",
                   files) >= (int) sizeof (log_path))
    {
      (*env)->ReleaseStringUTFChars (env, files_dir, files);
      return -3;
    }

  log = fopen (log_path, "w");
  if (log == NULL)
    {
      (*env)->ReleaseStringUTFChars (env, files_dir, files);
      return -4;
    }

  if (rounds < 1)
    rounds = 1;
  if (rounds > 20)
    rounds = 20;
  fprintf (log, "abi_version=%u uid=%d api_sock=%s rounds=%d\n",
           tun_poc_control_shim_abi_version (), (int) getuid (), api_sock,
           (int) rounds);
  for (i = 1; i <= rounds; i++)
    {
      int rc = run_control_round (log, api_sock, block_owner_uid, i);
      if (rc != 0 && result == 0)
        result = rc;
    }
  fprintf (log, "result=%s rc=%d\n", result == 0 ? "pass" : "fail", result);
  fclose (log);
  (*env)->ReleaseStringUTFChars (env, files_dir, files);
  return result;
}
