/* Current typed Product policy, shared by the TUN protocol acceptance cases. */
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static sakamoto_product_bytes_t bytes(const char *s) {
  return (sakamoto_product_bytes_t){(const uint8_t *)s,(uint32_t)strlen(s)};
}
int main(int argc,char **argv) {
  if(argc!=10)return 2; /* socket generation files revision mode uid family protocol source-port */
  uint64_t generation=strtoull(argv[2],0,10);
  sakamoto_product_core_handle_t *handle=0;sakamoto_product_status_t status={0};
  uint32_t code=sakamoto_product_core_connect(bytes(argv[1]),generation,&handle,&status);if(code)return code;
  sakamoto_product_policy_bundle_t b={0};b.abi_version=SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION;b.struct_size=sizeof(b);
  b.requested_revision=strtoull(argv[4],0,10);b.snapshot_hash=b.requested_revision;b.default_pass=1;
  snprintf(b.snapshot_identity,sizeof(b.snapshot_identity),"s198/revision/%s",argv[4]);
  int mode=atoi(argv[5]);unsigned protocol=strtoul(argv[8],0,10),port=strtoul(argv[9],0,10);
  if(mode){
    sakamoto_product_policy_rule_entry_t *r=mode==1?&b.gate_entries[0]:&b.l4_entries[0];
    if(mode==1)b.gate_entry_count=1;else b.l4_rule_count=1;
    r->subject_uid=strtoul(argv[6],0,10);r->network_context=UINT32_MAX;r->ifindex=SAKAMOTO_PRODUCT_POLICY_IFINDEX_ANY;
    r->rule_kind=mode==1?SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE:SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4;
    r->action=SAKAMOTO_PRODUCT_POLICY_ACTION_DROP;r->enabled=1;r->rule_id=b.requested_revision;r->reason_id=198;
    if(mode!=1){
      r->ip_family=strtoul(argv[7],0,10);r->ip_protocol=protocol;
      r->direction=SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT;
      r->source_port_first=r->source_port_last=port;r->destination_port_first=r->destination_port_last=40634;
    }
  }
  code=sakamoto_product_core_apply_policy_bundle(handle,generation,bytes(argv[3]),&b,&status);
  printf("policy rc=%u generation=%llu revision=%llu mode=%d family=%s protocol=%u port=%u detail=%s\n",code,(unsigned long long)generation,(unsigned long long)b.requested_revision,mode,argv[7],protocol,port,status.error_detail);
  sakamoto_product_core_disconnect(handle);sakamoto_product_core_destroy(handle);return code;
}
