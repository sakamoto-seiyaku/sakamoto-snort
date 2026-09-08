/* Host-only source-port selection; device node trace must independently agree. */
#include "product_packet.h"
#include <stdio.h>
int main(void) {
  unsigned char p[28]={0x45,0,0,28,0,0,0,0,64,17};
  p[12]=p[16]=127; p[15]=p[19]=1;
  p[22]=40403>>8; p[23]=40403&255; p[25]=8;
  product_worker_layout_t layout={.worker_count=2,.hash_seed=UINT64_C(0x6f776e65722d3137)};
  int found[2]={0};
  for (unsigned port=30000;port<30100;port++) {
    p[20]=port>>8;p[21]=port&255;
    product_packet_ingress_t in={.data=p,.length=sizeof(p),.current_worker=0,.origin_obligation_id=1};
    product_packet_lease_t lease;
    if(product_packet_admit(&layout,&in,&lease)) return 2;
    if (!found[lease.assignment.execution_owner]) {printf("owner%u=%u\n",lease.assignment.execution_owner,port);found[lease.assignment.execution_owner]=1;}
    if(found[0]&&found[1])return 0;
  }
  return 3;
}
