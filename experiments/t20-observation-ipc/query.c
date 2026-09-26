#include "ipc.h"
#include <stdlib.h>
int main(int argc,char **argv)
{
  if(argc!=3)return 2;
  ipc *h=ipc_open(argv[1],-2,strtoull(argv[2],0,10),0);
  if(!h)return 3;
  ipc_report(h,"independent_query");ipc_close(h);return 0;
}
