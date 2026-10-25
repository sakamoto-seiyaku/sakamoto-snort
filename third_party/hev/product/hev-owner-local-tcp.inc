/* SPDX-License-Identifier: MIT */
/* Private byte-stream endpoint, sharing the existing owner/lwIP lifetime.
 * No Direct fd, broker request, task, policy engine or DNS-ID authority. */
static local_tcp_output_t *local_tcp_first(owner_session_t *s)
{
  local_tcp_output_t *found=NULL;
  for(unsigned i=0;i<HEV_OWNER_LOCAL_TCP_PENDING;++i) {
    local_tcp_output_t *o=&s->owner->local_outputs[i];
    if(o->session==s->id && o->wire && (!found || o->order<found->order))found=o;
  }
  return found;
}
static void local_tcp_output_facts(owner_session_t *s,hev_owner_facts_t *facts)
{
  local_tcp_output_t *o=local_tcp_first(s);
  if(!o || !o->written)return;
  facts->local_reply_token=o->token;
  facts->underlay_epoch=o->binding.underlay_epoch;
  facts->network_context=o->binding.network_context;
  facts->availability &= ~HEV_OWNER_CONTEXT_KNOWN;
  if(o->binding.context_known)facts->availability |= HEV_OWNER_CONTEXT_KNOWN;
}
static void local_tcp_release(hev_owner_t *owner,local_tcp_output_t *o,int success)
{
  uint64_t session=o->session,token=o->token;
  if(o->wire) {
    owner->stats.local_tcp_bytes-=o->length;
    --owner->stats.local_tcp_outputs;
    if(success)++owner->stats.local_tcp_delivered;else ++owner->stats.local_tcp_failed;
  } else --owner->stats.local_tcp_pending;
  free(o->wire);memset(o,0,sizeof(*o));
  if(owner->config.local_tcp_done)
    owner->config.local_tcp_done(owner->config.opaque,owner->config.generation,session,token,success);
}
static void local_tcp_cleanup(owner_session_t *s)
{
  hev_owner_t *owner=s->owner;
  for(unsigned i=0;i<HEV_OWNER_LOCAL_TCP_PENDING;++i)
    if(owner->local_outputs[i].session==s->id)local_tcp_release(owner,&owner->local_outputs[i],0);
  owner->stats.local_tcp_bytes-=sizeof(local_tcp_t);
  --owner->stats.local_tcp_sessions;free(s->local_tcp);s->local_tcp=NULL;
}
static err_t local_tcp_receive(void *opaque,struct tcp_pcb *pcb,struct pbuf *p,err_t error)
{
  owner_session_t *s=opaque;local_tcp_t *c=s->local_tcp;
  if(error!=ERR_OK || s->closing || !s->owner->stats.running)return ERR_MEM;
  if(!p) {c->eof=1;return ERR_OK;}
  if(p->tot_len>sizeof(c->input)-c->used)return ERR_MEM;
  if(pbuf_copy_partial(p,c->input+c->used,p->tot_len,0)!=p->tot_len)return ERR_MEM;
  if(!c->used)c->partial_deadline=now_ms()+10000;
  c->used+=p->tot_len;c->idle_deadline=now_ms()+30000;
  tcp_recved(pcb,p->tot_len);pbuf_free(p);return ERR_OK;
}
static err_t local_tcp_sent(void *opaque,struct tcp_pcb *pcb,u16_t bytes)
{
  owner_session_t *s=opaque;(void)pcb;
  local_tcp_output_t *o=local_tcp_first(s);
  if(!o || bytes>o->written-o->acked) {close_session(s,"local_tcp_ack_conflict");return ERR_OK;}
  o->acked+=bytes;
  s->local_tcp->idle_deadline=now_ms()+30000;
  if(o->acked==o->length)local_tcp_release(s->owner,o,1);
  return ERR_OK;
}
static int local_tcp_timeout(owner_session_t *s)
{
  uint64_t next=s->local_tcp->used?s->local_tcp->partial_deadline:s->local_tcp->idle_deadline;
  for(unsigned i=0;i<HEV_OWNER_LOCAL_TCP_PENDING;++i)
    if(s->owner->local_outputs[i].session==s->id && s->owner->local_outputs[i].deadline<next)
      next=s->owner->local_outputs[i].deadline;
  uint64_t now=now_ms();return next>now?(int)(next-now):0;
}
static int local_tcp_step(owner_session_t *s)
{
  if(!s->pcb)return 0;
  if(!s->closing && !local_tcp_timeout(s))close_session(s,"local_tcp_expired");
  if(s->closing) {tcp_abort(s->pcb);return 0;}
  local_tcp_t *c=s->local_tcp;
  int runnable=0;
  local_tcp_output_t *o=local_tcp_first(s);
  if(o && s->tcp_accepted && !c->fin) {
    size_t count=o->length-o->written;
    if(count>tcp_sndbuf(s->pcb))count=tcp_sndbuf(s->pcb);
    if(count>16384)count=16384;
    if(count) {
      err_t result=tcp_write(s->pcb,o->wire+o->written,(u16_t)count,TCP_WRITE_FLAG_COPY);
      if(result==ERR_OK) {
        o->written+=count;
        /* Continue only after actual write progress with remaining capacity.
         * ERR_MEM, a full sndbuf and an ACK wait need their event/TCP deadline,
         * never an occupancy-based polling turn. */
        runnable=o->written<o->length && tcp_sndbuf(s->pcb)>0;
      }
      else if(result!=ERR_MEM)close_session(s,"local_tcp_write_failed");
    }
    if(!s->closing && o->written)tcp_output(s->pcb);
  }
  int pending=0;
  for(unsigned i=0;i<HEV_OWNER_LOCAL_TCP_PENDING;++i)
    if(s->owner->local_outputs[i].session==s->id)pending=1;
  if(c->eof && !pending && !c->used && !c->fin) {
    /* FIN is transport state; the ext-arg keeps identity until final PCB death. */
    if(tcp_close(s->pcb)==ERR_OK)c->fin=1;
  }
  if(c->eof && !pending && c->used && (c->used<2 || c->used<(size_t)(((unsigned)c->input[0]<<8)|c->input[1])+2))
    close_session(s,"local_tcp_partial_fin");
  return runnable || s->closing;
}
uint64_t hev_owner_local_tcp_reservation(const hev_owner_t *owner)
{
  /* Owned input/output copies plus worst-case lwIP COPY sndbuf per client.
   * The existing lwIP heap/pbuf/PCB budgets independently cap its allocations. */
  return owner?HEV_OWNER_LOCAL_TCP_BYTES+HEV_OWNER_LOCAL_TCP_CLIENTS*(uint64_t)TCP_SND_BUF+
    sizeof(owner->local_outputs):0;
}
int hev_owner_local_tcp_next(hev_owner_t *owner,uint64_t generation,uint64_t *session,
  uint64_t *token,uint8_t *message,size_t capacity,size_t *length)
{
  owner_scope_t scope;
  if(!owner || generation!=owner->config.generation || !session || !token || !message || !length || enter(owner,&scope))return -1;
  int result=0;
  for(owner_session_t *s=owner->sessions;s;s=s->next) {
    if(!s->local_tcp || s->closing || !owner->stats.running)continue;
    local_tcp_t *c=s->local_tcp;
    if(c->used<2)continue;
    size_t n=((unsigned)c->input[0]<<8)|c->input[1];
    if(c->used<n+2)continue;
    if(n>capacity || owner->local_token==UINT64_MAX) {close_session(s,"local_tcp_read_capacity");result=-1;break;}
    local_tcp_output_t *free_output=NULL;
    for(unsigned i=0;i<HEV_OWNER_LOCAL_TCP_PENDING;++i)
      if(!owner->local_outputs[i].session){free_output=&owner->local_outputs[i];break;}
    if(!free_output){close_session(s,"local_tcp_pending_capacity");result=-1;break;}
    *session=s->id;*token=++owner->local_token;*length=n;
    memcpy(message,c->input+2,n);c->used-=n+2;memmove(c->input,c->input+n+2,c->used);
    c->partial_deadline=c->used?now_ms()+10000:0;
    *free_output=(local_tcp_output_t){.session=s->id,.token=*token,.deadline=now_ms()+10000};
    ++owner->stats.local_tcp_pending;
    if(owner->stats.local_tcp_pending>owner->stats.local_tcp_pending_peak)
      owner->stats.local_tcp_pending_peak=owner->stats.local_tcp_pending;
    ++owner->stats.local_tcp_frames;result=1;break;
  }
  leave(owner,&scope);return result;
}
int hev_owner_local_tcp_reply(hev_owner_t *owner,uint64_t generation,uint64_t session,
  uint64_t token,const uint8_t *message,size_t length,const hev_owner_binding_t *binding)
{
  owner_scope_t scope;
  if(!owner || generation!=owner->config.generation || !message || length>65535 || enter(owner,&scope))return -1;
  int result=-1;
  owner_session_t *client=owner->sessions;
  while(client && client->id!=session)client=client->next;
  if(!client || !client->local_tcp || client->closing) {leave(owner,&scope);return -1;}
  for(unsigned i=0;i<HEV_OWNER_LOCAL_TCP_PENDING;++i) {
    local_tcp_output_t *o=&owner->local_outputs[i];
    if(o->session!=session || o->token!=token || o->wire || !owner->stats.running)continue;
    if(owner->stats.local_tcp_bytes+length+2>HEV_OWNER_LOCAL_TCP_BYTES || owner->local_order==UINT64_MAX)break;
    uint8_t *wire=malloc(length+2);if(!wire)break;
    wire[0]=length>>8;wire[1]=length;memcpy(wire+2,message,length);
    o->wire=wire;o->length=length+2;o->order=++owner->local_order;o->deadline=now_ms()+10000;
    if(binding)o->binding=*binding;
    --owner->stats.local_tcp_pending;++owner->stats.local_tcp_outputs;
    if(owner->stats.local_tcp_outputs>owner->stats.local_tcp_output_peak)
      owner->stats.local_tcp_output_peak=owner->stats.local_tcp_outputs;
    owner->stats.local_tcp_bytes+=length+2;
    if(owner->stats.local_tcp_bytes>owner->stats.local_tcp_peak_bytes)owner->stats.local_tcp_peak_bytes=owner->stats.local_tcp_bytes;
    result=0;break;
  }
  leave(owner,&scope);return result;
}
