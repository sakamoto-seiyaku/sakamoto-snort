/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_tcp.h"
#include "product_protocol_catalog.h"
#include <stdlib.h>
#include <string.h>

#define WINDOW (PRODUCT_DNS_MESSAGE_MAX + 2U)
#define PRESENT ((WINDOW + 7U) / 8U)
typedef struct {
  uint8_t bytes[WINDOW], present[PRESENT];
  product_dns_context_t context;
  uint64_t deadline, messages;
  uint32_t base, initial, head, contiguous, span;
  uint8_t anchored, failed, context_valid;
} dns_tcp_side_t;
struct product_dns_tcp_flow {
  product_dns_context_t context;
  product_dns_identity_t identity;
  dns_tcp_side_t side[2];
  product_dns_tcp_event_t fact[2];
  product_dns_policy_identity_t checked;
  uint32_t bound_context;
  uint8_t fact_valid[2], blocked, processing, retired, bound_context_known;
};
_Static_assert(sizeof(product_dns_tcp_flow_t) <= PRODUCT_DNS_TCP_FLOW_BYTES,
  "TCP observation is bounded by the bidirectional flow budget");
_Static_assert(sizeof(product_dns_owner_t) + sizeof(product_dns_tcp_owner_t) +
  PRODUCT_DNS_TCP_FLOWS * sizeof(product_dns_tcp_flow_t) + PRODUCT_DNS_CODEC_BYTES +
  PRODUCT_DNS_MESSAGE_MAX + 2U * sizeof(product_dns_tcp_event_t) < PRODUCT_DNS_WORK_BYTES,
  "requests, TCP byte copies and synchronous codec/events fit the owner work budget");

static int tuple(const product_l4_policy_packet_t *a,const product_l4_policy_packet_t *b,int reverse)
{
  return a->family==b->family && a->protocol==b->protocol &&
    a->source_port==(reverse?b->destination_port:b->source_port) &&
    a->destination_port==(reverse?b->source_port:b->destination_port) &&
    !memcmp(a->source_address,reverse?b->destination_address:b->source_address,16) &&
    !memcmp(a->destination_address,reverse?b->source_address:b->destination_address,16);
}
static int context_matches(const product_dns_tcp_flow_t *f,const product_dns_tcp_input_t *i)
{
  if(f->identity.generation!=i->identity.generation ||
     f->identity.network_revision!=i->identity.network_revision ||
     f->identity.profile!=i->identity.profile ||
     (f->identity.incarnation && i->identity.incarnation &&
       f->identity.incarnation!=i->identity.incarnation) ||
     !(tuple(&f->context.packet,&i->context.packet,0) ||
       tuple(&f->context.packet,&i->context.packet,1))) return 0;
  if(i->identity.profile==2 && i->context.packet.direction==1)
    {
      if(!i->identity.incarnation || f->identity.incarnation!=i->identity.incarnation ||
         !i->identity.transport_session || f->identity.transport_session!=i->identity.transport_session)
        return 0;
      /* lwIP emits the local SYN/ACK before protect/bind completes. Its exact
       * session stamp may be consumed after the binding publication. Only this
       * byte-free handshake can anchor the reverse sequence without an epoch;
       * it never supplies resolver data or replaces the current binding. */
      if(!i->identity.underlay_epoch && i->flags==0x12 && !i->length &&
         !i->context.packet.network_context_known) return 1;
      return i->identity.underlay_epoch && f->identity.underlay_epoch==i->identity.underlay_epoch &&
        f->bound_context_known==i->context.packet.network_context_known &&
        (!f->bound_context_known || f->bound_context==i->context.packet.network_context_id);
    }
  return f->context.packet.network_context_known==i->context.packet.network_context_known &&
    (!f->context.packet.network_context_known ||
      f->context.packet.network_context_id==i->context.packet.network_context_id) &&
    f->context.packet.ifindex_known==i->context.packet.ifindex_known &&
    (!f->context.packet.ifindex_known || f->context.packet.ifindex==i->context.packet.ifindex);
}
void product_dns_tcp_start(product_dns_tcp_owner_t *owner,uint64_t generation)
{
  if(!owner) return;
  memset(owner,0,sizeof(*owner));owner->generation=generation;owner->accepting=!!generation;
}
static void release_flow(product_dns_tcp_owner_t *owner,unsigned slot)
{
  if(!owner->flows[slot]) return;
  free(owner->flows[slot]);owner->flows[slot]=NULL;
  --owner->active;owner->allocated_bytes-=sizeof(product_dns_tcp_flow_t);
}
void product_dns_tcp_stop(product_dns_tcp_owner_t *owner)
{
  if(!owner) return;
  owner->accepting=0;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n) release_flow(owner,n);
}
void product_dns_tcp_end(product_dns_tcp_owner_t *owner,uint64_t generation,uint64_t incarnation)
{
  if(!owner || owner->generation!=generation || !incarnation) return;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    if(owner->flows[n] && owner->flows[n]->identity.incarnation==incarnation)
      {
        if(owner->flows[n]->processing) owner->flows[n]->retired=1;
        else release_flow(owner,n);
      }
}
void product_dns_tcp_bind(product_dns_tcp_owner_t *owner,product_dns_owner_t *requests,const product_dns_context_t *context,
  const product_dns_identity_t *identity)
{
  if(!owner || !context || !identity || !owner->accepting ||
    owner->generation!=identity->generation || !identity->incarnation) return;
  product_dns_tcp_input_t input={.context=*context,.identity=*identity};
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    if(owner->flows[n] && !owner->flows[n]->identity.incarnation && context_matches(owner->flows[n],&input))
      {
        owner->flows[n]->identity.incarnation=identity->incarnation;
        /* An allowed SYN with DNS data can decide before FlowRuntime creates
         * its incarnation. Bind only that pending tuple after actual admission. */
        if(requests && requests->accepting && requests->generation==identity->generation)
          for(unsigned r=0;r<PRODUCT_DNS_REQUESTS;++r)
            {
              product_dns_request_t *request=&requests->requests[r];
              if(request->active && !request->identity.incarnation &&
                request->query.packet.protocol==6 &&
                request->identity.generation==identity->generation &&
                request->identity.network_revision==identity->network_revision &&
                tuple(&request->query.packet,&context->packet,0))
                request->identity.incarnation=identity->incarnation;
            }
      }
}
void product_dns_tcp_transport(product_dns_tcp_owner_t *owner,uint64_t generation,
  uint64_t incarnation,uint64_t session,uint64_t epoch,uint32_t context,int known)
{
  if(!owner || !owner->accepting || owner->generation!=generation || !incarnation || !session) return;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {
      product_dns_tcp_flow_t *f=owner->flows[n];
      if(!f || f->identity.profile!=2 || f->identity.incarnation!=incarnation ||
        (f->identity.transport_session && f->identity.transport_session!=session) ||
        (f->identity.underlay_epoch && f->identity.underlay_epoch!=epoch)) continue;
      f->identity.transport_session=session;f->identity.underlay_epoch=epoch;
      f->bound_context=context;f->bound_context_known=!!known;
    }
}
void product_dns_tcp_transport_bound(product_dns_tcp_owner_t *owner,uint64_t generation,
  uint64_t session,uint64_t epoch,uint32_t context,int known)
{
  if(!owner || !owner->accepting || owner->generation!=generation || !session || !epoch) return;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {
      product_dns_tcp_flow_t *f=owner->flows[n];
      if(!f || f->identity.profile!=2 || f->identity.transport_session!=session ||
        f->identity.underlay_epoch) continue;
      f->identity.underlay_epoch=epoch;
      f->bound_context=context;f->bound_context_known=!!known;
    }
}
void product_dns_tcp_expire(product_dns_tcp_owner_t *owner,uint64_t now)
{
  if(!owner) return;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {
      product_dns_tcp_flow_t *flow=owner->flows[n];
      if(!flow) continue;
      if(!flow->identity.incarnation && !flow->blocked &&
          flow->identity.now_us+PRODUCT_DNS_REQUEST_US<=now)
        {release_flow(owner,n);++owner->expired;continue;}
      for(unsigned s=0;s<2;++s)
        {
          dns_tcp_side_t *side=&flow->side[s];
          if(side->span && !side->failed && side->deadline<=now)
            {
              memset(side->bytes,0,sizeof(side->bytes));
              memset(side->present,0,sizeof(side->present));
              side->span=side->contiguous=0;side->context_valid=0;
              side->failed=PRODUCT_DNS_TCP_EXPIRED;++owner->expired;
            }
        }
    }
}
uint64_t product_dns_tcp_deadline(const product_dns_tcp_owner_t *owner)
{
  uint64_t next=UINT64_MAX;
  if(!owner || !owner->accepting) return next;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {
      const product_dns_tcp_flow_t *flow=owner->flows[n];if(!flow) continue;
      if(!flow->identity.incarnation && !flow->blocked &&
          flow->identity.now_us+PRODUCT_DNS_REQUEST_US<next)
        next=flow->identity.now_us+PRODUCT_DNS_REQUEST_US;
      for(unsigned s=0;s<2;++s)
        if(flow->side[s].span && !flow->side[s].failed && flow->side[s].deadline<next)
          next=flow->side[s].deadline;
    }
  return next;
}
static int present(const dns_tcp_side_t *side,unsigned offset)
{
  unsigned at=(side->head+offset)%WINDOW;
  return !!(side->present[at/8] & (1U<<(at%8)));
}
static uint8_t byte(const dns_tcp_side_t *side,unsigned offset)
{ return side->bytes[(side->head+offset)%WINDOW]; }
static void consume(dns_tcp_side_t *side,unsigned size)
{
  for(unsigned n=0;n<size;++n)
    {
      unsigned at=(side->head+n)%WINDOW;
      side->present[at/8]&=~(1U<<(at%8));
    }
  side->head=(side->head+size)%WINDOW;side->base+=size;
  side->contiguous-=size;side->span-=size;
  if(!side->span) {side->context_valid=0;side->deadline=0;}
}
static void coverage(const product_dns_tcp_input_t *input,unsigned reason,
  product_dns_tcp_observer_t observer,void *context)
{
  product_dns_tcp_event_t event={.stage=input->context.packet.direction==3?1:2,
    .sequence=input->sequence};
  product_dns_inspect_query(NULL,0,&input->context,&event.facts.question);
  event.facts.question.coverage=reason;
  event.facts.question.tcp_sequence=input->sequence;
  event.status=product_l4_policy_match_position(input->view,&event.facts.question.packet,
    PRODUCT_L4_POLICY_POSITION_ALL,&event.match);
  if(event.stage==2) event.facts.correlation=PRODUCT_DNS_UNMATCHED;
  observer(context,&event);
}
static int policy_rejection(const product_dns_tcp_input_t *input,const product_dns_tcp_event_t *event)
{
  return !event->status && event->match.actual_action==PRODUCT_L4_POLICY_ACTION_DROP &&
    event->match.rule_index<input->view->rule_count &&
    product_static_expression_domain_references(input->view->rules[event->match.rule_index].source.expression,
      input->view->rules[event->match.rule_index].source.expression_length)!=0;
}
static void current_names(const product_dns_tcp_input_t *input,product_dns_tcp_event_t *event)
{
  product_dns_query_t *question=&event->facts.question;
  int available=question->coverage==PRODUCT_DNS_QUERY_COMPLETE &&
    question->caller==PRODUCT_DNS_CALLER_PLATFORM_APP && input->context.domains_available &&
    (event->stage==1 || event->facts.correlation==PRODUCT_DNS_CORRELATED);
  for(unsigned n=0;n<event->facts.name_count;++n)
    {
      product_dns_name_t *name=&event->facts.names[n];name->lists=0;name->available=0;
      if(available) name->available=!product_domains_lookup_dns(input->context.domains,
        (const uint8_t *)name->name,name->length,&name->lists);
    }
  question->packet.domain_available=available && event->facts.name_count && event->facts.names[0].available;
  question->packet.domain_lists=question->packet.domain_available?event->facts.names[0].lists:0;
  if(question->coverage==PRODUCT_DNS_QUERY_COMPLETE)
    {
      question->packet.protocol_set|=product_protocol_bit(1001);
      question->packet.protocol_set_known=1;
    }
}
static void match_position(const product_dns_tcp_input_t *input,product_dns_tcp_event_t *event,
  product_l4_policy_position_t position)
{
  product_l4_policy_packet_t packet=event->facts.question.packet;
  /* First-byte caller evidence is immutable. An Unknown caller does not
   * freeze the ordinary packet UID used by independently applicable rules:
   * an asynchronous lookup can qualify this completing packet without
   * qualifying the original DNS caller or rewriting the retained question. */
  if(event->facts.question.caller==PRODUCT_DNS_CALLER_UNKNOWN)
    {packet.uid=input->context.packet.uid;packet.uid_known=input->context.packet.uid_known;}
  if(event->stage==1)
    event->status=product_l4_policy_match_position(input->view,&packet,
      position,&event->match);
  else
    event->status=product_dns_response_match(input->view,&packet,&event->facts,
      position,&event->match);
}
static void match_event(const product_dns_tcp_input_t *input,product_dns_tcp_flow_t *flow,
  product_dns_tcp_event_t *event,product_dns_identity_t *identity)
{
  match_position(input,event,input->flow_facts?PRODUCT_L4_POLICY_POSITION_PRE:PRODUCT_L4_POLICY_POSITION_ALL);
  if(event->status || event->match.evaluation || !input->flow_facts) return;
  product_l4_policy_packet_t current=input->context.packet;
  if(input->flow_facts(input->flow_context,&current,identity))
    {event->status=PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;return;}
  if(flow->retired)
    {
      /* The ordinary Flow stage can retire this tuple (for example a real
       * caller change). Its synchronous END cannot free an active framing
       * borrow, and bytes from that old incarnation cannot become new facts. */
      memset(&event->facts,0,sizeof(event->facts));
      product_dns_inspect_query(NULL,0,&input->context,&event->facts.question);
      event->facts.question.coverage=PRODUCT_DNS_TCP_MIDSTREAM;
      event->facts.question.tcp_sequence=input->sequence;
      event->stage=input->context.packet.direction==3?1:2;
      event->continuation=0;event->message_sequence=0;event->sequence=input->sequence;
      if(event->stage==2) event->facts.correlation=PRODUCT_DNS_UNMATCHED;
    }
  product_l4_policy_packet_t *packet=&event->facts.question.packet;
  packet->ct_state=current.ct_state;packet->ct_state_known=current.ct_state_known;
  packet->flow_direction=current.flow_direction;packet->flow_direction_known=current.flow_direction_known;
  if(tuple(packet,&current,1) && packet->flow_direction_known)
    packet->flow_direction=packet->flow_direction==1?2:1;
  packet->protocol_set=current.protocol_set;packet->protocol_set_known=current.protocol_set_known;
  packet->sni_result=current.sni_result;
  current_names(input,event);
  match_position(input,event,PRODUCT_L4_POLICY_POSITION_POST);
  if(!flow->identity.incarnation && identity->incarnation) flow->identity.incarnation=identity->incarnation;
}

static int recheck(product_dns_tcp_flow_t *flow,product_dns_owner_t *requests,const product_dns_tcp_input_t *input,
  product_dns_tcp_observer_t observer,void *context)
{
  int changed=flow->checked.generation!=input->policy.generation ||
    flow->checked.revision!=input->policy.revision || flow->checked.hash!=input->policy.hash;
  if(!flow->blocked && !changed) return 0;
  for(unsigned n=0;n<2;++n)
    {
      if(!flow->fact_valid[n] || (flow->blocked && flow->blocked!=n+1)) continue;
      product_dns_tcp_event_t event=flow->fact[n];event.continuation=1;
      event.facts.question.tcp_continuation=1;
      product_dns_identity_t identity=input->identity;
      current_names(input,&event);match_event(input,flow,&event,&identity);
      int restriction=policy_rejection(input,&event);
      if(!flow->retired && !event.status &&
          event.match.actual_action==PRODUCT_L4_POLICY_ACTION_DROP && !restriction)
        {
          /* A retained question/answer is not this packet's generic tuple or
           * direction. Do not publish its pure-generic winner as a new DNS
           * rejection or replace the current packet's ordinary policy seam. */
          flow->blocked=0;continue;
        }
      if(event.stage==1 && !event.status && !flow->retired &&
          event.match.actual_action!=PRODUCT_L4_POLICY_ACTION_DROP &&
          event.facts.correlation==PRODUCT_DNS_CORRELATION_NONE)
        {
          /* A once-rejected TCP frame can now progress via kernel retransmit.
           * Record its new allowed control point without rewriting the old
           * rejection. Previously admitted requests retain their own history. */
          product_dns_policy_identity_t policy=input->policy;
          policy.winner=event.match.evaluation?event.match.rule_id:0;
          event.facts.correlation=product_dns_remember(requests,&event.facts.question,
            &identity,input->token,&policy);
          flow->fact[n].facts.correlation=event.facts.correlation;
        }
      observer(context,&event);
      if(flow->retired || event.status) return 1;
      if(restriction)
        {flow->blocked=n+1;flow->checked=input->policy;return 1;}
      flow->blocked=0;
    }
  flow->checked=input->policy;return 0;
}
static void complete_message(product_dns_tcp_owner_t *owner,product_dns_owner_t *requests,
  const product_dns_tcp_input_t *input,product_dns_tcp_flow_t *flow,dns_tcp_side_t *side,const uint8_t *wire,unsigned size,
  product_dns_tcp_observer_t observer,void *context)
{
  product_dns_context_t current=side->context;
  current.domains=input->context.domains;current.domains_available=input->context.domains_available;
  /* Attribution belongs to this frame's first observed bytes; current dynamic
   * flow facts are borrowed only for this complete-message control point. */
  current.packet.ct_state=input->context.packet.ct_state;
  current.packet.ct_state_known=input->context.packet.ct_state_known;
  current.packet.flow_direction=input->context.packet.flow_direction;
  current.packet.flow_direction_known=input->context.packet.flow_direction_known;
  current.packet.protocol_set=input->context.packet.protocol_set;
  current.packet.protocol_set_known=input->context.packet.protocol_set_known;
  current.packet.sni_result=input->context.packet.sni_result;
  product_dns_identity_t identity=input->identity;
  product_dns_tcp_event_t event={.stage=current.packet.direction==3?1:2,
    .sequence=side->base,.message_sequence=++side->messages};
  if(event.stage==1)
    {
      product_dns_inspect_query(wire,size,&current,&event.facts.question);
      event.facts.question.message_sequence=event.message_sequence;
      event.facts.name_count=event.facts.question.name_length?1:0;
      product_dns_name_t *name=&event.facts.names[0];
      name->length=event.facts.question.name_length;
      memcpy(name->name,event.facts.question.name,sizeof(name->name));
      current_names(input,&event);match_event(input,flow,&event,&identity);
      if(!event.status && event.match.actual_action!=PRODUCT_L4_POLICY_ACTION_DROP)
        {
          product_dns_policy_identity_t policy=input->policy;
          policy.winner=event.match.evaluation?event.match.rule_id:0;
          event.facts.correlation=product_dns_remember(requests,&event.facts.question,
            &identity,input->token,&policy);
        }
    }
  else
    {
      product_dns_inspect_response(wire,size,&current,&input->identity,requests,&event.facts);
      current_names(input,&event);match_event(input,flow,&event,&identity);
    }
  event.facts.question.message_sequence=event.message_sequence;
  event.facts.question.tcp_sequence=event.sequence;
  if(event.facts.question.coverage!=PRODUCT_DNS_NOT_QUERY)
    {
      ++owner->messages;
      if(!flow->retired && event.facts.question.coverage==PRODUCT_DNS_QUERY_COMPLETE)
        {
          unsigned n=event.stage==2;
          flow->fact[n]=event;flow->fact_valid[n]=1;flow->checked=input->policy;
          if(policy_rejection(input,&event)) flow->blocked=n+1;
        }
      observer(context,&event);
    }
}
static void process_flow(product_dns_tcp_owner_t *owner,product_dns_owner_t *requests,
  const product_dns_tcp_input_t *input,product_dns_tcp_flow_t *flow,
  product_dns_tcp_observer_t observer,void *context)
{
  unsigned direction=input->context.packet.direction==1;
  if((input->flags&2) && !(input->flags&16) && !direction &&
      !input->identity.incarnation && flow->identity.incarnation)
    {
      uint8_t processing=flow->processing;
      memset(flow,0,sizeof(*flow));flow->processing=processing;
      flow->context=input->context;flow->context.domains=NULL;flow->identity=input->identity;
    }
  if(!flow->identity.incarnation && input->identity.incarnation)
    flow->identity.incarnation=input->identity.incarnation;
  dns_tcp_side_t *side=&flow->side[direction];
  if((input->flags&2) && side->anchored && side->initial!=input->sequence+1)
    {
      /* Only a newly admitted client SYN may replace an old framing identity.
       * A contradictory SYN within the same incarnation is not a reset escape. */
      if(!direction && !(input->flags&16) && !input->identity.incarnation)
        {
          uint8_t processing=flow->processing;
          memset(flow,0,sizeof(*flow));flow->processing=processing;flow->context=input->context;
          flow->context.domains=NULL;flow->identity=input->identity;side=&flow->side[direction];
        }
      else
        {
          if(input->length && recheck(flow,requests,input,observer,context)) return;
          side->failed=PRODUCT_DNS_TCP_CONFLICT;++owner->conflicts;
          if(input->length) coverage(input,PRODUCT_DNS_TCP_CONFLICT,observer,context);
          return;
        }
    }
  if(input->flags&2)
    {
      if(!side->anchored || side->initial!=input->sequence+1)
        {
          memset(side,0,sizeof(*side));side->anchored=1;
          side->base=side->initial=input->sequence+1;
        }
    }
  if(!input->length) return;
  if(recheck(flow,requests,input,observer,context) || flow->retired) return;
  if(!side->anchored)
    {++owner->midstream;coverage(input,PRODUCT_DNS_TCP_MIDSTREAM,observer,context);return;}
  if(side->failed) {coverage(input,side->failed,observer,context);return;}
  if(input->length>PRODUCT_DNS_MESSAGE_MAX)
    {side->failed=PRODUCT_DNS_CAPACITY;++owner->capacity;coverage(input,PRODUCT_DNS_CAPACITY,observer,context);return;}
  if(input->copied<input->length || !input->bytes)
    {side->failed=PRODUCT_DNS_COPY_GAP;coverage(input,PRODUCT_DNS_COPY_GAP,observer,context);return;}
  unsigned old_bytes=0;
  for(size_t n=0;n<input->length;++n)
    {
      uint32_t sequence=input->sequence+!!(input->flags&2)+(uint32_t)n;
      int32_t offset=(int32_t)(sequence-side->base);
      if(offset<0) {++owner->duplicates;old_bytes=1;continue;}
      if((uint32_t)offset>=WINDOW)
        {side->failed=PRODUCT_DNS_CAPACITY;++owner->capacity;coverage(input,PRODUCT_DNS_CAPACITY,observer,context);return;}
      unsigned at=(side->head+(uint32_t)offset)%WINDOW;
      if(present(side,offset))
        {
          if(side->bytes[at]!=input->bytes[n])
            {side->failed=PRODUCT_DNS_TCP_CONFLICT;++owner->conflicts;coverage(input,PRODUCT_DNS_TCP_CONFLICT,observer,context);return;}
          ++owner->duplicates;continue;
        }
      if(!side->context_valid)
        {
          side->context=input->context;side->context.domains=NULL;side->context_valid=1;
          side->deadline=input->identity.now_us+PRODUCT_DNS_REQUEST_US;
        }
      side->bytes[at]=input->bytes[n];side->present[at/8]|=1U<<(at%8);
      if(side->span<(uint32_t)offset+1) side->span=offset+1;
      while(side->contiguous<side->span && present(side,side->contiguous)) ++side->contiguous;
      while(side->contiguous>=2)
        {
          unsigned size=(unsigned)byte(side,0)*256U+byte(side,1);
          /* Even an invalid DNS message has a known TCP framing boundary.
           * Inspect its exact bytes as MALFORMED and consume that frame;
           * unlike a byte gap/conflict, it cannot hide following messages. */
          if(side->contiguous>=size+2)
            {
              uint8_t wire[PRODUCT_DNS_MESSAGE_MAX];
              for(unsigned p=0;p<size;++p) wire[p]=byte(side,p+2);
              complete_message(owner,requests,input,flow,side,wire,size,observer,context);
              if(flow->retired) return;
              consume(side,size+2);
              if(flow->blocked) return;
            }
          else break;
        }
    }
  if(side->span)
    {
      unsigned reason=side->span>side->contiguous?PRODUCT_DNS_TCP_GAP:PRODUCT_DNS_TCP_PENDING;
      if(reason==PRODUCT_DNS_TCP_GAP) ++owner->gaps;
      coverage(input,reason,observer,context);
    }
  else if(old_bytes) coverage(input,PRODUCT_DNS_TCP_OLD_BYTES,observer,context);
}
void product_dns_tcp_process(product_dns_tcp_owner_t *owner,product_dns_owner_t *requests,
  const product_dns_tcp_input_t *input,product_dns_tcp_observer_t observer,void *context)
{
  if(!owner || !requests || !input || !input->view || !observer || !owner->accepting ||
    owner->generation!=input->identity.generation || input->context.packet.protocol!=6 ||
    (input->context.packet.direction!=1 && input->context.packet.direction!=3)) return;
  product_dns_tcp_expire(owner,input->identity.now_us);
  product_dns_tcp_flow_t *flow=NULL;unsigned empty=PRODUCT_DNS_TCP_FLOWS;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {
      if(!owner->flows[n]) {if(empty==PRODUCT_DNS_TCP_FLOWS) empty=n;continue;}
      if(context_matches(owner->flows[n],input)) {flow=owner->flows[n];break;}
    }
  if(!flow)
    {
      /* An old or unstamped Direct return still follows ordinary packet
       * completion, but cannot establish or mutate a framing incarnation. */
      if(input->identity.profile==2 && input->context.packet.direction==1)
        {if(input->length) coverage(input,PRODUCT_DNS_TCP_MIDSTREAM,observer,context);return;}
      if(empty==PRODUCT_DNS_TCP_FLOWS || !(flow=calloc(1,sizeof(*flow))))
        {++owner->capacity;if(input->length) coverage(input,PRODUCT_DNS_CAPACITY,observer,context);return;}
      flow->context=input->context;flow->context.domains=NULL;
      flow->identity=input->identity;owner->flows[empty]=flow;
      ++owner->active;owner->allocated_bytes+=sizeof(*flow);
      if(owner->high_water<owner->active) owner->high_water=owner->active;
      if(owner->high_water_bytes<owner->allocated_bytes) owner->high_water_bytes=owner->allocated_bytes;
    }
  flow->processing=1;
  process_flow(owner,requests,input,flow,observer,context);
  flow->processing=0;
  if(flow->retired)
    for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
      if(owner->flows[n]==flow) {release_flow(owner,n);break;}
}
