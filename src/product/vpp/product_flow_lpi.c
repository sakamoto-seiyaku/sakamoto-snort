/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_protocol_catalog.h"
#include "../../../third_party/libprotoident/adapter.h"
#include <string.h>

int product_lpi_init (void) { return sakamoto_lpi_init (); }

/* RFC 9000 16/17.2.2, RFC 9369 3.2. Header recognition only: authentication
 * and CRYPTO/SNI assembly belong to the later QUIC producer. Never use ports
 * alone or promote a malformed/truncated version probe to a protocol fact. */
static int quic_varint (const uint8_t *p, uint32_t n, uint32_t *at, uint64_t *value)
{
  if (*at >= n) return 0;
  unsigned bytes = 1U << (p[*at] >> 6);
  if (bytes > n - *at) return 0;
  uint64_t v = p[(*at)++] & 63;
  for (unsigned i = 1; i < bytes; ++i) v = (v << 8) | p[(*at)++];
  *value = v;
  return 1;
}
static int quic_initial (const uint8_t *p, uint32_t n)
{
  if (n < 1200 || (p[0] & 0xc0) != 0xc0) return 0;
  uint32_t version = (uint32_t)p[1]<<24 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<8 | p[4];
  unsigned type = (p[0] >> 4) & 3;
  if (!((version == 1 && type == 0) || (version == UINT32_C(0x6b3343cf) && type == 1))) return 0;
  uint32_t at = 5;
  for (unsigned i = 0; i < 2; ++i) {
    if (at >= n) return 0;
    unsigned length = p[at++];
    if (length > 20 || length > n - at) return 0;
    at += length;
  }
  uint64_t token, length;
  if (!quic_varint (p,n,&at,&token) || token > n-at) return 0;
  at += (uint32_t)token;
  if (!quic_varint (p,n,&at,&length) || length < 20 || length > n-at) return 0;
  return 1;
}

static unsigned dns_u16 (const uint8_t *p)
{ return (unsigned)p[0] << 8 | p[1]; }

/* RFC1035 4.1.4: no recursion or retained bytes. A pointer must refer back to
 * the message and name traversal has independent finite work/jump bounds. */
static int dns_name (const uint8_t *p, uint32_t n, uint32_t *cursor,
                     unsigned *work, uint8_t boundaries[512])
{
  uint32_t at=*cursor, end=0;
  unsigned expanded=0, jumps=0;
  for (;;) {
    if (at>=n || !*work) return 0;
    --*work;
    uint32_t label=at;
    unsigned size=p[at++];
    if (!size) {
      if (++expanded>255) return 0;
      boundaries[label/8]|=(uint8_t)(1U<<(label%8));
      *cursor=end?end:at;
      return 1;
    }
    if ((size & 0xc0)==0xc0) {
      if (at>=n || ++jumps>16) return 0;
      unsigned target=((size & 63)<<8)|p[at++];
      if (target<12 || target>=at-2 || !(boundaries[target/8]&(1U<<(target%8)))) return 0;
      boundaries[label/8]|=(uint8_t)(1U<<(label%8));
      if (!end) end=at;
      at=target;
    } else {
      if ((size & 0xc0) || size>n-at || expanded+size+1>254) return 0;
      boundaries[label/8]|=(uint8_t)(1U<<(label%8));
      expanded+=size+1;
      at+=size;
    }
  }
}

/* nDPI pinned dns.c informs port/header/count selection; independent bounded
 * RFC1035/6762 framing, no nDPI code/state imported. RDATA remains opaque. */
static int mdns_message (const uint8_t *p, uint32_t n)
{
  if (n<12 || n>4096 || (dns_u16(p+2)&0x780f)) return 0;
  unsigned questions=dns_u16(p+4), records=dns_u16(p+6)+dns_u16(p+8)+dns_u16(p+10);
  if (!questions && !records) return 0;
  if (questions+records>64) return 0;
  uint32_t at=12;
  unsigned work=4096;
  uint8_t boundaries[512]={0};
  for (unsigned i=0;i<questions+records;++i) {
    if (!dns_name(p,n,&at,&work,boundaries)) return 0;
    unsigned header=i<questions?4:10;
    if (header>n-at || !dns_u16(p+at) || !(dns_u16(p+at+2)&0x7fff)) return 0;
    unsigned data=i<questions?0:dns_u16(p+at+8);
    at+=header;
    if (data>n-at) return 0;
    at+=data;
  }
  return at==n;
}

/* Complete bounded first line only. Case folding is ASCII and locale-free. */
static unsigned ascii_upper (unsigned c)
{ return c >= 'a' && c <= 'z' ? c - ('a'-'A') : c; }
static int word_equal (const uint8_t *p, unsigned n, const char *word)
{
  unsigned length=(unsigned)strlen(word);
  if(n!=length) return 0;
  for(unsigned i=0;i<n;++i) if(ascii_upper(p[i])!=(unsigned)word[i]) return 0;
  return 1;
}
static unsigned first_line (const uint8_t *p, unsigned n)
{
  if(n>512) n=512;
  for(unsigned i=0;i+1<n;++i) {
    if(p[i]=='\r' && p[i+1]=='\n') return i;
    if(p[i]<32 || p[i]>126) return 0;
  }
  return 0;
}
static int banner_token (const uint8_t *p, unsigned n, const char *token)
{
  unsigned at=4;
  while(at<n) {
    while(at<n && p[at]==' ') ++at;
    unsigned start=at;
    while(at<n && p[at]!=' ') ++at;
    if(word_equal(p+start,at-start,token)) return 1;
  }
  return 0;
}
static const char *mail_banner (const uint8_t *p, unsigned n)
{
  unsigned line=first_line(p,n);
  if(line<5 || memcmp(p,"220",3) || (p[3]!=' ' && p[3]!='-')) return NULL;
  int smtp=banner_token(p,line,"SMTP") || banner_token(p,line,"ESMTP");
  int ftp=banner_token(p,line,"FTP") || banner_token(p,line,"FTPD");
  if(smtp==ftp) return NULL;
  return smtp?"sakamoto:smtp":"sakamoto:ftp-control";
}

/* RFC8446 record envelope plus handshake header; not handshake validation.
 * Require the complete first record in this borrowed payload. */
static int tls_handshake_record (const uint8_t *p, unsigned n)
{
  if(n<9 || p[0]!=22 || p[1]!=3 || p[2]>3) return 0;
  unsigned record=((unsigned)p[3]<<8)|p[4];
  unsigned handshake=((unsigned)p[6]<<16)|((unsigned)p[7]<<8)|p[8];
  return record>=4 && record<=18432 && record<=n-5 &&
    (p[5]==1 || p[5]==2) && handshake<=record-4;
}

static int line_command (const uint8_t *p, unsigned n, const char *command,
                         int argument)
{
  unsigned size=(unsigned)strlen(command);
  return n>=size && word_equal(p,size,command) &&
    (argument ? n>size+1 && p[size]==' ' : n==size);
}

enum { MAIL_PENDING_NONE, MAIL_PENDING_SMTP, MAIL_PENDING_FTP };
enum { FTPS_PLAIN, FTPS_AUTH_PENDING, FTPS_TLS_READY };

/* Small request/reply evidence, no credentials or TCP bytes retained. */
static const char *mail_exchange (product_lpi_state_t *state, unsigned side,
  const product_packet_facts_t *facts, const uint8_t *p, unsigned n,
  const char **companion)
{
  if(tls_handshake_record(p,n)) {
    if((state->ftps_stage==FTPS_TLS_READY && side==state->ftps_side)
       || facts->source_port==990 || facts->destination_port==990) {
      *companion="lpi:tls";
      return "sakamoto:ftps";
    }
    return (state->protocols & (product_protocol_bit(1007)|product_protocol_bit(1008)))
      ? "lpi:tls" : NULL;
  }
  unsigned line=first_line(p,n);
  if(!line) return NULL;
  const char *banner=mail_banner(p,n);
  if(banner) return banner;
  int mail_port=facts->source_port==25 || facts->destination_port==25 ||
    facts->source_port==110 || facts->destination_port==110 ||
    facts->source_port==587 || facts->destination_port==587;
  if(line_command(p,line,"EHLO",1) || line_command(p,line,"HELO",1)) {
    state->mail_pending=MAIL_PENDING_SMTP;state->mail_side=(uint8_t)side;
    return NULL;
  }
  int auth=line_command(p,line,"AUTH TLS",0);
  int ftp_context=(state->protocols & product_protocol_bit(1008)) ||
    facts->source_port==21 || facts->destination_port==21;
  if(auth && ftp_context) {
    state->ftps_stage=FTPS_AUTH_PENDING;state->ftps_side=(uint8_t)side;
    state->mail_pending=MAIL_PENDING_FTP;state->mail_side=(uint8_t)side;
    return NULL;
  }
  if(!mail_port && (line_command(p,line,"SYST",0) ||
      line_command(p,line,"FEAT",0) || line_command(p,line,"PASV",0) ||
      line_command(p,line,"EPSV",0) || line_command(p,line,"RETR",1) ||
      line_command(p,line,"STOR",1) ||
      (ftp_context && (line_command(p,line,"USER",1) || line_command(p,line,"PASS",1))))) {
    state->mail_pending=MAIL_PENDING_FTP;state->mail_side=(uint8_t)side;
    return NULL;
  }
  if(line>=4 && p[0]>='1' && p[0]<='5' && p[1]>='0' && p[1]<='9' &&
      p[2]>='0' && p[2]<='9' && (p[3]==' ' || p[3]=='-')) {
    unsigned code=(p[0]-'0')*100+(p[1]-'0')*10+p[2]-'0';
    if(state->ftps_stage==FTPS_AUTH_PENDING && side!=state->ftps_side) {
      state->ftps_stage=(code==234 && p[3]==' ')?FTPS_TLS_READY:
        (code==234?FTPS_AUTH_PENDING:FTPS_PLAIN);
    }
    if(state->mail_pending && side!=state->mail_side) {
      unsigned pending=state->mail_pending;
      state->mail_pending=MAIL_PENDING_NONE;
      if(pending==MAIL_PENDING_SMTP && code==250) return "sakamoto:smtp";
      if(pending==MAIL_PENDING_FTP) return "sakamoto:ftp-control";
    }
  }
  return NULL;
}

/* MS-RDPBCGR negotiation carried by TPKT/X.224, including bounded Cookie.
 * Only a paired request and opposite response/failure establish the fact.
 * Correlation-info flag8 requires a larger PDU and is outside this subset. */
static unsigned rdp_negotiation (const uint8_t *p, unsigned n)
{
  if(n<19 || n>260 || p[0]!=3 || p[1] || dns_u16(p+2)!=n || p[4]!=n-5 ||
     (p[5]!=0xe0 && p[5]!=0xd0) || p[10]) return 0;
  unsigned at=11;
  if(p[5]==0xe0 && n>19) {
    if(n<28 || memcmp(p+at,"Cookie: ",8)) return 0;
    at+=8;
    while(at+1<n && p[at]>=32 && p[at]<=126) ++at;
    if(at+1>=n || p[at]!='\r' || p[at+1]!='\n') return 0;
    at+=2;
  }
  if(n-at!=8 || p[at+2]!=8 || p[at+3] || p[at+5] || p[at+6] || p[at+7]) return 0;
  unsigned kind=p[at], value=p[at+4];
  if(p[5]==0xe0 && kind==1 && !(value&~0x0bU) && !(p[at+1]&~0x03U)) return 1;
  if(p[5]==0xd0 && kind==2 && (value==0 || value==1 || value==2 || value==8)) return 2;
  if(p[5]==0xd0 && kind==3 && !p[at+1] && value>=1 && value<=6) return 2;
  return 0;
}
static int rdp_exchange (product_lpi_state_t *state, unsigned side,
  const product_packet_facts_t *facts, const uint8_t *p, unsigned n)
{
  if(facts->protocol==6) {
    unsigned kind=rdp_negotiation(p,n);
    if(kind==1) {state->rdp_pending=1;state->rdp_side=(uint8_t)side;}
    else if(state->rdp_pending && side!=state->rdp_side) {
      state->rdp_pending=0;
      return kind==2;
    }
  } else if(n==16 && (facts->source_port==3389 || facts->destination_port==3389)) {
    unsigned flags=dns_u16(p+6), up=dns_u16(p+12), down=dns_u16(p+14);
    if(up<256 || up>1600 || down<256 || down>1600) return 0;
    if(flags==1 && facts->destination_port==3389 && !memcmp(p,"\xff\xff\xff\xff",4)) {
      memcpy(&state->rdp_sequence,p+8,4);
      state->rdp_pending=1;state->rdp_side=(uint8_t)side;
    } else if(state->rdp_pending && side!=state->rdp_side && facts->source_port==3389) {
      state->rdp_pending=0;
      return flags==3 && !memcmp(p,&state->rdp_sequence,4);
    }
  }
  return 0;
}

/* Selected unencrypted OpenVPN control envelope, any TCP/UDP port.
 * nDPI session continuity and remote-session matching inform this state only.
 * No HMAC-size guessing, obfuscation, reassembly or inner TLS inspection. */
static int openvpn_exchange (product_lpi_state_t *state, unsigned side,
                             unsigned transport, const uint8_t *p, unsigned n)
{
  if(transport==6) {
    if(n<2 || dns_u16(p)!=n-2) return 0;
    p+=2;n-=2;
  }
  if(n<14 || n>=1200 || (p[0]&7)) return 0;
  unsigned opcode=p[0]>>3;
  int client=opcode==1 || opcode==7, server=opcode==2 || opcode==8;
  if(!client && !server && opcode!=4 && opcode!=5) return 0;
  if(!memcmp(p+4,"\x21\x12\xa4\x42",4)) return 0; /* STUN */
  unsigned nonzero=0;
  for(unsigned i=1;i<=8;++i) nonzero|=p[i];
  if(!nonzero) return 0;
  unsigned count=p[9], at=10;
  if(count>8 || count*4U>n-at) return 0;
  at+=count*4;
  const uint8_t *remote=NULL;
  if(count) {if(n-at<8) return 0;remote=p+at;at+=8;}
  if(opcode!=5) {
    if(n-at<4) return 0;
    if((client || server) && (p[at] || p[at+1] || p[at+2] || p[at+3])) return 0;
    at+=4;
  }
  if((client || server || opcode==5) && at!=n) return 0;
  if(!state->ovpn_count[side]) {
    if(!client && !server) return 0;
    memcpy(state->ovpn_session[side],p+1,8);
    state->ovpn_reset[side]=(uint8_t)(client?1:2);
  } else if(memcmp(state->ovpn_session[side],p+1,8)) {
    state->ovpn_count[0]=state->ovpn_count[1]=0;
    return 0;
  }
  if(remote && state->ovpn_count[!side] &&
     memcmp(remote,state->ovpn_session[!side],8)) {
    state->ovpn_count[0]=state->ovpn_count[1]=0;
    return 0;
  }
  if(state->ovpn_count[side]<2) ++state->ovpn_count[side];
  if(server && remote && state->ovpn_count[!side] && state->ovpn_reset[!side]==1)
    return 1;
  return state->ovpn_count[0]==2 && state->ovpn_count[1]==2 &&
    state->ovpn_reset[0]!=state->ovpn_reset[1];
}

enum { WG_NONE, WG_INITIATION, WG_TRANSPORT_ONE, WG_TRANSPORT_BOTH };
/* WireGuard fixed framing and cross-direction indices; opaque encrypted body.
 * Unlike nDPI's retransmission shortcut, initiation alone never publishes. */
static int wireguard_exchange (product_lpi_state_t *state, unsigned side,
                               const uint8_t *p, unsigned n)
{
  if(n<32 || p[1] || p[2] || p[3]) return 0;
  uint32_t index;
  memcpy(&index,p+4,4);
  if(p[0]==1 && n==148) {
    state->wg_stage=WG_INITIATION;state->wg_side=(uint8_t)side;
    state->wg_index[side]=index;
  } else if((p[0]==2 && n==92) || (p[0]==3 && n==64)) {
    if(p[0]==2) memcpy(&index,p+8,4);
    if(state->wg_stage==WG_INITIATION && side!=state->wg_side) {
      int match=index==state->wg_index[!side];
      state->wg_stage=WG_NONE;
      return match;
    }
  } else if(p[0]==4) {
    if(state->wg_stage==WG_NONE) {
      state->wg_stage=WG_TRANSPORT_ONE;state->wg_side=(uint8_t)side;
      state->wg_index[side]=index;
    } else if(state->wg_stage==WG_TRANSPORT_ONE && side!=state->wg_side) {
      state->wg_index[side]=index;state->wg_stage=WG_TRANSPORT_BOTH;
    } else if(state->wg_stage==WG_TRANSPORT_BOTH) {
      if(state->wg_index[side]==index) return 1;
      state->wg_stage=WG_NONE;
    }
  }
  return 0;
}

/* RFC1928 negotiation and SOCKS4/4a request/reply framing. Bounded current
 * messages only; neither authentication nor a working proxy is inferred. */
static const char *socks_exchange (product_lpi_state_t *state, unsigned side,
                                  const uint8_t *p, unsigned n)
{
  if(state->socks_version && side!=state->socks_side) {
    unsigned version=state->socks_version;
    state->socks_version=0;
    if(version==4 && n==8 && p[0]==0 && p[1]>=90 && p[1]<=93)
      return "sakamoto:socks4";
    if(version==5 && n==2 && p[0]==5 &&
       (p[1]==255 || (state->socks_methods[p[1]/8] & (1U<<(p[1]%8)))))
      return "sakamoto:socks5";
  }
  if(n>=9 && n<=512 && p[0]==4 && (p[1]==1 || p[1]==2) && dns_u16(p+2)) {
    unsigned at=8;
    while(at<n && p[at]) ++at;
    if(at==n) return NULL;
    ++at;
    if(!p[4] && !p[5] && !p[6] && p[7]) {
      unsigned start=at;
      while(at<n && p[at]>=33 && p[at]<=126) ++at;
      if(at==start || at==n || p[at]) return NULL;
      ++at;
    }
    if(at==n) {state->socks_version=4;state->socks_side=(uint8_t)side;}
  }
  if(n>=3 && n<=34 && p[0]==5 && p[1] && n==2U+p[1]) {
    /* RFC1928's full method byte space, including private-use offers. */
    for(unsigned i=2;i<n;++i) if(p[i]==255) return NULL;
    memset(state->socks_methods,0,sizeof state->socks_methods);
    for(unsigned i=2;i<n;++i) state->socks_methods[p[i]/8]|=(uint8_t)(1U<<(p[i]%8));
    state->socks_version=5;state->socks_side=(uint8_t)side;
  }
  return NULL;
}

/* Resolve one unpublished guess before any catalog mapping. Explicitly prefer
 * QUIC's modern Initial framing over port heuristics; mDNS requires its own
 * framing and either 5353 endpoint. Never union conflicting current guesses.
 * Earlier published facts remain untouched by this resolution. */
static const char *resolve_guess (const char *base,
  const product_packet_facts_t *facts, const uint8_t *payload, uint32_t length,
  const char **companion, product_lpi_state_t *state, unsigned side)
{
  *companion=NULL;
  if(rdp_exchange(state,side,facts,payload,length)) return "sakamoto:rdp";
  if(openvpn_exchange(state,side,facts->protocol,payload,length)) return "sakamoto:openvpn";
  if (facts->protocol==17) {
    if (wireguard_exchange(state,side,payload,length)) return "sakamoto:wireguard";
    if (quic_initial(payload,length)) return "lpi:quic";
    if ((facts->source_port==5353 || facts->destination_port==5353)
        && mdns_message(payload,length)) return "sakamoto:mdns";
  }
  if (facts->protocol==6) {
    const char *proxy=socks_exchange(state,side,payload,length);
    if(proxy) return proxy;
    const char *mail=mail_exchange(state,side,facts,payload,length,companion);
    if(mail) return mail;
    if((facts->source_port==20 || facts->destination_port==20)
       && !product_protocol_provider_id(base)) return "sakamoto:ftp-data";
  }
  return base;
}

product_flow_entry_status_t product_flow_entry_identify (
  product_flow_runtime_t *pool, uint32_t slot, uint64_t generation,
  uint64_t incarnation, const product_packet_facts_t *facts,
  const uint8_t *payload, uint32_t length)
{
  if (!pool || !facts || (length && !payload)) return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_runtime_snapshot_t runtime = product_flow_runtime_snapshot (pool);
  if (runtime.generation != generation) return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
  const product_flow_entry_t *borrowed = product_flow_runtime_entry (pool,slot);
  if (!borrowed || !borrowed->linked || borrowed->incarnation != incarnation)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  /* Entry is allocated mutable storage; the public query is const to prevent
   * accidental mutation. Only this identity-validated owner operation writes. */
  product_flow_entry_t *entry = (product_flow_entry_t *) borrowed;
  product_lpi_state_t *state = &entry->lpi;
  if (entry->key.protocol != 6 && entry->key.protocol != 17) {
    state->stop_reason = PRODUCT_LPI_STOP_UNSUPPORTED;
    return PRODUCT_FLOW_ENTRY_STATUS_OK;
  }
  unsigned source_is_a = entry->last_flow_direction == PRODUCT_FLOW_DIRECTION_ORIG
    ? entry->origin_is_endpoint_a : !entry->origin_is_endpoint_a;
  const uint8_t *source = source_is_a ? entry->key.address_a : entry->key.address_b;
  const uint8_t *destination = source_is_a ? entry->key.address_b : entry->key.address_a;
  if (facts->protocol != entry->key.protocol || facts->ip_family != entry->key.ip_family
      || facts->l4_status != PRODUCT_PACKET_L4_COMPLETE
      || facts->transport_length < facts->l4_header_length
      || length != (uint32_t)facts->transport_length - facts->l4_header_length
      || memcmp (facts->source_address, source, 16)
      || memcmp (facts->destination_address, destination, 16)
      || facts->source_port != (source_is_a ? entry->key.transport.ports.a : entry->key.transport.ports.b)
      || facts->destination_port != (source_is_a ? entry->key.transport.ports.b : entry->key.transport.ports.a))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  if (state->stop_reason || !length) return PRODUCT_FLOW_ENTRY_STATUS_OK;
  if (length > PRODUCT_LPI_MAX_BYTES - state->bytes) {
    state->stop_reason = PRODUCT_LPI_STOP_BYTE_BUDGET;
    return PRODUCT_FLOW_ENTRY_STATUS_OK;
  }
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_DIRECTION_REPLY;
  if (!state->attempts) {
    state->client_port = side ? facts->destination_port : facts->source_port;
    state->server_port = side ? facts->source_port : facts->destination_port;
    if (facts->ip_family == 4) {
      memcpy (&state->ips[side],facts->source_address,4);
      memcpy (&state->ips[!side],facts->destination_address,4);
    }
  }
  state->payload[side] = 0;
  memcpy (&state->payload[side],payload,length < 4 ? length : 4);
  state->lengths[side] = length;
  state->observed[side] += length;
  state->bytes += length;
  ++state->attempts;
  const char *alias = sakamoto_lpi_guess (state->payload,state->lengths,state->observed,
    state->ips,state->client_port,state->server_port,facts->protocol);
  const char *companion=NULL;
  alias = resolve_guess (alias,facts,payload,length,&companion,state,side);
  uint64_t result = product_protocol_bit (product_protocol_provider_id (alias))
    | product_protocol_bit (product_protocol_provider_id (companion));
  state->last_outcome = result ? PRODUCT_LPI_MAPPED : alias ? PRODUCT_LPI_UNMAPPED : PRODUCT_LPI_MISS;
  state->protocols |= result;
  state->available = state->protocols != 0;
  if (state->attempts == PRODUCT_LPI_MAX_ATTEMPTS)
    state->stop_reason = PRODUCT_LPI_STOP_PACKET_BUDGET;
  else if (state->bytes == PRODUCT_LPI_MAX_BYTES)
    state->stop_reason = PRODUCT_LPI_STOP_BYTE_BUDGET;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}
