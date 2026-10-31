/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_dns_http.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef product_dns_http_response_t response_t;
static uint8_t dns[40];
static uint8_t body[65535];

static void fill(void){for(unsigned i=0;i<sizeof(dns);++i)dns[i]=(uint8_t)(i*7+1);}

static int run(response_t *r,const char *text,size_t length,size_t step)
{
  product_dns_http_init(r,body,sizeof(body));
  int result=PRODUCT_DNS_HTTP_MORE;
  for(size_t at=0;at<length;){
    size_t n=length-at<step?length-at:step,consumed=0;
    result=product_dns_http_feed(r,(const uint8_t *)text+at,n,&consumed);
    at+=consumed;
    if(result<0)return result; /* DONE keeps feeding: later bytes must be reported as trailing */
  }
  return result;
}

static char *response_text(const char *head,size_t body_length,size_t *total)
{
  size_t head_length=strlen(head);
  char *out=malloc(head_length+body_length);
  memcpy(out,head,head_length);
  for(size_t i=0;i<body_length;++i)out[head_length+i]=(char)(i*5+3);
  *total=head_length+body_length;return out;
}

static void request_has_exact_shape(void)
{
  uint8_t out[512];
  size_t n=product_dns_http_build_request(out,sizeof(out),"dns.test",443,"/dns-query",dns,sizeof(dns));
  static const char head[]="POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\n"
    "Accept: application/dns-message\r\nContent-Length: 40\r\nConnection: close\r\n\r\n";
  assert(n==sizeof(head)-1+sizeof(dns)&&!memcmp(out,head,sizeof(head)-1)&&!memcmp(out+sizeof(head)-1,dns,sizeof(dns)));
  n=product_dns_http_build_request(out,sizeof(out),"2001:db8::53",8443,"/q?dns=1",dns,sizeof(dns));
  assert(n&&memmem(out,n,"Host: [2001:db8::53]:8443\r\n",26));
  assert(product_dns_http_build_request(out,10,"dns.test",443,"/x",dns,sizeof(dns))==0);
  assert(!product_dns_http_build_request(out,sizeof(out),"dns.test",443,"dns-query",dns,sizeof(dns)));
  assert(!product_dns_http_build_request(out,sizeof(out),"dns.test",443,"/a b",dns,sizeof(dns)));
  assert(!product_dns_http_build_request(out,sizeof(out),"dns.test\r\nX:1",443,"/x",dns,sizeof(dns)));
  assert(!product_dns_http_build_request(out,sizeof(out),"dns.test",0,"/x",dns,sizeof(dns)));
  assert(!product_dns_http_build_request(out,sizeof(out),"dns.test",443,"/x",dns,11));
  char *long_path=malloc(PRODUCT_DNS_HTTP_PATH_BYTES+3);
  memset(long_path,'a',PRODUCT_DNS_HTTP_PATH_BYTES+2);long_path[0]='/';long_path[PRODUCT_DNS_HTTP_PATH_BYTES+2]=0;
  assert(!product_dns_http_path_valid(long_path));free(long_path);
}

static void content_length_body_survives_every_split(void)
{
  size_t total;
  char *text=response_text("HTTP/1.1 200 OK\r\ncontent-TYPE: Application/DNS-Message; charset=x\r\n"
    "Age: 17\r\nContent-Length: 64\r\nConnection: close\r\n\r\n",64,&total);
  static response_t r;
  for(size_t step=1;step<=total;step+=step<9?1:37){
    assert(run(&r,text,total,step)==PRODUCT_DNS_HTTP_DONE);
    assert(r.status==200&&r.age==17&&r.body_at==64&&r.connection_close&&!r.close_delimited);
    for(unsigned i=0;i<64;++i)assert(body[i]==(uint8_t)(i*5+3));
  }
  free(text);
}

static void chunked_body_survives_every_split(void)
{
  const char head[]="HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: Chunked\r\n\r\n";
  char text[512];size_t at=0;
  memcpy(text,head,sizeof(head)-1);at=sizeof(head)-1;
  static const unsigned sizes[]={13,20,31};
  unsigned value=0;
  for(unsigned c=0;c<3;++c){
    at+=(size_t)snprintf(text+at,sizeof(text)-at,c==1?"%X;ext=a\r\n":"%x\r\n",sizes[c]);
    for(unsigned i=0;i<sizes[c];++i)text[at++]=(char)(value++*3+9);
    memcpy(text+at,"\r\n",2);at+=2;
  }
  at+=(size_t)snprintf(text+at,sizeof(text)-at,"0\r\nX-Trailer: ignored\r\n\r\n");
  static response_t r;
  for(size_t step=1;step<=at;++step){
    assert(run(&r,text,at,step)==PRODUCT_DNS_HTTP_DONE);
    assert(r.chunked&&r.body_at==64);
    for(unsigned i=0;i<64;++i)assert(body[i]==(uint8_t)(i*3+9));
  }
}

static void expect(const char *head,size_t body_length,int code)
{
  static response_t r;size_t total;
  char *text=response_text(head,body_length,&total);
  assert(run(&r,text,total,total)==code);
  /* The same bytes must fail identically when delivered one byte at a time. */
  assert(run(&r,text,total,1)==code);
  free(text);
}

static void unsupported_or_unsafe_responses_are_distinct_failures(void)
{
  expect("HTTP/1.1 404 Not Found\r\nContent-Type: application/dns-message\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_STATUS);
  expect("HTTP/1.1 500 X\r\n\r\n",0,PRODUCT_DNS_HTTP_STATUS);
  expect("HTTP/1.1 100 Continue\r\n\r\n",0,PRODUCT_DNS_HTTP_STATUS);
  expect("HTTP/1.1 301 Moved\r\nLocation: https://x.test/\r\nContent-Length: 0\r\n\r\n",0,PRODUCT_DNS_HTTP_REDIRECT);
  expect("HTTP/1.1 307 Moved\r\n\r\n",0,PRODUCT_DNS_HTTP_REDIRECT);
  expect("HTTP/2 200\r\n\r\n",0,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 20 OK\r\n\r\n",0,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_CONTENT_TYPE);
  expect("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_CONTENT_TYPE);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_CONTENT_TYPE);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Encoding: gzip\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_ENCODING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",0,PRODUCT_DNS_HTTP_ENCODING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 20\r\nContent-Length: 21\r\n\r\n",21,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: +20\r\n\r\n",20,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 20x\r\n\r\n",20,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge: -1\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_AGE);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge: 1\r\nAge: 1\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_AGE);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge:\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_AGE);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n folded\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type : application/dns-message\r\nContent-Length: 20\r\n\r\n",20,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\nContent-Type: application/dns-message\r\n\r\n",0,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 5\r\n\r\n",5,PRODUCT_DNS_HTTP_EMPTY);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 20\r\n\r\n",21,PRODUCT_DNS_HTTP_TRAILING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 65536\r\n\r\n",0,PRODUCT_DNS_HTTP_BODY_LIMIT);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",0,PRODUCT_DNS_HTTP_FRAMING);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n10000\r\n",0,PRODUCT_DNS_HTTP_BODY_LIMIT);
  expect("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",0,PRODUCT_DNS_HTTP_EMPTY);
}

static void header_bounds_are_enforced(void)
{
  static response_t r;
  char *text=malloc(PRODUCT_DNS_HTTP_HEADER_BYTES*2);
  size_t at=(size_t)snprintf(text,PRODUCT_DNS_HTTP_HEADER_BYTES*2,"HTTP/1.1 200 OK\r\nX-Pad: ");
  memset(text+at,'a',PRODUCT_DNS_HTTP_HEADER_BYTES);at+=PRODUCT_DNS_HTTP_HEADER_BYTES;
  memcpy(text+at,"\r\n\r\n",4);at+=4;
  assert(run(&r,text,at,at)==PRODUCT_DNS_HTTP_HEADER_LIMIT);
  assert(run(&r,text,at,1)==PRODUCT_DNS_HTTP_HEADER_LIMIT);
  at=(size_t)snprintf(text,PRODUCT_DNS_HTTP_HEADER_BYTES*2,"HTTP/1.1 200 OK\r\n");
  for(unsigned i=0;i<PRODUCT_DNS_HTTP_HEADER_FIELDS+1;++i)
    at+=(size_t)snprintf(text+at,PRODUCT_DNS_HTTP_HEADER_BYTES*2-at,"X-%u: v\r\n",i);
  memcpy(text+at,"\r\n",2);at+=2;
  assert(run(&r,text,at,at)==PRODUCT_DNS_HTTP_HEADER_LIMIT);
  free(text);
}

static void connection_end_is_only_legal_for_a_close_delimited_body(void)
{
  static response_t r;size_t total;
  char *text=response_text("HTTP/1.0 200 OK\r\nContent-Type: application/dns-message\r\n\r\n",40,&total);
  assert(run(&r,text,total,7)==PRODUCT_DNS_HTTP_MORE&&r.close_delimited);
  assert(product_dns_http_eof(&r)==PRODUCT_DNS_HTTP_DONE&&r.body_at==40);
  free(text);
  text=response_text("HTTP/1.0 200 OK\r\nContent-Type: application/dns-message\r\n\r\n",5,&total);
  assert(run(&r,text,total,total)==PRODUCT_DNS_HTTP_MORE&&product_dns_http_eof(&r)==PRODUCT_DNS_HTTP_EMPTY);
  free(text);
  text=response_text("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 40\r\n\r\n",20,&total);
  assert(run(&r,text,total,total)==PRODUCT_DNS_HTTP_MORE&&product_dns_http_eof(&r)==PRODUCT_DNS_HTTP_CLOSED);
  free(text);
  text=response_text("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n14\r\n",10,&total);
  assert(run(&r,text,total,total)==PRODUCT_DNS_HTTP_MORE&&product_dns_http_eof(&r)==PRODUCT_DNS_HTTP_CLOSED);
  free(text);
  assert(product_dns_http_eof(&r)==PRODUCT_DNS_HTTP_CLOSED);
}

static void age_saturates_and_is_reported_exactly(void)
{
  static response_t r;size_t total;
  char *text=response_text("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nAge: 99999999999999999999\r\n"
    "Content-Length: 20\r\n\r\n",20,&total);
  assert(run(&r,text,total,total)==PRODUCT_DNS_HTTP_DONE&&r.age==UINT32_MAX);
  free(text);
  text=response_text("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 20\r\n\r\n",20,&total);
  assert(run(&r,text,total,total)==PRODUCT_DNS_HTTP_DONE&&!r.age&&!r.age_seen);
  free(text);
}

int main(void)
{
  fill();
  request_has_exact_shape();
  content_length_body_survives_every_split();
  chunked_body_survives_every_split();
  unsupported_or_unsafe_responses_are_distinct_failures();
  header_bounds_are_enforced();
  connection_end_is_only_legal_for_a_close_delimited_body();
  age_saturates_and_is_reported_exactly();
  puts("DoH HTTP/1.1 framing PASS");
  return 0;
}
