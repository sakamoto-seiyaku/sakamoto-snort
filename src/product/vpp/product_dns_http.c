/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_dns_http.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

enum { S_STATUS, S_HEADERS, S_BODY_LENGTH, S_BODY_CLOSE, S_CHUNK_SIZE, S_CHUNK_DATA,
       S_CHUNK_END, S_TRAILERS, S_DONE, S_FAILED };
#define DNS_HEADER_BYTES 12U

int product_dns_http_path_valid(const char *path)
{
  if(!path||path[0]!='/')return 0;
  size_t n=strnlen(path,PRODUCT_DNS_HTTP_PATH_BYTES+1);
  if(n>PRODUCT_DNS_HTTP_PATH_BYTES)return 0;
  for(size_t i=0;i<n;++i){
    unsigned char c=(unsigned char)path[i];
    if(c<=0x20||c>=0x7f||c=='#'||c=='\\')return 0;
  }
  return 1;
}

static int host_valid(const char *host)
{
  if(!host||!host[0])return 0;
  size_t n=strnlen(host,PRODUCT_DNS_HTTP_HOST_BYTES+1);
  if(n>PRODUCT_DNS_HTTP_HOST_BYTES)return 0;
  for(size_t i=0;i<n;++i){
    unsigned char c=(unsigned char)host[i];
    if(c<=0x20||c>=0x7f||c=='/'||c=='\\'||c=='#'||c=='?'||c=='@'||c=='['||c==']')return 0;
  }
  return 1;
}

size_t product_dns_http_build_request(uint8_t *out, size_t capacity, const char *host,
  uint16_t port, const char *path, const uint8_t *dns, size_t dns_length)
{
  if(!out||!dns||dns_length<DNS_HEADER_BYTES||dns_length>65535U||!port||
     !host_valid(host)||!product_dns_http_path_valid(path))return 0;
  char authority[PRODUCT_DNS_HTTP_HOST_BYTES+16];
  int literal6=strchr(host,':')!=NULL;
  int written=port==443?snprintf(authority,sizeof(authority),literal6?"[%s]":"%s",host)
                       :snprintf(authority,sizeof(authority),literal6?"[%s]:%u":"%s:%u",host,(unsigned)port);
  if(written<=0||(size_t)written>=sizeof(authority))return 0;
  char head[PRODUCT_DNS_HTTP_PATH_BYTES+PRODUCT_DNS_HTTP_HOST_BYTES+256];
  written=snprintf(head,sizeof(head),
    "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\n"
    "Accept: application/dns-message\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
    path,authority,dns_length);
  if(written<=0||(size_t)written>=sizeof(head)||(size_t)written+dns_length>capacity)return 0;
  memcpy(out,head,(size_t)written);memcpy(out+written,dns,dns_length);
  return (size_t)written+dns_length;
}

void product_dns_http_init(product_dns_http_response_t *r, uint8_t *body, size_t capacity)
{
  memset(r,0,sizeof(*r));
  r->body=body;r->body_cap=capacity;r->state=S_STATUS;
}

static int fail(product_dns_http_response_t *r,int code){r->state=S_FAILED;return code;}

static const char *trim(char *text)
{
  while(*text==' '||*text=='\t')++text;
  size_t n=strlen(text);
  while(n&&(text[n-1]==' '||text[n-1]=='\t'))text[--n]=0;
  return text;
}

static int digits(const char *text,uint64_t *value,unsigned maximum)
{
  size_t n=strlen(text);
  if(!n||n>maximum)return 0;
  uint64_t out=0;
  for(size_t i=0;i<n;++i){
    if(text[i]<'0'||text[i]>'9')return 0;
    out=out*10+(uint64_t)(text[i]-'0');
  }
  *value=out;return 1;
}

static int token(const char *name)
{
  if(!*name)return 0;
  for(const unsigned char *p=(const unsigned char *)name;*p;++p){
    if(*p<=0x20||*p>=0x7f||strchr("()<>@,;:\\\"/[]?={}",*p))return 0;
  }
  return 1;
}

static int status_line(product_dns_http_response_t *r)
{
  char *line=r->line;
  if(strncmp(line,"HTTP/1.1 ",9)&&strncmp(line,"HTTP/1.0 ",9))return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  const char *code=line+9;
  if(!(code[0]>='0'&&code[0]<='9'&&code[1]>='0'&&code[1]<='9'&&code[2]>='0'&&code[2]<='9')||
     (code[3]&&code[3]!=' '))return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  r->status=(uint16_t)((code[0]-'0')*100+(code[1]-'0')*10+(code[2]-'0'));
  if(r->status>=300&&r->status<400)return fail(r,PRODUCT_DNS_HTTP_REDIRECT);
  if(r->status!=200)return fail(r,PRODUCT_DNS_HTTP_STATUS);
  r->state=S_HEADERS;return PRODUCT_DNS_HTTP_MORE;
}

static int has_token(const char *list,const char *wanted)
{
  size_t n=strlen(wanted);
  for(const char *p=list;*p;){
    while(*p==' '||*p=='\t'||*p==',')++p;
    const char *start=p;
    while(*p&&*p!=','&&*p!=' '&&*p!='\t')++p;
    if((size_t)(p-start)==n&&!strncasecmp(start,wanted,n))return 1;
  }
  return 0;
}

static int header_line(product_dns_http_response_t *r,int trailer)
{
  char *line=r->line;
  if(*line==' '||*line=='\t')return fail(r,PRODUCT_DNS_HTTP_FRAMING); /* obsolete folding */
  char *colon=strchr(line,':');
  if(!colon)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  *colon=0;
  if(!token(line))return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  if(++r->fields>PRODUCT_DNS_HTTP_HEADER_FIELDS)return fail(r,PRODUCT_DNS_HTTP_HEADER_LIMIT);
  if(trailer)return PRODUCT_DNS_HTTP_MORE; /* trailer fields are bounded and ignored */
  const char *value=trim(colon+1);
  uint64_t number;
  if(!strcasecmp(line,"content-length")){
    if(!digits(value,&number,15))return fail(r,PRODUCT_DNS_HTTP_FRAMING);
    if(r->has_length&&r->length!=number)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
    r->has_length=1;r->length=number;
  }else if(!strcasecmp(line,"transfer-encoding")){
    if(strcasecmp(value,"chunked"))return fail(r,PRODUCT_DNS_HTTP_ENCODING);
    if(r->chunked)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
    r->chunked=1;
  }else if(!strcasecmp(line,"content-encoding")){
    if(strcasecmp(value,"identity"))return fail(r,PRODUCT_DNS_HTTP_ENCODING);
  }else if(!strcasecmp(line,"content-type")){
    char *end=strchr((char *)value,';');
    if(end)*end=0;
    if(strcasecmp(trim((char *)value),"application/dns-message"))return fail(r,PRODUCT_DNS_HTTP_CONTENT_TYPE);
    r->content_type_ok=1;
  }else if(!strcasecmp(line,"age")){
    if(r->age_seen||!*value)return fail(r,PRODUCT_DNS_HTTP_AGE);
    size_t n=strlen(value);
    if(n>20)return fail(r,PRODUCT_DNS_HTTP_AGE);
    uint64_t age=0;
    for(size_t i=0;i<n;++i){
      if(value[i]<'0'||value[i]>'9')return fail(r,PRODUCT_DNS_HTTP_AGE);
      age=age*10+(uint64_t)(value[i]-'0');
      if(age>UINT32_MAX)age=UINT32_MAX;
    }
    r->age_seen=1;r->age=(uint32_t)age;
  }else if(!strcasecmp(line,"connection")){
    if(has_token(value,"close"))r->connection_close=1;
  }
  return PRODUCT_DNS_HTTP_MORE;
}

static int headers_end(product_dns_http_response_t *r)
{
  if(!r->content_type_ok)return fail(r,PRODUCT_DNS_HTTP_CONTENT_TYPE);
  if(r->chunked&&r->has_length)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  if(r->chunked){r->state=S_CHUNK_SIZE;return PRODUCT_DNS_HTTP_MORE;}
  if(r->has_length){
    if(r->length>r->body_cap)return fail(r,PRODUCT_DNS_HTTP_BODY_LIMIT);
    if(r->length<DNS_HEADER_BYTES)return fail(r,PRODUCT_DNS_HTTP_EMPTY);
    r->state=S_BODY_LENGTH;return PRODUCT_DNS_HTTP_MORE;
  }
  r->close_delimited=1;r->state=S_BODY_CLOSE;return PRODUCT_DNS_HTTP_MORE;
}

static int finish_body(product_dns_http_response_t *r)
{
  if(r->body_at<DNS_HEADER_BYTES)return fail(r,PRODUCT_DNS_HTTP_EMPTY);
  r->state=S_DONE;return PRODUCT_DNS_HTTP_DONE;
}

static int chunk_size(product_dns_http_response_t *r)
{
  char *p=r->line;uint64_t size=0;unsigned digits_seen=0;
  for(;*p&&*p!=';';++p){
    int v=*p>='0'&&*p<='9'?*p-'0':*p>='a'&&*p<='f'?*p-'a'+10:*p>='A'&&*p<='F'?*p-'A'+10:-1;
    if(v<0||++digits_seen>8)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
    size=size*16+(uint64_t)v;
  }
  if(!digits_seen)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  if(!size){r->state=S_TRAILERS;return PRODUCT_DNS_HTTP_MORE;}
  if(size>r->body_cap-r->body_at)return fail(r,PRODUCT_DNS_HTTP_BODY_LIMIT);
  r->chunk_remaining=size;r->state=S_CHUNK_DATA;return PRODUCT_DNS_HTTP_MORE;
}

static int complete_line(product_dns_http_response_t *r)
{
  switch(r->state){
    case S_STATUS:return status_line(r);
    case S_HEADERS:return r->line_at?header_line(r,0):headers_end(r);
    case S_CHUNK_SIZE:return chunk_size(r);
    case S_CHUNK_END:
      if(r->line_at)return fail(r,PRODUCT_DNS_HTTP_FRAMING);
      r->state=S_CHUNK_SIZE;return PRODUCT_DNS_HTTP_MORE;
    case S_TRAILERS:
      if(r->line_at)return header_line(r,1);
      return finish_body(r);
    default:return fail(r,PRODUCT_DNS_HTTP_FRAMING);
  }
}

static int line_state(const product_dns_http_response_t *r)
{
  return r->state==S_STATUS||r->state==S_HEADERS||r->state==S_CHUNK_SIZE||
         r->state==S_CHUNK_END||r->state==S_TRAILERS;
}

int product_dns_http_feed(product_dns_http_response_t *r, const uint8_t *bytes,
  size_t length, size_t *consumed)
{
  size_t at=0;int result=PRODUCT_DNS_HTTP_MORE;
  if(consumed)*consumed=0;
  if(!r||(!bytes&&length))return PRODUCT_DNS_HTTP_FRAMING;
  if(r->state==S_FAILED)return PRODUCT_DNS_HTTP_FRAMING;
  while(at<length){
    if(r->state==S_DONE){result=fail(r,PRODUCT_DNS_HTTP_TRAILING);break;}
    if(line_state(r)){
      unsigned char c=bytes[at++];
      if(r->header_bytes>=PRODUCT_DNS_HTTP_HEADER_BYTES){result=fail(r,PRODUCT_DNS_HTTP_HEADER_LIMIT);break;}
      ++r->header_bytes;
      if(c=='\n'){
        if(!r->line_at||r->line[r->line_at-1]!='\r'){result=fail(r,PRODUCT_DNS_HTTP_FRAMING);break;}
        --r->line_at;r->line[r->line_at]=0;
        if(memchr(r->line,'\r',r->line_at)){result=fail(r,PRODUCT_DNS_HTTP_FRAMING);break;}
        result=complete_line(r);r->line_at=0;
        if(result==PRODUCT_DNS_HTTP_DONE)result=PRODUCT_DNS_HTTP_MORE; /* later bytes are trailing */
        if(result!=PRODUCT_DNS_HTTP_MORE)break;
        continue;
      }
      if((c<0x20&&c!='\t'&&c!='\r')||c==0x7f){result=fail(r,PRODUCT_DNS_HTTP_FRAMING);break;}
      if(r->line_at+2>=sizeof(r->line)){result=fail(r,PRODUCT_DNS_HTTP_HEADER_LIMIT);break;}
      r->line[r->line_at++]=(char)c;
      continue;
    }
    size_t available=length-at,take;
    if(r->state==S_BODY_LENGTH){
      take=r->length-r->body_at;if(take>available)take=available;
      memcpy(r->body+r->body_at,bytes+at,take);r->body_at+=take;at+=take;
      if(r->body_at==r->length){
        result=finish_body(r);
        if(result==PRODUCT_DNS_HTTP_DONE)result=PRODUCT_DNS_HTTP_MORE;
        if(result!=PRODUCT_DNS_HTTP_MORE)break;
      }
    }else if(r->state==S_BODY_CLOSE){
      take=r->body_cap-r->body_at;
      if(take>available)take=available;
      if(!take){result=fail(r,PRODUCT_DNS_HTTP_BODY_LIMIT);break;}
      memcpy(r->body+r->body_at,bytes+at,take);r->body_at+=take;at+=take;
    }else if(r->state==S_CHUNK_DATA){
      take=r->chunk_remaining>available?available:(size_t)r->chunk_remaining;
      memcpy(r->body+r->body_at,bytes+at,take);r->body_at+=take;at+=take;r->chunk_remaining-=take;
      if(!r->chunk_remaining)r->state=S_CHUNK_END;
    }else{result=fail(r,PRODUCT_DNS_HTTP_FRAMING);break;}
  }
  if(consumed)*consumed=at;
  if(result==PRODUCT_DNS_HTTP_MORE&&r->state==S_DONE)result=PRODUCT_DNS_HTTP_DONE;
  return result;
}

int product_dns_http_eof(product_dns_http_response_t *r)
{
  if(!r)return PRODUCT_DNS_HTTP_CLOSED;
  if(r->state==S_DONE)return PRODUCT_DNS_HTTP_DONE;
  if(r->state==S_BODY_CLOSE)return finish_body(r);
  r->state=S_FAILED;return PRODUCT_DNS_HTTP_CLOSED;
}
