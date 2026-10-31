/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_dns_tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "product_memory.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#define TLS_CONNECTIONS 5U
struct product_dns_tls_owner {
  sakamoto_mbedtls_budget_t aggregate, trust;
  /* Connection budgets live as long as the owner. Verification lazily caches
   * RSA/ECP state inside the shared trust anchors; that memory is allocated in
   * a connection scope but freed with the anchors, so its recorded budget must
   * outlive the connection. Such retained bytes stay charged to the slot. */
  sakamoto_mbedtls_budget_t slots[TLS_CONNECTIONS];
  uint8_t slot_used[TLS_CONNECTIONS];
  mbedtls_ssl_config config;
  mbedtls_x509_crt anchors;
  uint32_t certificates, connections, authenticated;
};
struct product_dns_tls {
  sakamoto_mbedtls_budget_t *memory;
  product_dns_tls_owner_t *owner;
  mbedtls_ssl_context ssl;
  int fd, error;
  uint8_t authenticated;
  char identity[256];
};

size_t product_dns_tls_reservation(unsigned connections)
{
  return sizeof(product_dns_tls_owner_t)+PRODUCT_DNS_TLS_OWNER_BYTES+
    connections*sizeof(product_dns_tls_t);
}
product_dns_tls_resources_t product_dns_tls_resources(const product_dns_tls_owner_t *owner)
{
  if(!owner)return (product_dns_tls_resources_t){0};
  return (product_dns_tls_resources_t){.bytes=sizeof(*owner)+owner->connections*sizeof(product_dns_tls_t)+owner->aggregate.bytes,
    .high_water_bytes=sizeof(*owner)+TLS_CONNECTIONS*sizeof(product_dns_tls_t)+owner->aggregate.high_water,
    .rejected=owner->aggregate.rejected,.trust_certificates=owner->certificates,
    .authenticated=owner->authenticated};
}
static int random_bytes(void *unused,unsigned char *bytes,size_t size)
{
  (void)unused;
  while(size){
    ssize_t n=getrandom(bytes,size,GRND_NONBLOCK);
    if(n<=0)return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    bytes+=n;size-=n;
  }
  return 0;
}
static int certificate(product_dns_tls_owner_t *owner,const unsigned char *bytes,size_t size)
{
  int result=mbedtls_x509_crt_parse(&owner->anchors,bytes,size);
  unsigned count=0;
  for(const mbedtls_x509_crt *p=&owner->anchors;p&&p->version;p=p->next)
    ++count;
  /* A partial upstream parse may already have appended valid certificates.
   * Count it before returning failure so a directory cannot retain unreported
   * anchors or evade the certificate bound after a partial bundle error. */
  owner->certificates=count;
  return !result&&count<=PRODUCT_DNS_TLS_TRUST_CERTIFICATES;
}
static int trust_file(product_dns_tls_owner_t *owner,int directory,const char *name,size_t *total)
{
  int fd=openat(directory,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
  struct stat st;
  if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||
      (uint64_t)st.st_size>PRODUCT_DNS_TLS_TRUST_INPUT_BYTES-*total){close(fd);return 0;}
  unsigned char bytes[PRODUCT_DNS_TLS_CERTIFICATE_BYTES+1];size_t at=0;
  /* System roots are individual bounded PEM/DER certificates. Host's ordinary
   * CA bundle is streamed one PEM at a time under the same total input cap. */
  int bundle=st.st_size>PRODUCT_DNS_TLS_CERTIFICATE_BYTES,good=1;
  if(bundle){
    unsigned char block[4096];ssize_t n;
    while((n=read(fd,block,sizeof(block)))>0){
      *total+=n;
      for(ssize_t i=0;i<n;++i){
        if(at==PRODUCT_DNS_TLS_CERTIFICATE_BYTES){good=0;break;}
        bytes[at++]=block[i];bytes[at]=0;
        if(block[i]=='\n'&&strstr((const char *)bytes,"-----END CERTIFICATE-----")){
          if(!certificate(owner,bytes,at+1)){good=0;break;}at=0;
        }
      }
      if(!good)break;
    }
    if(n<0)good=0;
    if(at){for(size_t i=0;i<at;++i)if(bytes[i]!='\r'&&bytes[i]!='\n'&&bytes[i]!=' '&&bytes[i]!='\t')good=0;}
  }else{
    ssize_t n;
    while(at<(size_t)st.st_size&&(n=read(fd,bytes+at,(size_t)st.st_size-at))>0)at+=n;
    bytes[at]=0;*total+=at;
    good=at==(size_t)st.st_size&&certificate(owner,bytes,
      at+(at>=10&&!memcmp(bytes,"-----BEGIN",10)));
  }
  close(fd);return good;
}
static int trust_directory(product_dns_tls_owner_t *owner,const char *path)
{
  int fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
  DIR *dir=fdopendir(fd);if(!dir){close(fd);return 0;}
  size_t total=0;unsigned examined=0;int good=1;struct dirent *entry;
  while((entry=readdir(dir))){
    if(entry->d_name[0]=='.')continue;
    if(++examined>512){good=0;break;}
    /* Directory inputs must all be CA files, not an arbitrary filesystem tree.
     * Unsupported/invalid individual system anchors remain unavailable. */
    unsigned before=owner->certificates;
    if(!trust_file(owner,fd,entry->d_name,&total)&&owner->certificates!=before){good=0;break;}
    if(owner->trust.rejected||total>=PRODUCT_DNS_TLS_TRUST_INPUT_BYTES){good=0;break;}
  }
  closedir(dir);return good&&owner->certificates;
}
product_dns_tls_owner_t *product_dns_tls_owner_open(const char *directory)
{
  product_dns_tls_owner_t *owner=calloc(1,sizeof(*owner));if(!owner)return NULL;
  owner->aggregate.limit=PRODUCT_DNS_TLS_OWNER_BYTES;
  owner->trust.limit=PRODUCT_DNS_TLS_TRUST_BYTES;owner->trust.parent=&owner->aggregate;
  mbedtls_ssl_config_init(&owner->config);mbedtls_x509_crt_init(&owner->anchors);
  sakamoto_mbedtls_budget_t *previous=sakamoto_mbedtls_scope(&owner->trust);
  int trusted=0;
  if(directory)trusted=trust_directory(owner,directory);
  else {
#ifdef __ANDROID__
    trusted=trust_directory(owner,"/apex/com.android.conscrypt/cacerts");
    if(!trusted&&owner->certificates==0)trusted=trust_directory(owner,"/system/etc/security/cacerts");
#else
    size_t total=0;trusted=trust_file(owner,AT_FDCWD,"/etc/ssl/certs/ca-certificates.crt",&total);
#endif
  }
  int configured=trusted&&!mbedtls_ssl_config_defaults(&owner->config,MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);
  if(configured){
    static const int suites[]={MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,0};
    mbedtls_ssl_conf_ciphersuites(&owner->config,suites);
    mbedtls_ssl_conf_min_tls_version(&owner->config,MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&owner->config,MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_authmode(&owner->config,MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&owner->config,random_bytes,NULL);
    mbedtls_ssl_conf_ca_chain(&owner->config,&owner->anchors,NULL);
  }
  sakamoto_mbedtls_scope(previous);
  if(!configured){product_dns_tls_owner_close(owner);return NULL;}
  return owner;
}
void product_dns_tls_owner_close(product_dns_tls_owner_t *owner)
{
  if(!owner)return;
  mbedtls_ssl_config_free(&owner->config);
  mbedtls_x509_crt_free(&owner->anchors);
  free(owner);
}
static int send_bytes(void *opaque,const unsigned char *bytes,size_t size)
{
  product_dns_tls_t *tls=opaque;ssize_t result=send(tls->fd,bytes,size,MSG_DONTWAIT|MSG_NOSIGNAL);
  if(result<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return MBEDTLS_ERR_SSL_WANT_WRITE;
  return result<0?MBEDTLS_ERR_SSL_INTERNAL_ERROR:(int)result;
}
static int receive_bytes(void *opaque,unsigned char *bytes,size_t size)
{
  product_dns_tls_t *tls=opaque;ssize_t result=recv(tls->fd,bytes,size,MSG_DONTWAIT);
  if(result<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return MBEDTLS_ERR_SSL_WANT_READ;
  return result<0?MBEDTLS_ERR_SSL_INTERNAL_ERROR:(int)result;
}
product_dns_tls_t *product_dns_tls_open(product_dns_tls_owner_t *owner,int fd,const char *identity)
{
  if(!owner||fd<0||!identity||!identity[0]||strlen(identity)>=256||owner->connections>=TLS_CONNECTIONS)return NULL;
  product_dns_tls_t *tls=calloc(1,sizeof(*tls));if(!tls)return NULL;
  tls->owner=owner;tls->fd=fd;memcpy(tls->identity,identity,strlen(identity)+1);
  unsigned slot=0;while(slot<TLS_CONNECTIONS&&owner->slot_used[slot])++slot;
  if(slot==TLS_CONNECTIONS){free(tls);return NULL;}
  owner->slot_used[slot]=1;tls->memory=&owner->slots[slot];
  tls->memory->limit=PRODUCT_DNS_TLS_CONNECTION_BYTES;tls->memory->parent=&owner->aggregate;
  mbedtls_ssl_init(&tls->ssl);
  sakamoto_mbedtls_budget_t *previous=sakamoto_mbedtls_scope(tls->memory);
  int result=mbedtls_ssl_setup(&tls->ssl,&owner->config);
  if(!result)result=mbedtls_ssl_set_hostname(&tls->ssl,identity);
  sakamoto_mbedtls_scope(previous);
  if(result){mbedtls_ssl_free(&tls->ssl);owner->slot_used[tls->memory-owner->slots]=0;free(tls);return NULL;}
  mbedtls_ssl_set_bio(&tls->ssl,tls,send_bytes,receive_bytes,NULL);
  ++owner->connections;return tls;
}
void product_dns_tls_close(product_dns_tls_t *tls)
{
  if(!tls)return;
  mbedtls_ssl_free(&tls->ssl);--tls->owner->connections;
  tls->owner->slot_used[tls->memory-tls->owner->slots]=0;
  if(tls->authenticated)--tls->owner->authenticated;
  free(tls);
}
static int dns_identity(const product_dns_tls_t *tls)
{
  const mbedtls_x509_crt *peer=mbedtls_ssl_get_peer_cert(&tls->ssl);
  if(!peer)return 0;
  uint8_t ip[16];int length=inet_pton(AF_INET,tls->identity,ip)==1?4:
    inet_pton(AF_INET6,tls->identity,ip)==1?16:0;
  for(const mbedtls_x509_sequence *san=&peer->subject_alt_names;san;san=san->next){
    unsigned type=san->buf.tag&MBEDTLS_ASN1_TAG_VALUE_MASK;
    if(length){
      if(type==MBEDTLS_X509_SAN_IP_ADDRESS&&san->buf.len==(size_t)length&&!memcmp(san->buf.p,ip,length))return 1;
    }else if(type==MBEDTLS_X509_SAN_DNS_NAME){
      size_t n=strlen(tls->identity);
      if(n==san->buf.len&&!strncasecmp(tls->identity,(const char *)san->buf.p,n))return 1;
      const char *dot=strchr(tls->identity,'.');
      if(dot&&san->buf.len>2&&san->buf.p[0]=='*'&&san->buf.p[1]=='.'&&
          strlen(dot)==san->buf.len-1&&!strncasecmp(dot,(const char *)san->buf.p+1,san->buf.len-1))return 1;
    }
  }
  return 0;
}
static int wanted_event(int result,unsigned *wanted)
{
  *wanted=result==MBEDTLS_ERR_SSL_WANT_READ?1:result==MBEDTLS_ERR_SSL_WANT_WRITE?2:0;
  return *wanted!=0;
}
int product_dns_tls_pending(const product_dns_tls_t *tls)
{return tls&&mbedtls_ssl_check_pending(&tls->ssl);}
int product_dns_tls_error(const product_dns_tls_t *tls)
{return tls?tls->error:0;}
int product_dns_tls_handshake(product_dns_tls_t *tls,unsigned *wanted)
{
  if(!tls||!wanted)return -1;
  if(tls->authenticated){*wanted=0;return 1;}
  sakamoto_mbedtls_budget_t *previous=sakamoto_mbedtls_scope(tls->memory);
  int result=mbedtls_ssl_handshake(&tls->ssl);
  sakamoto_mbedtls_scope(previous);
  if(wanted_event(result,wanted))return 0;
  if(result||mbedtls_ssl_get_verify_result(&tls->ssl)||!dns_identity(tls)){
    tls->error=result?result:MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;return -1;
  }
  tls->authenticated=1;++tls->owner->authenticated;return 1;
}
ssize_t product_dns_tls_write(product_dns_tls_t *tls,const uint8_t *bytes,size_t size,unsigned *wanted)
{
  if(!tls||!tls->authenticated||!wanted)return -1;
  sakamoto_mbedtls_budget_t *previous=sakamoto_mbedtls_scope(tls->memory);
  int result=mbedtls_ssl_write(&tls->ssl,bytes,size);
  sakamoto_mbedtls_scope(previous);
  if(wanted_event(result,wanted))return -2;
  if(result<=0)tls->error=result;
  return result<=0?-1:result;
}
ssize_t product_dns_tls_read(product_dns_tls_t *tls,uint8_t *bytes,size_t size,unsigned *wanted)
{
  if(!tls||!tls->authenticated||!wanted)return -1;
  sakamoto_mbedtls_budget_t *previous=sakamoto_mbedtls_scope(tls->memory);
  int result=mbedtls_ssl_read(&tls->ssl,bytes,size);
  sakamoto_mbedtls_scope(previous);
  if(wanted_event(result,wanted))return -2;
  if(result<=0)tls->error=result;
  return result<=0?-1:result;
}
