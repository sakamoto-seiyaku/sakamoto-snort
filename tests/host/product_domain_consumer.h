/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DOMAIN_CONSUMER_TEST_H
#define PRODUCT_DOMAIN_CONSUMER_TEST_H
#include "product_domains.h"
#include "product_l4_policy.h"
#include "product_protocol_catalog.h"
#include <assert.h>
#include <string.h>

/* Called with independently expected parser results after public owner input.
 * Literal names decide expected memberships; the actual projection uses rax. */
static void domain_consumer(const product_flow_entry_t *entry, unsigned expected_result,
                            const char *expected_name, unsigned protocol) {
    assert(entry->sni.result==expected_result && !strcmp(entry->sni.name,expected_name));
    sakamoto_product_domains_t source={.list_count=2,.entry_count=6,
        .entries={{.list=0,.length=11,.name="example.com"},
                  {.list=0,.length=12,.name="example.test"},
                  {.list=0,.length=13,.name="example.tests"},
                  {.list=1,.mode=1,.length=3,.name="com"},
                  {.list=1,.mode=1,.length=4,.name="test"},
                  {.list=1,.mode=1,.length=5,.name="tests"}}};
    product_domains_t *domains=NULL;
    assert(!product_domains_build(&source,&domains));
    int exact=!strcmp(expected_name,"example.com") || !strcmp(expected_name,"example.test") ||
              !strcmp(expected_name,"example.tests");
    const char *last=strrchr(expected_name,'.');
    int descendant=last && (!strcmp(last+1,"com") || !strcmp(last+1,"test") || !strcmp(last+1,"tests"));
    product_l4_policy_rule_t rules[4];
    for(unsigned i=0;i<4;++i) rules[i]=(product_l4_policy_rule_t){
        .rule_id=101+i,.reason_id=201+i,.priority=1+i,.order=5+i,.uid=17,
        .action=i==3?1:2,.mode=i==1?0:1,.network_context_id=UINT32_MAX,
        .ifindex=UINT32_MAX,.source_port_last=65535,.destination_port_last=65535};
    rules[0].expression_length=8;memcpy(rules[0].expression,(uint8_t[]){17,0,12,187,1,187,1,1},8);
    rules[1].expression_length=2;memcpy(rules[1].expression,(uint8_t[]){17,1},2);
    rules[2].expression_length=3;memcpy(rules[2].expression,(uint8_t[]){17,1,3},3);
    for(unsigned plan=0;plan<3;++plan) {
        product_l4_policy_compile_budget_t budget=product_l4_policy_default_budget();
        if(plan) budget.direct_entries=0;
        if(plan==2) budget.factor_rules=0;
        product_l4_policy_view_t view;
        assert(!product_l4_policy_compile_with_budget(&view,rules,4,&budget));
        product_policy_cache_t cache={0};
        product_policy_cache_identity_t identity={7,1,33,entry->incarnation};
        product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=protocol,
            .ports_available=1,.source_port=42000,.destination_port=443};
        product_l4_policy_match_result_t actual;
        for(unsigned i=0;i<2;++i) {
            assert(!product_l4_policy_match_cached(&cache,&view,&packet,&identity,0,&actual));
            assert(actual.rule_id==104 && actual.actual_action==1);
        }
        packet.sni_result=entry->sni.result;packet.protocol_set=entry->lpi.protocols;
        packet.protocol_set_known=entry->lpi.available;
        packet.domain_lists=product_domains_match(domains,(const uint8_t *)entry->sni.name,entry->sni.name_length);
        assert(packet.domain_lists==(expected_result==PRODUCT_SNI_NAME ? (unsigned)exact+2U*(unsigned)descendant : 0));
        int applicable=entry->lpi.available && (entry->lpi.protocols &
            (product_protocol_bit(1003)|product_protocol_bit(1004)));
        unsigned winner=!expected_result || !applicable ? 3 : exact ? 0 : descendant ? 1 : 2;
        for(unsigned i=0;i<2;++i) {
            assert(!product_l4_policy_match_cached(&cache,&view,&packet,&identity,0,&actual));
            assert(actual.rule_id==101+winner && actual.reason_id==201+winner);
            assert(actual.priority==1+winner && actual.order==5+winner && actual.winner_rank==1+winner);
            assert(actual.mode==rules[winner].mode && actual.action==rules[winner].action);
            assert(actual.actual_action==(winner==1?2:1));
        }
        /* Current reverse-packet ports still constrain the complete rule. */
        packet.source_port=443;packet.destination_port=42000;
        assert(!product_l4_policy_match_cached(&cache,&view,&packet,&identity,0,&actual));
        unsigned reverse=!expected_result || !applicable ? 3 : descendant ? 1 : 2;
        assert(actual.rule_id==101+reverse && actual.winner_rank==1+reverse);
    }
    product_domains_destroy(domains);
}
#endif
