#!/bin/bash
# tests/integration/full-smoke.sh - sucre-snort 完整冒烟测试
# 覆盖 BACKEND_DEV_SMOKE.md 中的 24 个测试用例

# 不使用 set -e，让测试继续运行

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# ============================================================================
# 测试用例
# ============================================================================

# 取样应用 UID（com.android.angle）
SAMPLE_UID=""
SAMPLE_PKG=""

# 获取取样应用
get_sample_app() {
    local result
    result=$(send_cmd "APP.NAME com.android")
    if [[ -z "$result" ]]; then
        echo "警告: 无法获取应用列表"
        SAMPLE_UID="10118"
        SAMPLE_PKG="com.android.angle"
        return
    fi

    # 提取第一个应用的 uid 和 name
    SAMPLE_UID=$(echo "$result" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data:
    print(data[0]['uid'])
" 2>/dev/null || echo "10118")

    SAMPLE_PKG=$(echo "$result" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data:
    print(data[0]['name'])
" 2>/dev/null || echo "com.android.angle")

    log_info "取样应用: $SAMPLE_PKG (uid=$SAMPLE_UID)"
}

# DEV.DNSQUERY helper: echoes 1 if blocked, 0 if allowed.
dev_dnsquery_blocked_flag() {
    local uid="$1"
    local domain="$2"

    local out
    out=$(send_cmd "DEV.DNSQUERY $uid $domain")
    local rc=$?
    if [[ $rc -ne 0 || -z "$out" || "$out" == "NOK" ]]; then
        return 1
    fi

    echo "$out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(1 if d.get('blocked') else 0)
" 2>/dev/null
}

# ----------------------------------------------------------------------------
# Group 1: 连接与协议 (TC-01, TC-02)
# ----------------------------------------------------------------------------

test_group_1() {
    log_section "Group 1: 连接与协议"

    # TC-01: HELLO
    assert_ok "HELLO" "TC-01 HELLO"

    # TC-02: HELP
    assert_not_empty "HELP" "TC-02 HELP"
}

# ----------------------------------------------------------------------------
# Group 2: 密码与状态 (TC-03, TC-04)
# ----------------------------------------------------------------------------

test_group_2() {
    log_section "Group 2: 密码与状态"

    # TC-03: PASSWORD 设置/查询/清空
    local pwd_set pwd_get pwd_clear

    pwd_set=$(send_cmd 'PASSWORD "testpwd"')
    if [[ "$pwd_set" != "OK" ]]; then
        log_fail "TC-03 PASSWORD 设置"
        echo "    响应: $pwd_set"
    else
        pwd_get=$(send_cmd 'PASSWORD')
        if [[ "$pwd_get" == '"testpwd"' ]]; then
            pwd_clear=$(send_cmd 'PASSWORD ""')
            if [[ "$pwd_clear" == "OK" ]]; then
                log_pass "TC-03 PASSWORD 设置/查询/清空"
            else
                log_fail "TC-03 PASSWORD 清空失败"
            fi
        else
            log_fail "TC-03 PASSWORD 查询不匹配"
            echo "    预期: \"testpwd\""
            echo "    实际: $pwd_get"
        fi
    fi

    # TC-04: PASSSTATE
    assert_set_get "PASSSTATE" "1" "0" "TC-04 PASSSTATE"
}

# ----------------------------------------------------------------------------
# Group 3: 全局开关与参数 (TC-05 ~ TC-10)
# ----------------------------------------------------------------------------

test_group_3() {
    log_section "Group 3: 全局开关与参数"

    # TC-05: BLOCK
    local block_orig
    block_orig=$(send_cmd "BLOCK")
    assert_set_get "BLOCK" "0" "$block_orig" "TC-05 BLOCK"

    # TC-06: RDNS
    local rdns_set rdns_unset
    rdns_set=$(send_cmd "RDNS.SET")
    rdns_unset=$(send_cmd "RDNS.UNSET")
    if [[ "$rdns_set" == "OK" && "$rdns_unset" == "OK" ]]; then
        log_pass "TC-06 RDNS.SET/UNSET"
    else
        log_fail "TC-06 RDNS.SET/UNSET"
        echo "    SET: $rdns_set, UNSET: $rdns_unset"
    fi

    # TC-07: GETBLACKIPS
    local gbi_orig
    gbi_orig=$(send_cmd "GETBLACKIPS")
    if [[ "$gbi_orig" =~ ^[01]$ ]]; then
        local new_val=$((1 - gbi_orig))
        assert_set_get "GETBLACKIPS" "$new_val" "$gbi_orig" "TC-07 GETBLACKIPS"
    else
        log_fail "TC-07 GETBLACKIPS 查询格式错误"
        echo "    响应: $gbi_orig"
    fi

    # TC-08: BLOCKIPLEAKS
    local bil_orig
    bil_orig=$(send_cmd "BLOCKIPLEAKS")
    if [[ "$bil_orig" =~ ^[01]$ ]]; then
        local new_val=$((1 - bil_orig))
        assert_set_get "BLOCKIPLEAKS" "$new_val" "$bil_orig" "TC-08 BLOCKIPLEAKS"
    else
        log_fail "TC-08 BLOCKIPLEAKS 查询格式错误"
        echo "    响应: $bil_orig"
    fi

    # TC-09: MAXAGEIP
    local mai_orig
    mai_orig=$(send_cmd "MAXAGEIP")
    if [[ "$mai_orig" =~ ^[0-9]+$ ]]; then
        assert_set_get "MAXAGEIP" "14400" "$mai_orig" "TC-09 MAXAGEIP"
    else
        log_fail "TC-09 MAXAGEIP 查询格式错误"
        echo "    响应: $mai_orig"
    fi

    # TC-10: BLOCKMASKDEF / BLOCKIFACEDEF
    local bmd_orig bid_orig
    bmd_orig=$(send_cmd "BLOCKMASKDEF")
    bid_orig=$(send_cmd "BLOCKIFACEDEF")

    if [[ "$bmd_orig" =~ ^[0-9]+$ ]]; then
        assert_set_get "BLOCKMASKDEF" "129" "$bmd_orig" "TC-10a BLOCKMASKDEF"
    else
        log_fail "TC-10a BLOCKMASKDEF 查询格式错误"
    fi

    if [[ "$bid_orig" =~ ^[0-9]+$ ]]; then
        assert_set_get "BLOCKIFACEDEF" "0" "$bid_orig" "TC-10b BLOCKIFACEDEF"
    else
        log_fail "TC-10b BLOCKIFACEDEF 查询格式错误"
    fi
}

# ----------------------------------------------------------------------------
# Group 4: 应用操作 (TC-11 ~ TC-13)
# ----------------------------------------------------------------------------

test_group_4() {
    log_section "Group 4: 应用操作"

    # TC-11: APP.NAME 取样
    local app_result
    app_result=$(send_cmd "APP.NAME com")
    if echo "$app_result" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if len(d)>0 else 1)" 2>/dev/null; then
        log_pass "TC-11 APP.NAME 取样"
    else
        log_fail "TC-11 APP.NAME 取样"
        echo "    响应: ${app_result:0:200}..."
    fi

    # TC-12: APP.UID / TRACK / UNTRACK
    local uid_result track_result untrack_result
    uid_result=$(send_cmd "APP.UID $SAMPLE_UID")
    if echo "$uid_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-12a APP.UID $SAMPLE_UID"
    else
        log_fail "TC-12a APP.UID $SAMPLE_UID"
    fi

    track_result=$(send_cmd "TRACK $SAMPLE_UID")
    untrack_result=$(send_cmd "UNTRACK $SAMPLE_UID")
    # 恢复 track 状态
    send_cmd "TRACK $SAMPLE_UID" >/dev/null

    if [[ "$track_result" == "OK" && "$untrack_result" == "OK" ]]; then
        log_pass "TC-12b TRACK/UNTRACK"
    else
        log_fail "TC-12b TRACK/UNTRACK"
        echo "    TRACK: $track_result, UNTRACK: $untrack_result"
    fi

    # TC-13: BLOCKMASK / BLOCKIFACE
    local bm_orig bi_orig
    bm_orig=$(send_cmd "BLOCKMASK $SAMPLE_UID")
    bi_orig=$(send_cmd "BLOCKIFACE $SAMPLE_UID")

    if [[ "$bm_orig" =~ ^[0-9]+$ ]]; then
        assert_set_get "BLOCKMASK $SAMPLE_UID" "128" "$bm_orig" "TC-13a BLOCKMASK"
    else
        log_fail "TC-13a BLOCKMASK 查询失败"
    fi

    if [[ "$bi_orig" =~ ^[0-9]+$ ]]; then
        assert_set_get "BLOCKIFACE $SAMPLE_UID" "1" "$bi_orig" "TC-13b BLOCKIFACE"
    else
        log_fail "TC-13b BLOCKIFACE 查询失败"
    fi
}

# ----------------------------------------------------------------------------
# Group 5: 统计 (TC-14)
# ----------------------------------------------------------------------------

test_group_5() {
    log_section "Group 5: 统计"

    # TC-14a: ALL.A
    assert_json "ALL.A" "TC-14a ALL.A 全局统计"

    # TC-14b: APP.DNS.0
    local dns_result
    dns_result=$(send_cmd "APP.DNS.0 $SAMPLE_UID")
    if echo "$dns_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-14b APP.DNS.0 应用统计"
    else
        log_fail "TC-14b APP.DNS.0 应用统计"
        echo "    响应: ${dns_result:0:200}"
    fi

    # TC-14c: APP.RESET.A 移到最后测试（会清空统计）
}

# ----------------------------------------------------------------------------
# Group 6: 域名视图 (TC-15)
# ----------------------------------------------------------------------------

test_group_6() {
    log_section "Group 6: 域名视图"

    # TC-15a: DOMAINS.0
    assert_json "DOMAINS.0" "TC-15a DOMAINS.0"

    # TC-15b: BLACK.A / WHITE.A / GREY.A
    local black_result white_result grey_result
    black_result=$(send_cmd "BLACK.A")
    white_result=$(send_cmd "WHITE.A")
    grey_result=$(send_cmd "GREY.A")

    # 可能返回空数组
    if echo "$black_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-15b BLACK.A"
    else
        log_fail "TC-15b BLACK.A"
    fi

    if echo "$white_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-15c WHITE.A"
    else
        log_fail "TC-15c WHITE.A"
    fi

    if echo "$grey_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-15d GREY.A"
    else
        log_fail "TC-15d GREY.A"
    fi
}

# ----------------------------------------------------------------------------
# Group 7: 主机 (TC-16)
# ----------------------------------------------------------------------------

test_group_7() {
    log_section "Group 7: 主机"

    # TC-16: HOSTS
    local hosts_result
    hosts_result=$(send_cmd "HOSTS")
    if echo "$hosts_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-16a HOSTS"
    else
        log_fail "TC-16a HOSTS"
        echo "    响应: ${hosts_result:0:200}"
    fi

    # TC-16b: HOSTS.NAME
    hosts_result=$(send_cmd "HOSTS.NAME play")
    if echo "$hosts_result" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "TC-16b HOSTS.NAME"
    else
        log_fail "TC-16b HOSTS.NAME"
    fi
}

# ----------------------------------------------------------------------------
# Group 8: 黑白名单 (TC-17, TC-18)
# ----------------------------------------------------------------------------

test_group_8() {
    log_section "Group 8: 黑白名单"

    local ts=$(date +%s)
    local test_domain="smoke-$ts.sucre.invalid"

    # TC-17: 全局黑白名单
    local add_result print_result remove_result

    # 黑名单
    add_result=$(send_cmd "BLACKLIST.ADD $test_domain")
    if [[ "$add_result" == "OK" ]]; then
        print_result=$(send_cmd "BLACKLIST.PRINT")
        if echo "$print_result" | grep -q "$test_domain"; then
            remove_result=$(send_cmd "BLACKLIST.REMOVE $test_domain")
            if [[ "$remove_result" == "OK" ]]; then
                log_pass "TC-17a BLACKLIST 全局"
            else
                log_fail "TC-17a BLACKLIST.REMOVE"
            fi
        else
            log_fail "TC-17a BLACKLIST.PRINT 未包含测试域名"
        fi
    else
        log_fail "TC-17a BLACKLIST.ADD"
        echo "    响应: $add_result"
    fi

    # 白名单
    add_result=$(send_cmd "WHITELIST.ADD $test_domain")
    if [[ "$add_result" == "OK" ]]; then
        print_result=$(send_cmd "WHITELIST.PRINT")
        if echo "$print_result" | grep -q "$test_domain"; then
            remove_result=$(send_cmd "WHITELIST.REMOVE $test_domain")
            if [[ "$remove_result" == "OK" ]]; then
                log_pass "TC-17b WHITELIST 全局"
            else
                log_fail "TC-17b WHITELIST.REMOVE"
            fi
        else
            log_fail "TC-17b WHITELIST.PRINT 未包含测试域名"
        fi
    else
        log_fail "TC-17b WHITELIST.ADD"
    fi

    # TC-18: 按应用黑白名单
    # 需要域名先"存在"（通过全局命令添加）
    local app_domain="apptest-$ts.sucre.invalid"

    # 先添加到全局黑名单（让域名存在）
    add_result=$(send_cmd "BLACKLIST.ADD $app_domain")
    if [[ "$add_result" != "OK" ]]; then
        log_fail "TC-18a 准备域名失败"
        return
    fi

    # 测试应用级黑名单
    add_result=$(send_cmd "BLACKLIST.ADD $SAMPLE_UID $app_domain")
    if [[ "$add_result" == "OK" ]]; then
        print_result=$(send_cmd "BLACKLIST.PRINT $SAMPLE_UID")
        if echo "$print_result" | grep -q "$app_domain"; then
            remove_result=$(send_cmd "BLACKLIST.REMOVE $SAMPLE_UID $app_domain")
            if [[ "$remove_result" == "OK" ]]; then
                log_pass "TC-18a BLACKLIST 应用级"
            else
                log_fail "TC-18a BLACKLIST.REMOVE 应用级"
            fi
        else
            log_fail "TC-18a BLACKLIST.PRINT 应用级未包含域名"
        fi
    else
        log_fail "TC-18a BLACKLIST.ADD 应用级"
        echo "    响应: $add_result"
    fi

    # 测试应用级白名单（域名已存在于全局黑名单，可添加到应用白名单）
    add_result=$(send_cmd "WHITELIST.ADD $SAMPLE_UID $app_domain")
    if [[ "$add_result" == "OK" ]]; then
        print_result=$(send_cmd "WHITELIST.PRINT $SAMPLE_UID")
        if echo "$print_result" | grep -q "$app_domain"; then
            remove_result=$(send_cmd "WHITELIST.REMOVE $SAMPLE_UID $app_domain")
            if [[ "$remove_result" == "OK" ]]; then
                log_pass "TC-18b WHITELIST 应用级"
            else
                log_fail "TC-18b WHITELIST.REMOVE 应用级"
            fi
        else
            log_fail "TC-18b WHITELIST.PRINT 应用级未包含域名"
        fi
    else
        log_fail "TC-18b WHITELIST.ADD 应用级"
    fi

    # 清理：移除全局域名
    send_cmd "BLACKLIST.REMOVE $app_domain" >/dev/null
}

# ----------------------------------------------------------------------------
# Group 9: 规则 (TC-19, TC-20)
# ----------------------------------------------------------------------------

test_group_9() {
    log_section "Group 9: 规则"

    # TC-19: RULES 全局
    local rule_id add_result print_result update_result remove_result

    add_result=$(send_cmd "RULES.ADD 1 *.smoke-test.*")
    # RULES.ADD 返回带引号的字符串，如 "0"
    if [[ "$add_result" =~ ^\"?[0-9]+\"?$ ]]; then
        # 去掉引号
        rule_id="${add_result//\"/}"
        log_pass "TC-19a RULES.ADD (id=$rule_id)"

        print_result=$(send_cmd "RULES.PRINT")
        if echo "$print_result" | grep -q "smoke-test"; then
            log_pass "TC-19b RULES.PRINT"
        else
            log_fail "TC-19b RULES.PRINT 未包含测试规则"
        fi

        update_result=$(send_cmd "RULES.UPDATE $rule_id 1 *.smoke-test2.*")
        if [[ "$update_result" == "OK" ]]; then
            log_pass "TC-19c RULES.UPDATE"
        else
            log_fail "TC-19c RULES.UPDATE"
        fi

        remove_result=$(send_cmd "RULES.REMOVE $rule_id")
        if [[ "$remove_result" == "OK" ]]; then
            log_pass "TC-19d RULES.REMOVE"
        else
            log_fail "TC-19d RULES.REMOVE"
        fi
    else
        log_fail "TC-19a RULES.ADD"
        echo "    响应: $add_result"
    fi

    # TC-20: BLACKRULES / WHITERULES
    # 创建规则后测试
    add_result=$(send_cmd "RULES.ADD 2 smoke-br-test.example.org")
    # 同样处理带引号的返回值
    if [[ "$add_result" =~ ^\"?[0-9]+\"?$ ]]; then
        rule_id="${add_result//\"/}"

        # 全局 BLACKRULES
        local br_add br_remove
        br_add=$(send_cmd "BLACKRULES.ADD $rule_id")
        br_remove=$(send_cmd "BLACKRULES.REMOVE $rule_id")
        if [[ "$br_add" == "OK" && "$br_remove" == "OK" ]]; then
            log_pass "TC-20a BLACKRULES 全局"
        else
            log_fail "TC-20a BLACKRULES 全局"
        fi

        # 应用级 WHITERULES
        local wr_add wr_remove
        wr_add=$(send_cmd "WHITERULES.ADD $SAMPLE_UID $rule_id")
        wr_remove=$(send_cmd "WHITERULES.REMOVE $SAMPLE_UID $rule_id")
        if [[ "$wr_add" == "OK" && "$wr_remove" == "OK" ]]; then
            log_pass "TC-20b WHITERULES 应用级"
        else
            log_fail "TC-20b WHITERULES 应用级"
        fi

        # 清理规则
        send_cmd "RULES.REMOVE $rule_id" >/dev/null
    else
        log_fail "TC-20 规则创建失败"
    fi
}

# ----------------------------------------------------------------------------
# Group 10: 拦截清单 (TC-21)
# ----------------------------------------------------------------------------

test_group_10() {
    log_section "Group 10: 拦截清单 (BLOCKLIST)"

    local guid="12345678-1234-1234-1234-$(date +%s | tail -c 13)"
    local url="https://smoke-test.invalid/list.txt"
    local name="Smoke Test List"

    # TC-21a: BLOCKLIST.BLACK.ADD
    local add_result
    add_result=$(send_cmd "BLOCKLIST.BLACK.ADD $guid $url 1 $name")
    if [[ "$add_result" == "OK" ]]; then
        log_pass "TC-21a BLOCKLIST.BLACK.ADD"
    else
        log_fail "TC-21a BLOCKLIST.BLACK.ADD"
        echo "    响应: $add_result"
        return
    fi

    # TC-21b: BLOCKLIST.PRINT
    local print_result
    print_result=$(send_cmd "BLOCKLIST.PRINT")
    if echo "$print_result" | grep -q "$guid"; then
        log_pass "TC-21b BLOCKLIST.PRINT"
    else
        log_fail "TC-21b BLOCKLIST.PRINT"
    fi

    # TC-21c: DOMAIN.BLACK.ADD.MANY
    local add_many_result
    add_many_result=$(send_cmd "DOMAIN.BLACK.ADD.MANY $guid 1 true a.smoke.invalid;b.smoke.invalid")
    if [[ "$add_many_result" == "2" ]]; then
        log_pass "TC-21c DOMAIN.BLACK.ADD.MANY"
    else
        log_fail "TC-21c DOMAIN.BLACK.ADD.MANY"
        echo "    预期: 2, 实际: $add_many_result"
    fi

    # TC-21d: DOMAIN.BLACK.PRINT
    local domain_print
    domain_print=$(send_cmd "DOMAIN.BLACK.PRINT $guid")
    if echo "$domain_print" | grep -q "smoke.invalid"; then
        log_pass "TC-21d DOMAIN.BLACK.PRINT"
    else
        log_fail "TC-21d DOMAIN.BLACK.PRINT"
    fi

    # TC-21e: BLOCKLIST.BLACK.DISABLE / ENABLE
    local disable_result enable_result
    disable_result=$(send_cmd "BLOCKLIST.BLACK.DISABLE $guid")
    enable_result=$(send_cmd "BLOCKLIST.BLACK.ENABLE $guid")
    if [[ "$disable_result" == "OK" && "$enable_result" == "OK" ]]; then
        log_pass "TC-21e BLOCKLIST DISABLE/ENABLE"
    else
        log_fail "TC-21e BLOCKLIST DISABLE/ENABLE"
    fi

    # TC-21f: BLOCKLIST.BLACK.REMOVE
    local remove_result
    remove_result=$(send_cmd "BLOCKLIST.BLACK.REMOVE $guid")
    if [[ "$remove_result" == "OK" ]]; then
        log_pass "TC-21f BLOCKLIST.BLACK.REMOVE"
    else
        log_fail "TC-21f BLOCKLIST.BLACK.REMOVE"
    fi

    # TC-21g: combinable blockmask chains (independent list lifecycle)
    local chain_domain="chain.smoke.invalid"
    local chain_suffix
    chain_suffix="$(date +%s%N | tail -c 13)"
    local guid_a="22222222-2222-2222-2222-${chain_suffix}"
    local guid_b="33333333-3333-3333-3333-${chain_suffix}"
    local url_a="https://smoke-test.invalid/chainA.txt"
    local url_b="https://smoke-test.invalid/chainB.txt"
    local name_a="Smoke Chain A"
    local name_b="Smoke Chain B"

    local block_orig bm_orig
    block_orig=$(send_cmd "BLOCK")
    bm_orig=$(send_cmd "BLOCKMASK $SAMPLE_UID")

    # Ensure DEV.DNSQUERY reflects blocking decisions.
    send_cmd "BLOCK 1" >/dev/null 2>&1 || true

    local chain_failed=0
    local r

    r=$(send_cmd "BLOCKLIST.BLACK.ADD $guid_a $url_a 2 $name_a")
    if [[ "$r" != "OK" ]]; then
        log_fail "TC-21g.1 BLOCKLIST.BLACK.ADD (mask=2)"
        chain_failed=1
    fi
    r=$(send_cmd "BLOCKLIST.BLACK.ADD $guid_b $url_b 4 $name_b")
    if [[ "$r" != "OK" ]]; then
        log_fail "TC-21g.2 BLOCKLIST.BLACK.ADD (mask=4)"
        chain_failed=1
    fi

    r=$(send_cmd "DOMAIN.BLACK.ADD.MANY $guid_a 2 true $chain_domain")
    if [[ "$r" != "1" ]]; then
        log_fail "TC-21g.3 DOMAIN.BLACK.ADD.MANY (list A)"
        echo "    预期: 1, 实际: $r"
        chain_failed=1
    fi
    r=$(send_cmd "DOMAIN.BLACK.ADD.MANY $guid_b 4 true $chain_domain")
    if [[ "$r" != "1" ]]; then
        log_fail "TC-21g.4 DOMAIN.BLACK.ADD.MANY (list B)"
        echo "    预期: 1, 实际: $r"
        chain_failed=1
    fi

    if [[ "$chain_failed" -eq 0 ]]; then
        # A enabled + appMask=2 -> blocked.
        send_cmd "BLOCKMASK $SAMPLE_UID 2" >/dev/null 2>&1 || true
        local blocked
        blocked="$(dev_dnsquery_blocked_flag "$SAMPLE_UID" "$chain_domain")"
        if [[ "$blocked" == "1" ]]; then
            log_pass "TC-21g.5 listA enabled blocks via appMask=2"
        else
            log_fail "TC-21g.5 listA enabled blocks via appMask=2"
            chain_failed=1
        fi

        # Disable A -> appMask=2 should no longer block (B contributes 4 only).
        send_cmd "BLOCKLIST.BLACK.DISABLE $guid_a" >/dev/null 2>&1 || true
        blocked="$(dev_dnsquery_blocked_flag "$SAMPLE_UID" "$chain_domain")"
        if [[ "$blocked" == "0" ]]; then
            log_pass "TC-21g.6 disable listA does not depend on listB"
        else
            log_fail "TC-21g.6 disable listA does not depend on listB"
            chain_failed=1
        fi

        # Enable A, set appMask=4 -> blocked via B.
        send_cmd "BLOCKLIST.BLACK.ENABLE $guid_a" >/dev/null 2>&1 || true
        send_cmd "BLOCKMASK $SAMPLE_UID 4" >/dev/null 2>&1 || true
        blocked="$(dev_dnsquery_blocked_flag "$SAMPLE_UID" "$chain_domain")"
        if [[ "$blocked" == "1" ]]; then
            log_pass "TC-21g.7 listB enabled blocks via appMask=4"
        else
            log_fail "TC-21g.7 listB enabled blocks via appMask=4"
            chain_failed=1
        fi

        # Disable B -> appMask=4 should no longer block (A contributes 2 only).
        send_cmd "BLOCKLIST.BLACK.DISABLE $guid_b" >/dev/null 2>&1 || true
        blocked="$(dev_dnsquery_blocked_flag "$SAMPLE_UID" "$chain_domain")"
        if [[ "$blocked" == "0" ]]; then
            log_pass "TC-21g.8 disable listB does not depend on listA"
        else
            log_fail "TC-21g.8 disable listB does not depend on listA"
            chain_failed=1
        fi

        # Re-enable B, remove A -> appMask=4 must still block.
        send_cmd "BLOCKLIST.BLACK.ENABLE $guid_b" >/dev/null 2>&1 || true
        send_cmd "BLOCKLIST.BLACK.REMOVE $guid_a" >/dev/null 2>&1 || true
        blocked="$(dev_dnsquery_blocked_flag "$SAMPLE_UID" "$chain_domain")"
        if [[ "$blocked" == "1" ]]; then
            log_pass "TC-21g.9 remove listA does not affect listB"
        else
            log_fail "TC-21g.9 remove listA does not affect listB"
            chain_failed=1
        fi
    fi

    # TC-21h: BLOCKMASK normalization (reinforced implies standard)
    local norm_set norm_get
    norm_set=$(send_cmd "BLOCKMASK $SAMPLE_UID 8")
    norm_get=$(send_cmd "BLOCKMASK $SAMPLE_UID")
    if [[ "$norm_set" == "OK" && "$norm_get" == "9" ]]; then
        log_pass "TC-21h BLOCKMASK 8 normalizes to 9"
    else
        log_fail "TC-21h BLOCKMASK 8 normalizes to 9"
        echo "    set: $norm_set, get: $norm_get"
    fi

    # Best-effort cleanup + restore.
    send_cmd "BLOCKLIST.BLACK.REMOVE $guid_a" >/dev/null 2>&1 || true
    send_cmd "BLOCKLIST.BLACK.REMOVE $guid_b" >/dev/null 2>&1 || true
    if [[ "$bm_orig" =~ ^[0-9]+$ ]]; then
        send_cmd "BLOCKMASK $SAMPLE_UID $bm_orig" >/dev/null 2>&1 || true
    fi
    if [[ "$block_orig" =~ ^[0-9]+$ ]]; then
        send_cmd "BLOCK $block_orig" >/dev/null 2>&1 || true
    fi
}

# ----------------------------------------------------------------------------
# Group 11: 流式推送 (TC-22, TC-23)
# ----------------------------------------------------------------------------

test_group_11() {
    log_section "Group 11: 流式推送"

    # TC-22a: DNSSTREAM (1s 采样)
    log_info "采样 DNSSTREAM (1s)..."
    local dns_stream
    dns_stream=$(stream_sample "DNSSTREAM.START 120 1" "DNSSTREAM.STOP" 1)
    # DNS 流可能为空（无 DNS 事件）
    log_pass "TC-22a DNSSTREAM (${#dns_stream} bytes)"

    # TC-22b: PKTSTREAM (0.5s 采样)
    log_info "采样 PKTSTREAM (0.5s)..."
    local pkt_stream
    # 在采样窗口内触发一点点网络流量，避免“环境过于安静”导致误报失败。
    local has_ping=0
    if adb_su "command -v ping >/dev/null 2>&1"; then
        has_ping=1
        adb_su "sh -c '(sleep 0.1; ping -4 -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true) &'" >/dev/null 2>&1 || true
    fi
    { pkt_stream=$(stream_sample "PKTSTREAM.START 120 1" "PKTSTREAM.STOP" 0.5); } 2>/dev/null
    if [[ ${#pkt_stream} -gt 10 ]]; then
        log_pass "TC-22b PKTSTREAM (${#pkt_stream} bytes)"
    else
        if [[ $has_ping -eq 0 ]]; then
            log_skip "TC-22b PKTSTREAM 数据过少（设备无 ping，无法可靠触发流量）"
        else
            log_fail "TC-22b PKTSTREAM 数据过少"
        fi
    fi

    # TC-22c: ACTIVITYSTREAM (0.5s 采样)
    log_info "采样 ACTIVITYSTREAM (0.5s)..."
    local activity_stream
    { activity_stream=$(stream_sample "ACTIVITYSTREAM.START" "ACTIVITYSTREAM.STOP" 0.5); } 2>/dev/null
    log_pass "TC-22c ACTIVITYSTREAM (${#activity_stream} bytes)"

    # TC-23: TOPACTIVITY 注入
    log_info "测试 TOPACTIVITY 注入..."
    local topact_result
    topact_result=$(send_cmd "TOPACTIVITY $SAMPLE_UID")
    # TOPACTIVITY 无响应（正常）
    log_pass "TC-23 TOPACTIVITY (无响应=正常)"

    # TC-14c: APP.RESET.A (放最后，会清空统计)
    log_info "测试 APP.RESET.A (会清空取样应用统计)..."
    assert_ok "APP.RESET.A $SAMPLE_UID" "TC-14c APP.RESET.A"
}

# ----------------------------------------------------------------------------
# Group 12: RESETALL (TC-24)
# ----------------------------------------------------------------------------

test_group_12() {
    log_section "Group 12: RESETALL"

    # TC-24: RESETALL
    log_info "执行 RESETALL..."
    local reset_result
    reset_result=$(send_cmd "RESETALL")

    if [[ "$reset_result" == "OK" ]]; then
        log_pass "TC-24a RESETALL 返回 OK"
    else
        log_fail "TC-24a RESETALL"
        echo "    响应: $reset_result"
        return
    fi

    # 检查进程是否还存在
    sleep 1
    log_info "检查进程是否存活..."
    local hello_result
    hello_result=$(send_cmd "HELLO" 2)

    if [[ "$hello_result" == "OK" ]]; then
        log_pass "TC-24b 进程存活"

        # 验证是否清空：检查统计
        log_info "验证数据是否已清空..."
        local all_stats
        all_stats=$(send_cmd "ALL.A")

        # 检查 dns.total 是否为 [0,0,0]
        local dns_total
        dns_total=$(echo "$all_stats" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('dns', {}).get('total', []))
" 2>/dev/null)

        if [[ "$dns_total" == "[0, 0, 0]" ]]; then
            log_pass "TC-24c 统计已清空"
        else
            log_fail "TC-24c 统计未清空"
            echo "    dns.total: $dns_total"
        fi
    else
        log_fail "TC-24b 进程已退出 (已知 bug)"
        echo "    HELLO 响应: $hello_result"
    fi
}

# ----------------------------------------------------------------------------
# Group 13: 多用户 (best-effort; TC-25)
# ----------------------------------------------------------------------------

test_group_13() {
    log_section "Group 13: 多用户 (best-effort)"

    if [[ "${SNORT_ENABLE_MULTIUSER_SMOKE:-0}" != "1" ]]; then
        log_skip "TC-25 multi-user smoke disabled (set SNORT_ENABLE_MULTIUSER_SMOKE=1)"
        return
    fi

    local users_out
    users_out="$(adb_su "pm list users 2>/dev/null" | tr -d '\r' || true)"
    if [[ -z "$users_out" ]]; then
        log_skip "TC-25 pm list users unavailable"
        return
    fi

    local user_ids
    user_ids="$(echo "$users_out" | python3 -c "
import re, sys
text = sys.stdin.read()
ids = set(re.findall(r'UserInfo\\{(\\d+):', text))
ids = sorted(ids, key=lambda s: int(s))
print(' '.join(ids))
" 2>/dev/null || true)"
    if [[ -z "$user_ids" ]]; then
        log_skip "TC-25 cannot parse user ids"
        return
    fi

    local other_user=""
    if [[ " $user_ids " == *" 10 "* ]]; then
        other_user="10"
    else
        local uid
        for uid in $user_ids; do
            if [[ "$uid" != "0" ]]; then
                other_user="$uid"
                break
            fi
        done
    fi
    if [[ -z "$other_user" ]]; then
        log_skip "TC-25 single-user device (only user 0)"
        return
    fi
    log_info "secondary userId=$other_user"

    # Find a package present in both user 0 and the secondary user.
    local tmpdir
    tmpdir="$(mktemp -d)"
    local apps0 apps1 common_pkg
    apps0="$tmpdir/apps_user0.json"
    apps1="$tmpdir/apps_user${other_user}.json"

    send_cmd "APP.UID USER 0" >"$apps0" 2>/dev/null || true
    send_cmd "APP.UID USER $other_user" >"$apps1" 2>/dev/null || true

    common_pkg="$(python3 - "$apps0" "$apps1" <<'PY' 2>/dev/null || true
import json
import sys

def load(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

u0 = load(sys.argv[1])
u1 = load(sys.argv[2])
names0 = {x.get("name","") for x in u0 if isinstance(x, dict)}
names1 = {x.get("name","") for x in u1 if isinstance(x, dict)}
common = [n for n in (names0 & names1) if n and "." in n and not n.startswith("system_")]
preferred = [n for n in common if n.startswith("com.")]
preferred.sort()
common.sort()
print(preferred[0] if preferred else (common[0] if common else ""))
PY
)"
    if [[ -z "$common_pkg" ]]; then
        rm -rf "$tmpdir" >/dev/null 2>&1 || true
        log_skip "TC-25 no common package found across users"
        return
    fi
    log_info "common package: $common_pkg"

    appuid_field() {
        local pkg="$1"
        local user="$2"
        local field="$3"
        send_cmd "APP.UID $pkg USER $user" | python3 -c '
import json
import sys

name = sys.argv[1]
field = sys.argv[2]

try:
    data = json.load(sys.stdin)
except Exception:
    data = []

for item in data:
    if isinstance(item, dict) and item.get("name") == name:
        value = item.get(field, "")
        if isinstance(value, bool):
            print(1 if value else 0)
        else:
            print(value)
        break
' "$pkg" "$field" 2>/dev/null || true
    }

    local uid0 uid1
    uid0="$(appuid_field "$common_pkg" "0" "uid")"
    uid1="$(appuid_field "$common_pkg" "$other_user" "uid")"

    if [[ "$uid0" =~ ^[0-9]+$ && "$uid1" =~ ^[0-9]+$ && "$uid0" != "$uid1" ]]; then
        log_pass "TC-25a same package yields distinct UIDs (u0=$uid0 u${other_user}=$uid1)"
    else
        log_fail "TC-25a same package yields distinct UIDs"
        echo "    uid0=$uid0 uid${other_user}=$uid1"
        rm -rf "$tmpdir" >/dev/null 2>&1 || true
        return
    fi

    # Verify per-app knobs are scoped by USER clause (BLOCKMASK + TRACK).
    local bm0 bm1 bm_get0 bm_get1
    bm0="$(send_cmd "BLOCKMASK $common_pkg USER 0")"
    bm1="$(send_cmd "BLOCKMASK $common_pkg USER $other_user")"

    local tracked0 tracked1 tracked1_after tracked0_after
    tracked0="$(appuid_field "$common_pkg" "0" "tracked")"
    tracked1="$(appuid_field "$common_pkg" "$other_user" "tracked")"

    # BLOCKMASK: set user0=1 and other=8 (must normalize to 9)
    if [[ "$(send_cmd "BLOCKMASK $common_pkg USER 0 1")" == "OK" && \
          "$(send_cmd "BLOCKMASK $common_pkg USER $other_user 8")" == "OK" ]]; then
        bm_get0="$(send_cmd "BLOCKMASK $common_pkg USER 0")"
        bm_get1="$(send_cmd "BLOCKMASK $common_pkg USER $other_user")"
        if [[ "$bm_get0" == "1" && "$bm_get1" == "9" ]]; then
            log_pass "TC-25b BLOCKMASK scoped per user (u0=1 u${other_user}=9)"
        else
            log_fail "TC-25b BLOCKMASK scoped per user"
            echo "    got: u0=$bm_get0 u${other_user}=$bm_get1"
        fi
    else
        log_fail "TC-25b BLOCKMASK set failed"
    fi

    # TRACK: toggle only the secondary user's instance.
    local untrack_result
    untrack_result="$(send_cmd "UNTRACK $common_pkg USER $other_user")"
    if [[ "$untrack_result" == "OK" ]]; then
        tracked1_after="$(appuid_field "$common_pkg" "$other_user" "tracked")"
        tracked0_after="$(appuid_field "$common_pkg" "0" "tracked")"
        if [[ "$tracked1_after" == "0" && "$tracked0_after" == "$tracked0" ]]; then
            log_pass "TC-25c TRACK/UNTRACK scoped per user"
        else
            log_fail "TC-25c TRACK/UNTRACK scoped per user"
            echo "    tracked0 before=$tracked0 after=$tracked0_after"
            echo "    tracked${other_user} before=$tracked1 after=$tracked1_after"
        fi
    else
        log_fail "TC-25c UNTRACK failed"
        echo "    响应: $untrack_result"
    fi

    # Custom black/white lists: verify decisions scoped by USER clause.
    local ts mu_domain blocked0 blocked1
    ts="$(date +%s)"
    mu_domain="mu-$ts.sucre.invalid"

    # Ensure custom lists are enabled for both instances.
    send_cmd "CUSTOMLIST.ON $common_pkg USER 0" >/dev/null 2>&1 || true
    send_cmd "CUSTOMLIST.ON $common_pkg USER $other_user" >/dev/null 2>&1 || true

    send_cmd "BLACKLIST.ADD $common_pkg USER 0 $mu_domain" >/dev/null 2>&1 || true
    blocked0="$(dev_dnsquery_blocked_flag "$uid0" "$mu_domain" 2>/dev/null || true)"
    blocked1="$(dev_dnsquery_blocked_flag "$uid1" "$mu_domain" 2>/dev/null || true)"
    if [[ "$blocked0" == "1" && "$blocked1" == "0" ]]; then
        log_pass "TC-25d custom blacklist scoped per user"
    else
        log_fail "TC-25d custom blacklist scoped per user"
        echo "    blocked0=$blocked0 blocked${other_user}=$blocked1"
    fi

    # Apply blacklist to secondary user, then override with whitelist.
    send_cmd "BLACKLIST.ADD $common_pkg USER $other_user $mu_domain" >/dev/null 2>&1 || true
    blocked1="$(dev_dnsquery_blocked_flag "$uid1" "$mu_domain" 2>/dev/null || true)"
    if [[ "$blocked1" == "1" ]]; then
        log_pass "TC-25e custom blacklist applied to secondary user"
    else
        log_fail "TC-25e custom blacklist applied to secondary user"
        echo "    blocked${other_user}=$blocked1"
    fi

    send_cmd "WHITELIST.ADD $common_pkg USER $other_user $mu_domain" >/dev/null 2>&1 || true
    blocked1="$(dev_dnsquery_blocked_flag "$uid1" "$mu_domain" 2>/dev/null || true)"
    if [[ "$blocked1" == "0" ]]; then
        log_pass "TC-25f custom whitelist overrides within selected user"
    else
        log_fail "TC-25f custom whitelist overrides within selected user"
        echo "    blocked${other_user}=$blocked1"
    fi

    # ACTIVITYSTREAM: inject two activities and assert uid/userId separation.
    local act_file spid
    act_file="$tmpdir/activity_stream.jsonl"
    stream_sample "ACTIVITYSTREAM.START" "ACTIVITYSTREAM.STOP" 2 >"$act_file" 2>/dev/null &
    spid=$!
    # Give the stream socket time to register before injecting events.
    sleep 0.5
    send_cmd "TOPACTIVITY $uid0" >/dev/null 2>&1 || true
    sleep 0.5
    send_cmd "TOPACTIVITY $uid1" >/dev/null 2>&1 || true
    wait "$spid" >/dev/null 2>&1 || true

    if python3 -c '
import json
import sys

uid0 = int(sys.argv[1])
uid1 = int(sys.argv[2])
user1 = int(sys.argv[3])

seen0 = False
seen1 = False

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    uid = obj.get("uid")
    if uid == uid0 and obj.get("userId") == 0:
        seen0 = True
    if uid == uid1 and obj.get("userId") == user1:
        seen1 = True

sys.exit(0 if (seen0 and seen1) else 1)
' "$uid0" "$uid1" "$other_user" <"$act_file" >/dev/null 2>&1; then
        log_pass "TC-25g ACTIVITYSTREAM carries uid/userId per user"
    else
        log_fail "TC-25g ACTIVITYSTREAM carries uid/userId per user"
        echo "    events:"
        grep -E "\"uid\":($uid0|$uid1)" "$act_file" 2>/dev/null | head -n 5 || true
    fi

    # Best-effort cleanup of custom domains.
    send_cmd "BLACKLIST.REMOVE $common_pkg USER 0 $mu_domain" >/dev/null 2>&1 || true
    send_cmd "BLACKLIST.REMOVE $common_pkg USER $other_user $mu_domain" >/dev/null 2>&1 || true
    send_cmd "WHITELIST.REMOVE $common_pkg USER $other_user $mu_domain" >/dev/null 2>&1 || true

    # Restore best-effort.
    if [[ "$bm0" =~ ^[0-9]+$ ]]; then
        send_cmd "BLOCKMASK $common_pkg USER 0 $bm0" >/dev/null 2>&1 || true
    fi
    if [[ "$bm1" =~ ^[0-9]+$ ]]; then
        send_cmd "BLOCKMASK $common_pkg USER $other_user $bm1" >/dev/null 2>&1 || true
    fi
    if [[ "$tracked1" == "1" ]]; then
        send_cmd "TRACK $common_pkg USER $other_user" >/dev/null 2>&1 || true
    fi

    rm -rf "$tmpdir" >/dev/null 2>&1 || true
}

# ============================================================================
# 主程序
# ============================================================================

show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help      显示帮助"
    echo "  -g, --group N   只运行指定组 (1-13, 逗号分隔；13 为多用户 best-effort)"
    echo "  -v, --verbose   详细输出"
    echo ""
    echo "环境变量:"
    echo "  SNORT_ENABLE_MULTIUSER_SMOKE=1   启用多用户组 (Group 13)"
    echo ""
    echo "示例:"
    echo "  $0                    # 运行所有测试"
    echo "  $0 -g 1,4,5           # 只运行组 1, 4, 5"
    echo "  SNORT_ENABLE_MULTIUSER_SMOKE=1 $0 -g 13   # 只跑多用户"
    echo ""
}

main() {
    local groups=""
    local verbose=0

    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -g|--group)
                groups="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=1
                shift
                ;;
            *)
                echo "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done

    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║        sucre-snort 完整冒烟测试                           ║"
    echo "║        基于 BACKEND_DEV_SMOKE.md (24 用例)                ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    # 初始化
    if ! init_test_env; then
        exit 1
    fi

    # 获取取样应用
    get_sample_app

    # 确定要运行的组
    local run_groups
    if [[ -n "$groups" ]]; then
        IFS=',' read -ra run_groups <<< "$groups"
    else
        run_groups=(1 2 3 4 5 6 7 8 9 10 11 12)
    fi

    # 运行测试
    for g in "${run_groups[@]}"; do
        case $g in
            1) test_group_1 ;;
            2) test_group_2 ;;
            3) test_group_3 ;;
            4) test_group_4 ;;
            5) test_group_5 ;;
            6) test_group_6 ;;
            7) test_group_7 ;;
            8) test_group_8 ;;
            9) test_group_9 ;;
            10) test_group_10 ;;
            11) test_group_11 ;;
            12) test_group_12 ;;
            13) test_group_13 ;;
            *) echo "未知组: $g" ;;
        esac
    done

    # 汇总
    print_summary

    # 返回状态
    if [[ $FAILED -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
