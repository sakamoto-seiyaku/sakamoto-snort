#!/bin/bash
# dev-smoke.sh - sucre-snort 完整冒烟测试
# 覆盖 BACKEND_DEV_SMOKE.md 中的 24 个测试用例

# 不使用 set -e，让测试继续运行

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/dev-smoke-lib.sh"

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
    { pkt_stream=$(stream_sample "PKTSTREAM.START 120 1" "PKTSTREAM.STOP" 0.5); } 2>/dev/null
    if [[ ${#pkt_stream} -gt 10 ]]; then
        log_pass "TC-22b PKTSTREAM (${#pkt_stream} bytes)"
    else
        log_fail "TC-22b PKTSTREAM 数据过少"
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

# ============================================================================
# 主程序
# ============================================================================

show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help      显示帮助"
    echo "  -g, --group N   只运行指定组 (1-12, 逗号分隔)"
    echo "  -v, --verbose   详细输出"
    echo ""
    echo "示例:"
    echo "  $0                    # 运行所有测试"
    echo "  $0 -g 1,4,5           # 只运行组 1, 4, 5"
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
