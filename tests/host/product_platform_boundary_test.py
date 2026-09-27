#!/usr/bin/env python3
"""Current source-wiring guards, not a replacement for packet/device evidence."""

from pathlib import Path
import re
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
JAVA = "app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/"
VPP = "src/product/vpp/"
# Keep literals but discard comments, so commentary cannot satisfy a guard.
LEXEMES = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S)


def source(path):
    return LEXEMES.sub(
        lambda match: " " if match[0].startswith(("//", "/*")) else match[0],
        (ROOT / path).read_text(),
    )


def body(text, name):
    """Extract a definition, excluding prototypes and braces inside literals."""
    definition = re.search(
        r"^[ \t]*(?:[A-Za-z_]\w*[ \t*]+)*" + re.escape(name)
        + r"\s*\([^;{}]*\)\s*\{", text, re.M,
    )
    if definition is None:
        raise AssertionError(f"missing definition: {name}")
    start = definition.end() - 1
    depth = 0
    for token in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', text[start:]):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                return text[start:start + token.end()]
    raise AssertionError(f"unclosed definition: {name}")


class ProductPlatformBoundaryTest(unittest.TestCase):
    def require(self, text, *tokens):
        for token in tokens:
            with self.subTest(token=token):
                self.assertIn(token, text)

    def ordered(self, text, *tokens):
        self.require(text, *tokens)
        positions = [text.index(token) for token in tokens]
        self.assertEqual(positions, sorted(positions), tokens)

    def test_root_authorization_and_dual_stack_lanes(self):
        service = source(JAVA + "RuntimeService.java")
        start = body(service, "startProductCoreRuntime")
        self.ordered(start, "!rootCommandAvailable()", "builder.start()")
        self.assertNotIn("installProductRootNfqueueHook()", start)
        capture = body(service, "continueProductCoreStartup")
        self.ordered(capture, "awaitInitialPolicy(session, process)",
                     "reconcileProductEmptyPolicy(session", "installProductRootNfqueueHook()",
                     "productCaptureStarted = true", "publishProductCoreRunning(")
        install = body(service, "installProductRootNfqueueHook")
        self.require(
            install,
            "selected != RuntimeProfile.ROOT",
            "Integer.toString(getApplicationInfo().uid)",
            'productRootFamilyHooks("iptables", outputChain, inputChain, uid, "176:177")',
            'productRootFamilyHooks("ip6tables", outputChain, inputChain, uid, "178:179")',
        )
        hooks = body(service, "productRootFamilyHooks")
        self.require(hooks, '"udp", "tcp", icmp', '"echo-request", "echo-reply"',
                     "--uid-owner", "--queue-balance", "--queue-bypass",
                     " -w -t mangle -I OUTPUT -j ", " -w -t mangle -I INPUT -j ")

    def test_root_completion_consumes_exact_origin_once(self):
        complete = body(source(VPP + "product_root_nfqueue_adapter.c"),
                        "product_root_nfqueue_complete_from_graph")
        self.require(
            complete,
            "obligation->queue_generation != nm->generation",
            "obligation->origin_lane",
            "obligation->origin_worker != lane->worker_index",
            "vm->thread_index != vlib_get_worker_thread_index (lane->worker_index)",
            "pending->completion.obligation.token != obligation->token",
            "pending->completion.obligation.packet_id != packet_id",
            "if (!pending->active)",
            "pending->buffer_index != buffer_index",
            "PRODUCT_COMPLETION_REPLAY_PROBE",
        )
        self.ordered(complete, "pending->active = 0;",
                     "product_nfqueue_send_verdict (lane->fd, lane->queue_id, packet_id",
                     "product_root_nfqueue_return_receive (")
        self.assertEqual(complete.count("product_nfqueue_send_verdict ("), 1)

    def test_root_facts_do_not_invent_uid_or_wifi(self):
        receive = body(source(VPP + "product_root_nfqueue_adapter.c"),
                       "product_root_nfqueue_read_ready")
        self.require(
            receive, "product_network_snapshot_current ()",
            "clib_memset (&platform, 0, sizeof (platform))",
            "packet.uid_present ? PRODUCT_PLATFORM_UID_KNOWN : 0",
            "packet.hook == NF_INET_LOCAL_OUT && packet.outdev_present",
            "packet.hook == NF_INET_LOCAL_IN && packet.indev_present",
            "PRODUCT_PLATFORM_IFINDEX_KNOWN", "network->entries[i].context",
        )
        self.assertNotIn("PRODUCT_ROOT_NFQUEUE_NETWORK_CONTEXT_WIFI", receive)
        self.assertNotRegex(receive, r"platform\.network_context_id\s*=\s*(?:1|SAKAMOTO_PRODUCT_NETWORK_WIFI)\s*;")

    def test_network_publication_is_generation_bound_and_whole(self):
        network = source(VPP + "product_network_snapshot.c")
        publish = body(network, "publish_snapshot")
        self.require(
            publish, "vm->thread_index != 0", "generation != network_generation",
            "snapshot->revision <= product_network_snapshot.revision",
            "snapshot->count > SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES",
            "if (iface || context) return 0",
            "snapshot->entries[j].linux_ifindex == iface",
        )
        self.ordered(publish, "vlib_worker_thread_barrier_sync (vm)",
                     "product_network_snapshot = *snapshot",
                     "vlib_worker_thread_barrier_release (vm)")
        self.require(body(network, "product_network_snapshot_publish"), "if (linux_owned) return 0")
        self.require(body(network, "product_network_snapshot_context"), "if (!interface_index) return 0", "return 0")
        self.require(body(network, "product_network_snapshot_stop"),
                     "network_generation = 0", "clib_memset (&product_network_snapshot, 0")

    def test_vpn_product_readiness_requires_native_handoff(self):
        service = source(JAVA + "RuntimeService.java")
        start = body(service, "startProductCoreRuntime")
        self.ordered(start, "!adapter.productLaunchAllowed && !vpnGraphValidation",
                     "builder.start()")
        self.require(start, 'builder.environment().put("SAKAMOTO_PRODUCT_VPN_PRODUCT", "1")',
                     'builder.environment().put("SAKAMOTO_PRODUCT_VPN_HEV", "1")')
        self.assertNotIn("establishPacketAdapterSession(adapter, vpnDnsServers)", start)
        capture = body(service, "continueProductCoreStartup")
        self.ordered(capture, "awaitInitialPolicy(session, process)",
                     "reconcileProductEmptyPolicy(session",
                     "establishPacketAdapterSession(adapter, vpnDnsServers)", "NativeTunFdClient.attach(")
        self.require(capture, "properties.getDnsServers()", '"vpn_dns_unavailable"',
                     "vpnDnsServers = servers.toArray(new InetAddress[0])")
        self.require(capture, "vpnTunSession.releaseFd(), getApplicationInfo().uid",
                     "NativeTunFdClient.attachUnknownIdentity",
                     "status.adapterAvailable != vpnProductFlowStack",
                     "status.protectionRunning != vpnProductFlowStack",
                     'throw new IOException("TUN graph handoff/readiness mismatch")')
        plugin = source(VPP + "product_core_plugin.c")
        self.require(body(plugin, "product_core_adapter_available"),
                     "product_vpn_tun_product_ready ()")
        self.require(body(plugin, "product_core_protection_running"),
                     "product_vpn_tun_product_ready ()")
        ready = body(source(VPP + "product_vpn_tun_adapter.c"),
                     "product_vpn_tun_product_ready")
        self.require(ready, "product_vpn_tun_product_mode ()", "tun.tun_fd >= 0",
                     "product_vpn_uid_resolver_ready ()",
                     "product_vpn_flow_stack_driver_ready ()",
                     "product_packet_graph_accepting ()")
        platform = source(JAVA + "VpnTunPlatformSession.java")
        self.assertRegex(platform, r"if \(graphValidation\)\s*\{\s*builder\.addAllowedApplication\(service\.getPackageName\(\)\);")
        self.assertIn("builder.addDnsServer(server)", platform)
        tun = body(source(VPP + "product_vpn_tun_adapter.c"), "tun_read_ready")
        self.require(tun, ".availability = tun.test_uid_known ? PRODUCT_PLATFORM_UID_KNOWN : 0",
                     ".direction = PRODUCT_PACKET_DIRECTION_OUTPUT",
                     ".provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN",
                     "product_network_snapshot_context (tun.snapshot_interface)")
        self.assertNotIn("PRODUCT_PLATFORM_IFINDEX_KNOWN", tun)
        self.assertFalse((ROOT / VPP / "product_vpn_udp4_adapter.c").exists())

    def test_definition_reader_ignores_prototypes_and_quoted_braces(self):
        self.assertEqual(body('void sample(int);\nif (!sample(1)) { fail(); }\n'
                              'void sample(int n) { log("}"); }',
                              "sample"), '{ log("}"); }')
        with self.assertRaises(AssertionError):
            body("void sample(int);", "sample")

    def test_negative_witnesses_reject_boundary_regressions(self):
        # Mutate reads in memory only; Product sources and frozen evidence stay intact.
        cases = (
            ("test_root_completion_consumes_exact_origin_once",
             "obligation->queue_generation != nm->generation", "0"),
            ("test_root_completion_consumes_exact_origin_once",
             "obligation->origin_worker != lane->worker_index", "0"),
            ("test_root_completion_consumes_exact_origin_once",
             "pending->active = 0;", "pending->active = 1;"),
            ("test_root_facts_do_not_invent_uid_or_wifi",
             "packet.uid_present ? PRODUCT_PLATFORM_UID_KNOWN : 0", "PRODUCT_PLATFORM_UID_KNOWN"),
            ("test_network_publication_is_generation_bound_and_whole",
             "generation != network_generation", "0"),
            ("test_network_publication_is_generation_bound_and_whole",
             "snapshot->revision <= product_network_snapshot.revision", "0"),
            ("test_vpn_product_readiness_requires_native_handoff",
             "!adapter.productLaunchAllowed && !vpnGraphValidation", "false"),
        )
        original_source = source
        for method, old, new in cases:
            changed = []

            def mutated_source(path):
                text = original_source(path)
                if old in text:
                    changed.append(path)
                return text.replace(old, new)

            with self.subTest(method=method, mutation=old):
                result = unittest.TestResult()
                with patch(__name__ + ".source", side_effect=mutated_source):
                    ProductPlatformBoundaryTest(method).run(result)
                self.assertTrue(changed, "negative witness did not reach source")
                self.assertFalse(result.wasSuccessful(), "boundary regression was accepted")


if __name__ == "__main__":
    unittest.main()
