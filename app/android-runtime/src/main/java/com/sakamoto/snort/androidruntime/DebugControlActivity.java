package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.net.ConnectivityManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.UserHandle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.net.InetSocketAddress;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Minimal debug shell. It only issues versioned requests and renders snapshots. */
public class DebugControlActivity extends Activity {
    private static final int NOTIFICATION_PERMISSION = 1001;
    private static final int VPN_PREPARE_REQUEST = 1002;
    private static final long STATUS_POLL_MILLIS = 500L;
    private static final String EXTRA_RUNTIME_START = "runtimeStart";
    private static final String EXTRA_RUNTIME_STOP = "runtimeStop";
    private static final String EXTRA_RUNTIME_PAUSE = "runtimePause";
    private static final String EXTRA_RUNTIME_RESUME = "runtimeResume";
    private static final String EXTRA_RUNTIME_PROFILE = "runtimeProfile";
    private static final String EXTRA_RUNTIME_CLEANUP_FAULT = "runtimeCleanupFault";
    private static final String EXTRA_RUNTIME_ROOT_NFQUEUE_FAULT_MODE =
            "runtimeRootNfqueueFaultMode";
    private static final String EXTRA_RUNTIME_VPN_FAULT_MODE =
            "runtimeVpnFaultMode";
    private static final String EXTRA_RUNTIME_VPN_FAULT_EVENT =
            "runtimeVpnFaultEvent";
    private static final String EXTRA_RUNTIME_POLICY_MUTATION_FAULT_MODE =
            "runtimePolicyMutationFaultMode";
    private static final String EXTRA_DEBUG_REFRESH = "debugRefresh";
    private static final String EXTRA_DEBUG_TRAFFIC = "debugTraffic";
    private static final String EXTRA_DEBUG_TRAFFIC_HOST = "debugTrafficHost";
    private static final String EXTRA_DEBUG_TRAFFIC_PORT = "debugTrafficPort";
    private static final String EXTRA_DEBUG_TRAFFIC_SOURCE_PORT = "debugTrafficSourcePort";
    private static final String EXTRA_DEBUG_TRAFFIC_NONCE = "debugTrafficNonce";
    private static final String EXTRA_DEBUG_TRAFFIC_TIMEOUT_MILLIS =
            "debugTrafficTimeoutMillis";
    // Evidence-only escape hatch; ordinary probes keep the platform default route.
    private static final String EXTRA_DEBUG_TRAFFIC_BIND_TO_VPN = "debugTrafficBindToVpn";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC = "debugUdpTraffic";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC_HOST = "debugUdpHost";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC_PORT = "debugUdpPort";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC_SOURCE_PORT =
            "debugUdpSourcePort";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC_NONCE = "debugUdpNonce";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC_EXPECT_REPLY =
            "debugUdpExpectReply";
    private static final String EXTRA_DEBUG_UDP_TRAFFIC_TIMEOUT_MILLIS =
            "debugUdpTimeoutMillis";
    private static final String EXTRA_DEBUG_DOWNLOAD = "debugDownload";
    private static final String EXTRA_DEBUG_DOWNLOAD_URL = "debugDownloadUrl";
    private static final String EXTRA_DEBUG_DOWNLOAD_TIMEOUT_MILLIS =
            "debugDownloadTimeoutMillis";
    private static final String EXTRA_DEBUG_DOWNLOAD_MAX_BYTES = "debugDownloadMaxBytes";
    private static final String EXTRA_DEBUG_APPLY_GATE_AND_PROBE = "debugApplyGateAndProbe";
    private static final String EXTRA_DEBUG_APPLY_EMPTY_POLICY = "debugApplyEmptyPolicy";
    private static final String EXTRA_DEBUG_L4_PREFILL_FROM_ACTIVITY =
            "debugL4PrefillFromActivity";
    private static final String EXTRA_DEBUG_EXPORT_RELEASE_DIAGNOSTICS =
            "debugExportReleaseDiagnostics";
    private static final String EXTRA_DEBUG_LISTEN = "debugListen";
    private static final String EXTRA_DEBUG_LISTEN_HOST = "debugListenHost";
    private static final String EXTRA_DEBUG_LISTEN_PORT = "debugListenPort";
    private static final String EXTRA_DEBUG_LISTEN_NONCE = "debugListenNonce";
    private static final String EXTRA_DEBUG_LISTEN_TIMEOUT_MILLIS =
            "debugListenTimeoutMillis";
    private static final String EXTRA_DEBUG_UDP_LISTEN = "debugUdpListen";
    private static final String EXTRA_DEBUG_UDP_LISTEN_HOST = "debugUdpListenHost";
    private static final String EXTRA_DEBUG_UDP_LISTEN_PORT = "debugUdpListenPort";
    private static final String EXTRA_DEBUG_UDP_LISTEN_NONCE = "debugUdpListenNonce";
    private static final String EXTRA_DEBUG_UDP_LISTEN_TIMEOUT_MILLIS =
            "debugUdpListenTimeoutMillis";
    private static final String EXTRA_DEBUG_BIND_APPLICATION_SUBJECT =
            "debugBindApplicationSubject";
    private static final String EXTRA_DEBUG_UNBIND_APPLICATION_SUBJECT =
            "debugUnbindApplicationSubject";
    private static final String EXTRA_DEBUG_SET_NETWORK_GATE_SUBJECT =
            "debugSetNetworkGateSubject";
    private static final String EXTRA_DEBUG_SET_NETWORK_GATE_CONTEXT =
            "debugSetNetworkGateContext";
    private static final String EXTRA_DEBUG_SET_NETWORK_GATE_BLOCKED =
            "debugSetNetworkGateBlocked";
    private static final String EXTRA_DEBUG_SET_L4_RULE_SUBJECT =
            "debugSetL4RuleSubject";
    private static final String EXTRA_DEBUG_SET_L4_RULE_FAMILY =
            "debugSetL4RuleFamily";
    private static final String EXTRA_DEBUG_SET_L4_RULE_SOURCE_CIDR =
            "debugSetL4RuleSourceCidr";
    private static final String EXTRA_DEBUG_SET_L4_RULE_DESTINATION_CIDR =
            "debugSetL4RuleDestinationCidr";
    private static final String EXTRA_DEBUG_SET_L4_RULE_SOURCE_PORT_FIRST =
            "debugSetL4RuleSourcePortFirst";
    private static final String EXTRA_DEBUG_SET_L4_RULE_SOURCE_PORT_LAST =
            "debugSetL4RuleSourcePortLast";
    private static final String EXTRA_DEBUG_SET_L4_RULE_DESTINATION_PORT_FIRST =
            "debugSetL4RuleDestinationPortFirst";
    private static final String EXTRA_DEBUG_SET_L4_RULE_DESTINATION_PORT_LAST =
            "debugSetL4RuleDestinationPortLast";
    private static final String EXTRA_DEBUG_SET_L4_RULE_IP_PROTOCOL =
            "debugSetL4RuleIpProtocol";
    private static final String EXTRA_DEBUG_SET_L4_RULE_DIRECTION =
            "debugSetL4RuleDirection";
    private static final String EXTRA_DEBUG_SET_L4_RULE_NETWORK_CONTEXT =
            "debugSetL4RuleNetworkContext";
    private static final String EXTRA_DEBUG_SET_L4_RULE_ACTION =
            "debugSetL4RuleAction";
    private static final String EXTRA_DEBUG_SET_L4_RULE_PRIORITY =
            "debugSetL4RulePriority";
    private static final String EXTRA_DEBUG_SET_L4_RULE_ORDER =
            "debugSetL4RuleOrder";
    private static final String DEBUG_TRAFFIC_PROBE_RESULT_PATH =
            "debug/traffic-probe.properties";
    private static final String DEBUG_UDP_TRAFFIC_PROBE_RESULT_PATH =
            "debug/udp-traffic-probe.properties";
    private static final String DEBUG_TCP_LISTENER_RESULT_PATH =
            "debug/tcp-listener.properties";
    private static final String DEBUG_UDP_LISTENER_RESULT_PATH =
            "debug/udp-listener.properties";
    private static final String DEBUG_DOWNLOAD_PROBE_RESULT_PATH =
            "debug/download-probe.properties";
    private static final String DEBUG_L4_PREFILL_RESULT_PATH =
            "debug/l4-prefill.properties";
    private static final String DEBUG_RELEASE_DIAGNOSTICS_RESULT_PATH =
            "debug/release-diagnostics.properties";
    private static final String DEBUG_TRAFFIC_HOST = "1.1.1.1";
    private static final int DEBUG_TRAFFIC_PORT = 80;
    private static final int DEBUG_TRAFFIC_TIMEOUT_MILLIS = 1000;
    private static final String DEBUG_UDP_TRAFFIC_HOST = "2606:4700:4700::1111";
    private static final int DEBUG_UDP_TRAFFIC_PORT = 53;
    private static final int DEBUG_UDP_TRAFFIC_TIMEOUT_MILLIS = 1200;
    private static final String DEBUG_DOWNLOAD_URL =
            "https://speed.cloudflare.com/__down?bytes=500000";
    private static final int DEBUG_DOWNLOAD_TIMEOUT_MILLIS = 20000;
    private static final int DEBUG_DOWNLOAD_MAX_BYTES = 500000;
    private static final int DEBUG_LISTEN_PORT = 18080;
    private static final int DEBUG_LISTEN_TIMEOUT_MILLIS = 5000;
    private static final String CONTROL_SOCKET_NAME = "sucre-snort-control-vnext";
    private static final int CONTROL_SOCKET_TIMEOUT_MILLIS = 2000;
    private static final int CONTROL_MAX_PAYLOAD_BYTES = 65536;
    private static final long DEBUG_POLICY_REVISION = 68L;
    private static final long DEBUG_POLICY_RULE_ID = 6801L;
    private static final int DEBUG_POLICY_REASON_ID = 6801;
    private static final int DEBUG_POLICY_NETWORK_CONTEXT = 0;

    private final RuntimeControlBackend backend = new RuntimeControlBackend();
    private final Handler main = new Handler(Looper.getMainLooper());
    private Spinner profileSpinner;
    private TextView statusView;
    private TextView actionView;
    private TextView productView;
    private Spinner appSpinner;
    private ImageView selectedAppIcon;
    private Button bindSelectedButton;
    private Button unbindSelectedButton;
    private Button wifiGateButton;
    private Button mobileGateButton;
    private Button vpnGateButton;
    private boolean suppressAppSelection;
    private ApplicationSubjectId selectedApplicationSubjectId;
    private boolean pendingStart;
    private boolean pendingVpnStart;
    private boolean suppressProfileSelectionPersist;
    private int productCatalogGeneration;
    private ProductCatalogFormatter.Projection productProjection =
            ProductCatalogFormatter.loading(ProductStateSnapshot.empty());
    /** Keeps an explicit user selection visible until the service publishes it. */
    private RuntimeProfile requestedProfile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (applyHeadlessControlIntent(getIntent())) {
            finish();
            return;
        }
        setContentView(buildUi());
        refreshProductCatalog();
        refreshStatus();
        applyControlIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (applyHeadlessControlIntent(intent)) {
            finish();
            return;
        }
        applyControlIntent(intent);
    }

    private boolean applyHeadlessControlIntent(Intent intent) {
        if (intent == null || hasInteractiveDebugExtras(intent)) {
            return false;
        }
        boolean handled = false;
        if (intent.hasExtra("debugNetworkSnapshotMissing")) {
            backend.setNetworkSnapshotMissing(this,
                    intent.getBooleanExtra("debugNetworkSnapshotMissing", false));
            handled = true;
        }
        if (intent.hasExtra(EXTRA_RUNTIME_CLEANUP_FAULT)) {
            backend.setCleanupFault(this,
                    intent.getBooleanExtra(EXTRA_RUNTIME_CLEANUP_FAULT, false));
            handled = true;
        }
        String rootNfqueueFaultMode = null;
        if (intent.hasExtra(EXTRA_RUNTIME_ROOT_NFQUEUE_FAULT_MODE)) {
            rootNfqueueFaultMode =
                    intent.getStringExtra(EXTRA_RUNTIME_ROOT_NFQUEUE_FAULT_MODE);
            backend.setRootNfqueueFaultMode(this, rootNfqueueFaultMode);
            handled = true;
        }
        String vpnFaultMode = null;
        if (intent.hasExtra(EXTRA_RUNTIME_VPN_FAULT_MODE)) {
            vpnFaultMode = intent.getStringExtra(EXTRA_RUNTIME_VPN_FAULT_MODE);
            backend.setVpnFaultMode(this, vpnFaultMode);
            handled = true;
        }
        if (intent.hasExtra(EXTRA_RUNTIME_VPN_FAULT_EVENT)) {
            backend.sendVpnFaultEvent(this,
                    intent.getStringExtra(EXTRA_RUNTIME_VPN_FAULT_EVENT));
            handled = true;
        }
        if (intent.hasExtra(EXTRA_RUNTIME_POLICY_MUTATION_FAULT_MODE)) {
            backend.setPolicyMutationFaultMode(this,
                    intent.getStringExtra(EXTRA_RUNTIME_POLICY_MUTATION_FAULT_MODE));
            handled = true;
        }
        if (intent.getBooleanExtra(EXTRA_RUNTIME_PAUSE, false)) {
            backend.pauseProtection(this);
            handled = true;
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_RESUME, false)) {
            backend.resumeProtection(this);
            handled = true;
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_STOP, false)) {
            backend.stop(this);
            handled = true;
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_START, false)) {
            String profile = intent.getStringExtra(EXTRA_RUNTIME_PROFILE);
            RuntimeProfile selected = RuntimeProfile.VPN.wireName.equalsIgnoreCase(profile)
                    ? RuntimeProfile.VPN : RuntimeProfile.ROOT;
            backend.start(this, selected, rootNfqueueFaultMode, vpnFaultMode);
            handled = true;
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_REFRESH, false)) {
            backend.queryService(this);
            handled = true;
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_APPLY_EMPTY_POLICY, false)) {
            backend.applyEmptyPolicy(this);
            handled = true;
        }
        return handled;
    }

    private boolean hasInteractiveDebugExtras(Intent intent) {
        return intent.getBooleanExtra(EXTRA_DEBUG_TRAFFIC, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_UDP_TRAFFIC, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_DOWNLOAD, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_APPLY_GATE_AND_PROBE, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_L4_PREFILL_FROM_ACTIVITY, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_EXPORT_RELEASE_DIAGNOSTICS, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_LISTEN, false)
                || intent.getBooleanExtra(EXTRA_DEBUG_UDP_LISTEN, false)
                || intent.getStringExtra(EXTRA_DEBUG_BIND_APPLICATION_SUBJECT) != null
                || intent.getStringExtra(EXTRA_DEBUG_UNBIND_APPLICATION_SUBJECT) != null
                || intent.getStringExtra(EXTRA_DEBUG_SET_NETWORK_GATE_SUBJECT) != null
                || intent.getStringExtra(EXTRA_DEBUG_SET_L4_RULE_SUBJECT) != null;
    }

    private void applyControlIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.hasExtra(EXTRA_RUNTIME_CLEANUP_FAULT)) {
            backend.setCleanupFault(this,
                    intent.getBooleanExtra(EXTRA_RUNTIME_CLEANUP_FAULT, false));
        }
        String rootNfqueueFaultMode = null;
        if (intent.hasExtra(EXTRA_RUNTIME_ROOT_NFQUEUE_FAULT_MODE)) {
            rootNfqueueFaultMode =
                    intent.getStringExtra(EXTRA_RUNTIME_ROOT_NFQUEUE_FAULT_MODE);
            backend.setRootNfqueueFaultMode(this, rootNfqueueFaultMode);
        }
        String vpnFaultMode = null;
        if (intent.hasExtra(EXTRA_RUNTIME_VPN_FAULT_MODE)) {
            vpnFaultMode = intent.getStringExtra(EXTRA_RUNTIME_VPN_FAULT_MODE);
            backend.setVpnFaultMode(this, vpnFaultMode);
        }
        if (intent.hasExtra(EXTRA_RUNTIME_VPN_FAULT_EVENT)) {
            backend.sendVpnFaultEvent(this,
                    intent.getStringExtra(EXTRA_RUNTIME_VPN_FAULT_EVENT));
        }
        if (intent.hasExtra(EXTRA_RUNTIME_POLICY_MUTATION_FAULT_MODE)) {
            backend.setPolicyMutationFaultMode(this,
                    intent.getStringExtra(EXTRA_RUNTIME_POLICY_MUTATION_FAULT_MODE));
        }
        if (intent.getBooleanExtra(EXTRA_RUNTIME_PAUSE, false)) {
            main.post(this::pauseProtection);
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_RESUME, false)) {
            main.post(this::resumeProtection);
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_STOP, false)) {
            main.post(this::stopRuntime);
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_START, false)) {
            String profile = intent.getStringExtra(EXTRA_RUNTIME_PROFILE);
            RuntimeProfile selected = profileFromSpinner();
            if (profileSpinner != null && profile != null) {
                selected = RuntimeProfile.VPN.wireName.equalsIgnoreCase(profile)
                        ? RuntimeProfile.VPN : RuntimeProfile.ROOT;
                requestedProfile = selected;
                setProfileSpinnerSelection(selected);
            }
            final String requestedRootNfqueueFaultMode = rootNfqueueFaultMode;
            final String requestedVpnFaultMode = vpnFaultMode;
            final RuntimeProfile requestedRuntimeProfile = selected;
            startProfile(requestedRuntimeProfile, requestedRootNfqueueFaultMode,
                    requestedVpnFaultMode, false);
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_REFRESH, false)) {
            main.post(() -> {
                refreshStatus();
                refreshProductCatalog();
            });
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_APPLY_EMPTY_POLICY, false)) {
            main.post(() -> {
                backend.applyEmptyPolicy(this);
                action("Debug empty policy apply requested.");
                refreshStatus();
            });
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_TRAFFIC, false)) {
            String host = intent.getStringExtra(EXTRA_DEBUG_TRAFFIC_HOST);
            if (host == null || host.isEmpty()) {
                host = DEBUG_TRAFFIC_HOST;
            }
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_TRAFFIC_PORT, DEBUG_TRAFFIC_PORT), DEBUG_TRAFFIC_PORT);
            int sourcePort = boundedOptionalPort(intent.getIntExtra(
                    EXTRA_DEBUG_TRAFFIC_SOURCE_PORT, 0));
            String nonce = boundedNonce(intent.getStringExtra(EXTRA_DEBUG_TRAFFIC_NONCE));
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_TRAFFIC_TIMEOUT_MILLIS, DEBUG_TRAFFIC_TIMEOUT_MILLIS),
                    DEBUG_TRAFFIC_TIMEOUT_MILLIS);
            boolean bindToVpn = intent.getBooleanExtra(EXTRA_DEBUG_TRAFFIC_BIND_TO_VPN, false);
            final String probeHost = host;
            final int probePort = port;
            final int probeSourcePort = sourcePort;
            final String probeNonce = nonce;
            final int probeTimeoutMillis = timeoutMillis;
            final boolean probeBindToVpn = bindToVpn;
            main.post(() -> runDebugTrafficProbe(
                    probeHost, probePort, probeSourcePort, probeTimeoutMillis, probeNonce,
                    probeBindToVpn));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_UDP_TRAFFIC, false)) {
            String host = intent.getStringExtra(EXTRA_DEBUG_UDP_TRAFFIC_HOST);
            if (host == null || host.isEmpty()) {
                host = DEBUG_UDP_TRAFFIC_HOST;
            }
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_UDP_TRAFFIC_PORT, DEBUG_UDP_TRAFFIC_PORT),
                    DEBUG_UDP_TRAFFIC_PORT);
            int sourcePort = boundedOptionalPort(intent.getIntExtra(
                    EXTRA_DEBUG_UDP_TRAFFIC_SOURCE_PORT, 0));
            String nonce = boundedNonce(intent.getStringExtra(EXTRA_DEBUG_UDP_TRAFFIC_NONCE));
            boolean expectReply = intent.getBooleanExtra(
                    EXTRA_DEBUG_UDP_TRAFFIC_EXPECT_REPLY, !nonce.isEmpty());
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_UDP_TRAFFIC_TIMEOUT_MILLIS, DEBUG_UDP_TRAFFIC_TIMEOUT_MILLIS),
                    DEBUG_UDP_TRAFFIC_TIMEOUT_MILLIS);
            // UDP evidence probes are VPN-bound by default.  The explicit
            // shared extra still lets a runner record a deliberate unbound
            // debug comparison without changing the production path.
            boolean bindToVpn = intent.getBooleanExtra(EXTRA_DEBUG_TRAFFIC_BIND_TO_VPN, true);
            final String probeHost = host;
            final int probePort = port;
            final int probeSourcePort = sourcePort;
            final String probeNonce = nonce;
            final boolean probeExpectReply = expectReply;
            final int probeTimeoutMillis = timeoutMillis;
            final boolean probeBindToVpn = bindToVpn;
            main.post(() -> runDebugUdpTrafficProbe(
                    probeHost, probePort, probeSourcePort, probeTimeoutMillis,
                    probeNonce, probeExpectReply,
                    probeBindToVpn));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_DOWNLOAD, false)) {
            String url = intent.getStringExtra(EXTRA_DEBUG_DOWNLOAD_URL);
            if (url == null || url.isEmpty()) {
                url = DEBUG_DOWNLOAD_URL;
            }
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_DOWNLOAD_TIMEOUT_MILLIS, DEBUG_DOWNLOAD_TIMEOUT_MILLIS),
                    DEBUG_DOWNLOAD_TIMEOUT_MILLIS);
            int maxBytes = boundedDownloadBytes(intent.getIntExtra(
                    EXTRA_DEBUG_DOWNLOAD_MAX_BYTES, DEBUG_DOWNLOAD_MAX_BYTES));
            final String downloadUrl = url;
            final int downloadTimeoutMillis = timeoutMillis;
            final int downloadMaxBytes = maxBytes;
            main.post(() -> runDebugDownloadProbe(
                    downloadUrl, downloadTimeoutMillis, downloadMaxBytes));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_LISTEN, false)) {
            String host = intent.getStringExtra(EXTRA_DEBUG_LISTEN_HOST);
            if (host == null || host.isEmpty()) {
                host = "0.0.0.0";
            }
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_LISTEN_PORT, DEBUG_LISTEN_PORT), DEBUG_LISTEN_PORT);
            String nonce = boundedNonce(intent.getStringExtra(EXTRA_DEBUG_LISTEN_NONCE));
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_LISTEN_TIMEOUT_MILLIS, DEBUG_LISTEN_TIMEOUT_MILLIS),
                    DEBUG_LISTEN_TIMEOUT_MILLIS);
            final String listenHost = host;
            final String listenNonce = nonce;
            main.post(() -> runDebugTrafficListener(
                    listenHost, port, timeoutMillis, listenNonce));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_UDP_LISTEN, false)) {
            String host = intent.getStringExtra(EXTRA_DEBUG_UDP_LISTEN_HOST);
            if (host == null || host.isEmpty()) {
                host = "0.0.0.0";
            }
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_UDP_LISTEN_PORT, DEBUG_LISTEN_PORT), DEBUG_LISTEN_PORT);
            String nonce = boundedNonce(intent.getStringExtra(EXTRA_DEBUG_UDP_LISTEN_NONCE));
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_UDP_LISTEN_TIMEOUT_MILLIS, DEBUG_LISTEN_TIMEOUT_MILLIS),
                    DEBUG_LISTEN_TIMEOUT_MILLIS);
            final String listenHost = host;
            final String listenNonce = nonce;
            main.post(() -> runDebugUdpTrafficListener(
                    listenHost, port, timeoutMillis, listenNonce));
        }
        String bindSubject = intent.getStringExtra(EXTRA_DEBUG_BIND_APPLICATION_SUBJECT);
        if (bindSubject != null && !bindSubject.trim().isEmpty()) {
            main.post(() -> requestDebugProductBinding(bindSubject, true));
        }
        String unbindSubject = intent.getStringExtra(EXTRA_DEBUG_UNBIND_APPLICATION_SUBJECT);
        if (unbindSubject != null && !unbindSubject.trim().isEmpty()) {
            main.post(() -> requestDebugProductBinding(unbindSubject, false));
        }
        String gateSubject = intent.getStringExtra(EXTRA_DEBUG_SET_NETWORK_GATE_SUBJECT);
        if (gateSubject != null && !gateSubject.trim().isEmpty()) {
            String context = intent.getStringExtra(EXTRA_DEBUG_SET_NETWORK_GATE_CONTEXT);
            boolean blocked = intent.getBooleanExtra(
                    EXTRA_DEBUG_SET_NETWORK_GATE_BLOCKED, true);
            main.post(() -> requestDebugNetworkGate(gateSubject, context, blocked));
        }
        String l4Subject = intent.getStringExtra(EXTRA_DEBUG_SET_L4_RULE_SUBJECT);
        if (l4Subject != null && !l4Subject.trim().isEmpty()) {
            main.post(() -> requestDebugL4Rule(intent, l4Subject));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_APPLY_GATE_AND_PROBE, false)) {
            main.post(this::runDebugApplyGateAndProbe);
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_L4_PREFILL_FROM_ACTIVITY, false)) {
            String host = intent.getStringExtra(EXTRA_DEBUG_TRAFFIC_HOST);
            if (host == null || host.isEmpty()) {
                host = DEBUG_TRAFFIC_HOST;
            }
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_TRAFFIC_PORT, DEBUG_TRAFFIC_PORT), DEBUG_TRAFFIC_PORT);
            final String prefillHost = host;
            final int prefillPort = port;
            main.post(() -> runDebugL4PrefillFromActivity(prefillHost, prefillPort));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_EXPORT_RELEASE_DIAGNOSTICS, false)) {
            main.post(this::exportReleaseDiagnostics);
        }
    }

    private View buildUi() {
        ScrollView scroller = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(16);
        root.setPadding(padding, padding, padding, padding);
        scroller.addView(root);

        TextView title = new TextView(this);
        title.setText("Sakamoto Debug Control");
        title.setTextSize(20);
        root.addView(title, fillWrap());

        profileSpinner = new Spinner(this);
        profileSpinner.setAdapter(new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_dropdown_item,
                new String[]{RuntimeProfile.ROOT.displayName, RuntimeProfile.VPN.displayName}));
        setProfileSpinnerSelection(ProductCatalogProjectionStore.read(getFilesDir()).selectedProfile);
        profileSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (suppressProfileSelectionPersist) {
                    return;
                }
                requestSelectedProductProfile(profileFromSpinner(), "Product profile selected");
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
        root.addView(profileSpinner, fillWrap());

        LinearLayout buttons = new LinearLayout(this);
        Button start = new Button(this);
        start.setText("Start");
        start.setAllCaps(false);
        start.setOnClickListener(view -> startSelected());
        buttons.addView(start, weighted());
        Button stop = new Button(this);
        stop.setText("Stop");
        stop.setAllCaps(false);
        stop.setOnClickListener(view -> stopRuntime());
        buttons.addView(stop, weighted());
        Button query = new Button(this);
        query.setText("Refresh");
        query.setAllCaps(false);
        query.setOnClickListener(view -> {
            refreshStatus();
            refreshProductCatalog();
        });
        buttons.addView(query, weighted());
        Button traffic = new Button(this);
        traffic.setText("Debug traffic");
        traffic.setAllCaps(false);
        traffic.setOnClickListener(view -> runDebugTrafficProbe());
        buttons.addView(traffic, weighted());
        Button gateProbe = new Button(this);
        gateProbe.setText("Gate+probe");
        gateProbe.setAllCaps(false);
        gateProbe.setOnClickListener(view -> runDebugApplyGateAndProbe());
        buttons.addView(gateProbe, weighted());
        root.addView(buttons, fillWrap());

        LinearLayout appSelector = new LinearLayout(this);
        appSelector.setOrientation(LinearLayout.HORIZONTAL);
        selectedAppIcon = new ImageView(this);
        int iconSize = dp(48);
        appSelector.addView(selectedAppIcon, new LinearLayout.LayoutParams(iconSize, iconSize));
        appSpinner = new Spinner(this);
        appSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (suppressAppSelection) {
                    return;
                }
                ProductCatalogFormatter.EntryRow row = selectedApplicationRow();
                selectedApplicationSubjectId = row == null ? null : row.subjectId;
                renderSelectedApplicationIcon(row);
                updateSelectedApplicationButtons(row);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                selectedApplicationSubjectId = null;
                renderSelectedApplicationIcon(null);
                updateSelectedApplicationButtons(null);
            }
        });
        appSelector.addView(appSpinner, weighted());
        root.addView(appSelector, fillWrap());

        LinearLayout productButtons = new LinearLayout(this);
        bindSelectedButton = new Button(this);
        bindSelectedButton.setText("Bind selected");
        bindSelectedButton.setAllCaps(false);
        bindSelectedButton.setOnClickListener(view -> bindSelectedApplication());
        productButtons.addView(bindSelectedButton, weighted());
        unbindSelectedButton = new Button(this);
        unbindSelectedButton.setText("Unbind selected");
        unbindSelectedButton.setAllCaps(false);
        unbindSelectedButton.setOnClickListener(view -> unbindSelectedApplication());
        productButtons.addView(unbindSelectedButton, weighted());
        wifiGateButton = new Button(this);
        wifiGateButton.setText("Block wifi");
        wifiGateButton.setAllCaps(false);
        wifiGateButton.setOnClickListener(view -> toggleSelectedNetworkGate(
                AuthoringPolicyBundle.NetworkContextId.WIFI));
        productButtons.addView(wifiGateButton, weighted());
        mobileGateButton = new Button(this);
        mobileGateButton.setText("Block mobile");
        mobileGateButton.setAllCaps(false);
        mobileGateButton.setOnClickListener(view -> toggleSelectedNetworkGate(
                AuthoringPolicyBundle.NetworkContextId.MOBILE));
        productButtons.addView(mobileGateButton, weighted());
        vpnGateButton = new Button(this);
        vpnGateButton.setText("Block vpn");
        vpnGateButton.setAllCaps(false);
        vpnGateButton.setOnClickListener(view -> toggleSelectedNetworkGate(
                AuthoringPolicyBundle.NetworkContextId.VPN));
        productButtons.addView(vpnGateButton, weighted());
        root.addView(productButtons, fillWrap());

        LinearLayout feedbackButtons = new LinearLayout(this);
        Button diagnostics = new Button(this);
        diagnostics.setText("Export diagnostics / feedback");
        diagnostics.setAllCaps(false);
        diagnostics.setOnClickListener(view -> exportReleaseDiagnostics());
        feedbackButtons.addView(diagnostics, fillWrap());
        root.addView(feedbackButtons, fillWrap());

        statusView = new TextView(this);
        statusView.setTextSize(15);
        statusView.setPadding(0, dp(12), 0, dp(8));
        root.addView(statusView, fillWrap());
        productView = new TextView(this);
        productView.setTextSize(14);
        productView.setPadding(0, dp(8), 0, dp(8));
        root.addView(productView, fillWrap());
        actionView = new TextView(this);
        root.addView(actionView, fillWrap());
        return scroller;
    }

    private void startSelected() {
        startSelected(null, null);
    }

    private void startSelected(String rootNfqueueFaultMode) {
        startSelected(rootNfqueueFaultMode, null);
    }

    private void startSelected(String rootNfqueueFaultMode, String vpnFaultMode) {
        RuntimeProfile profile = profileFromSpinner();
        startProfile(profile, rootNfqueueFaultMode, vpnFaultMode);
    }

    private void startProfile(RuntimeProfile profile, String rootNfqueueFaultMode,
                              String vpnFaultMode) {
        startProfile(profile, rootNfqueueFaultMode, vpnFaultMode, true);
    }

    private void startProfile(RuntimeProfile profile, String rootNfqueueFaultMode,
                              String vpnFaultMode, boolean requireVpnPrepare) {
        requestedProfile = profile;
        if (requireVpnPrepare && profile == RuntimeProfile.VPN
                && !ensureVpnPreparedForStart()) {
            return;
        }
        RuntimeControlBackend.StartResult result;
        try {
            result = backend.start(this, profile, rootNfqueueFaultMode, vpnFaultMode);
        } catch (RuntimeException error) {
            requestedProfile = null;
            action("Start failed: runtime_start_failed"
                    + (error.getMessage() == null ? "" : ": " + error.getMessage()));
            refreshStatus();
            return;
        }
        if (result == RuntimeControlBackend.StartResult.NOTIFICATION_REQUIRED) {
            pendingStart = true;
            if (android.os.Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        NOTIFICATION_PERMISSION);
            }
            action("Visible protection notification permission is required.");
        } else {
            action("Start requested for " + profile.wireName + ".");
        }
        refreshStatus();
    }

    private void stopRuntime() {
        pendingStart = false;
        pendingVpnStart = false;
        backend.stop(this);
        action("Stop requested.");
        refreshStatus();
    }

    private void pauseProtection() {
        pendingStart = false;
        pendingVpnStart = false;
        backend.pauseProtection(this);
        action("Protection Pause requested.");
        refreshStatus();
    }

    private void resumeProtection() {
        pendingStart = false;
        pendingVpnStart = false;
        RuntimeControlBackend.StartResult result = backend.resumeProtection(this);
        if (result == RuntimeControlBackend.StartResult.NOTIFICATION_REQUIRED) {
            pendingStart = true;
            action("Visible protection notification permission is required.");
        } else {
            action("Protection Resume requested.");
        }
        refreshStatus();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_PREPARE_REQUEST) {
            return;
        }
        if (resultCode == RESULT_OK && pendingVpnStart) {
            pendingVpnStart = false;
            requestedProfile = RuntimeProfile.VPN;
            setProfileSpinnerSelection(RuntimeProfile.VPN);
            startSelected();
            return;
        }
        pendingVpnStart = false;
        requestedProfile = null;
        action("VPN authorization denied.");
        refreshStatus();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == NOTIFICATION_PERMISSION && pendingStart
                && results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            pendingStart = false;
            startSelected();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();
        refreshProductCatalog();
        main.postDelayed(statusPoll, STATUS_POLL_MILLIS);
    }

    @Override
    protected void onPause() {
        main.removeCallbacks(statusPoll);
        super.onPause();
    }

    // Intentionally no stop request in onDestroy: Activity lifecycle is not runtime ownership.
    @Override
    protected void onDestroy() {
        main.removeCallbacks(statusPoll);
        super.onDestroy();
    }

    private final Runnable statusPoll = new Runnable() {
        @Override
        public void run() {
            refreshStatus();
            main.postDelayed(this, STATUS_POLL_MILLIS);
        }
    };

    private void refreshStatus() {
        if (statusView != null) {
            RuntimeSnapshot current = backend.query(this);
            if (requestedProfile != null
                    && current.profile == requestedProfile && current.isActive()) {
                requestedProfile = null;
            } else if (requestedProfile != null
                    && RuntimeSnapshot.STATE_ERROR.equals(current.state)
                    && !current.isActive()) {
                requestedProfile = null;
            }
            // Activity recreation must reflect the durable service projection,
            // including an active VPN profile. Selection is presentation-only;
            // changing it never sends a START request.
            if (requestedProfile == null && profileSpinner != null && current.isActive()) {
                if (current.profile == RuntimeProfile.VPN) {
                    setProfileSpinnerSelection(RuntimeProfile.VPN);
                } else {
                    setProfileSpinnerSelection(RuntimeProfile.ROOT);
                }
            }
            statusView.setText(current.displayText() + "\n\n"
                    + initializationPlanText(current));
        }
        if (productView != null) {
            renderProductProjection(ProductCatalogProjectionStore.read(getFilesDir()));
        }
    }

    private String initializationPlanText(RuntimeSnapshot current) {
        RuntimeProfile selected = current != null && current.isActive()
                ? current.profile : profileFromSpinner();
        boolean notificationReady = RuntimeService.notificationsReady(this);
        boolean rootAuthorized = current == null
                || !"root_authorization_required".equals(current.errorCode);
        boolean vpnAuthorized = selected != RuntimeProfile.VPN
                || VpnService.prepare(this) == null;
        boolean runtimeReady = current != null && current.isActive()
                && current.profile == selected
                && "ok".equals(current.coreHealth)
                && !RuntimeSnapshot.ADAPTER_UNAVAILABLE.equals(current.adapterReadiness);
        RuntimeProfileInitializationPlan plan = RuntimeProfileInitializationPlan.from(
                new RuntimeProfileInitializationPlan.Inputs(
                        ProductPacketAdapterContract.forProfile(RuntimeProfile.ROOT)
                                .productLaunchAllowed,
                        rootAuthorized,
                        ProductPacketAdapterContract.forProfile(RuntimeProfile.VPN)
                                .productLaunchAllowed,
                        vpnAuthorized,
                        notificationReady,
                        runtimeReady,
                        selected));
        return "Initialization: " + plan.currentStep
                + "\nRecommended: " + profileName(plan.recommendedProfile)
                + "\nAction: " + plan.currentAction
                + "\nImpact: " + plan.impact
                + "\nRecovery: " + plan.recoveryAction;
    }

    private static String profileName(RuntimeProfile profile) {
        return profile == null ? "none" : profile.displayName;
    }

    private RuntimeProfile profileFromSpinner() {
        return profileSpinner != null && profileSpinner.getSelectedItemPosition() == 1
                ? RuntimeProfile.VPN : RuntimeProfile.ROOT;
    }

    private void setProfileSpinnerSelection(RuntimeProfile profile) {
        if (profileSpinner == null) {
            return;
        }
        suppressProfileSelectionPersist = true;
        profileSpinner.setSelection(profile == RuntimeProfile.VPN ? 1 : 0);
        suppressProfileSelectionPersist = false;
    }

    private void requestSelectedProductProfile(RuntimeProfile profile, String successPrefix) {
        backend.selectProductProfile(this, profile);
        action(successPrefix + " requested: " + profile.wireName + ".");
        refreshProductCatalog();
    }

    private boolean ensureVpnPreparedForStart() {
        Intent prepare = VpnService.prepare(this);
        if (prepare == null) {
            return true;
        }
        pendingVpnStart = true;
        action("VPN authorization required before starting vpn profile.");
        startActivityForResult(prepare, VPN_PREPARE_REQUEST);
        return false;
    }

    private void refreshProductCatalog() {
        if (productView == null) {
            return;
        }
        final int generation = ++productCatalogGeneration;
        backend.queryService(this);
        renderProductProjection(ProductCatalogProjectionStore.read(getFilesDir()));
        main.postDelayed(() -> {
            if (generation == productCatalogGeneration) {
                renderProductProjection(ProductCatalogProjectionStore.read(getFilesDir()));
            }
        }, STATUS_POLL_MILLIS);
    }

    private void renderProductProjection(ProductCatalogFormatter.Projection projection) {
        productProjection = projection;
        if (productView != null) {
            AppDetail detail = ProductActivityProjectionStore.read(getFilesDir());
            productView.setText(projection.displayText + "\n\n" + detail.displayText);
        }
        renderApplicationSelector(projection);
    }

    private void renderApplicationSelector(ProductCatalogFormatter.Projection projection) {
        if (appSpinner == null) {
            return;
        }
        ArrayList<ProductCatalogFormatter.EntryRow> rows =
                new ArrayList<>(projection.selectableRows);
        ArrayAdapter<ProductCatalogFormatter.EntryRow> adapter =
                new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, rows);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

        ApplicationSubjectId previousSubject = selectedApplicationSubjectId;
        int selectedPosition = -1;
        for (int i = 0; i < rows.size(); i++) {
            if (previousSubject != null && previousSubject.equals(rows.get(i).subjectId)) {
                selectedPosition = i;
                break;
            }
        }
        if (selectedPosition < 0 && !rows.isEmpty()) {
            selectedPosition = 0;
        }

        suppressAppSelection = true;
        appSpinner.setAdapter(adapter);
        if (selectedPosition >= 0) {
            appSpinner.setSelection(selectedPosition);
        }
        suppressAppSelection = false;

        ProductCatalogFormatter.EntryRow row = selectedPosition < 0 ? null : rows.get(selectedPosition);
        selectedApplicationSubjectId = row == null ? null : row.subjectId;
        renderSelectedApplicationIcon(row);
        updateSelectedApplicationButtons(row);
    }

    private ProductCatalogFormatter.EntryRow selectedApplicationRow() {
        if (appSpinner == null) {
            return null;
        }
        Object selected = appSpinner.getSelectedItem();
        if (selected instanceof ProductCatalogFormatter.EntryRow) {
            return (ProductCatalogFormatter.EntryRow) selected;
        }
        return null;
    }

    private void updateSelectedApplicationButtons(ProductCatalogFormatter.EntryRow row) {
        if (bindSelectedButton != null) {
            bindSelectedButton.setEnabled(row != null && row.canBind());
        }
        if (unbindSelectedButton != null) {
            unbindSelectedButton.setEnabled(row != null && row.canUnbind());
        }
        updateNetworkGateButton(wifiGateButton, row,
                AuthoringPolicyBundle.NetworkContextId.WIFI);
        updateNetworkGateButton(mobileGateButton, row,
                AuthoringPolicyBundle.NetworkContextId.MOBILE);
        updateNetworkGateButton(vpnGateButton, row,
                AuthoringPolicyBundle.NetworkContextId.VPN);
    }

    private void updateNetworkGateButton(Button button, ProductCatalogFormatter.EntryRow row,
                                         AuthoringPolicyBundle.NetworkContextId context) {
        if (button == null) {
            return;
        }
        button.setEnabled(row != null && row.canToggleGate());
        button.setText(row == null ? "Block " + context.wireName
                : row.networkGateButtonLabel(context));
    }

    private void renderSelectedApplicationIcon(ProductCatalogFormatter.EntryRow row) {
        if (selectedAppIcon == null) {
            return;
        }
        Drawable icon = row == null ? null : loadApplicationIcon(row);
        if (icon == null) {
            selectedAppIcon.setImageDrawable(null);
            selectedAppIcon.setContentDescription("No selected application icon");
        } else {
            selectedAppIcon.setImageDrawable(icon);
            selectedAppIcon.setContentDescription("Icon for " + row.label
                    + " subject " + row.subjectId.encode());
        }
    }

    private Drawable loadApplicationIcon(ProductCatalogFormatter.EntryRow row) {
        LauncherApps launcherApps = getSystemService(LauncherApps.class);
        UserHandle user = UserHandle.getUserHandleForUid(row.fullUid);
        if (launcherApps != null && user != null) {
            try {
                List<LauncherActivityInfo> activities =
                        launcherApps.getActivityList(row.packageName, user);
                if (activities != null && !activities.isEmpty()) {
                    Drawable icon = activities.get(0).getBadgedIcon(0);
                    if (icon != null) {
                        return icon;
                    }
                    return activities.get(0).getIcon(0);
                }
            } catch (RuntimeException ignored) {
                // Fall through to the current-user PackageManager fallback below.
            }
        }
        try {
            return getPackageManager().getApplicationIcon(row.packageName);
        } catch (PackageManager.NameNotFoundException | RuntimeException ignored) {
            return null;
        }
    }

    private void bindSelectedApplication() {
        ProductCatalogFormatter.EntryRow row = selectedApplicationRow();
        ApplicationSubjectId subjectId = row == null ? selectedApplicationSubjectId : row.subjectId;
        if (subjectId == null || row == null || !row.canBind()) {
            action("No selected available catalog app to bind.");
            return;
        }
        backend.bindProductApplication(this, subjectId);
        action("Bind requested for application subject " + subjectId.encode() + ".");
        refreshProductCatalog();
    }

    private void unbindSelectedApplication() {
        ProductCatalogFormatter.EntryRow row = selectedApplicationRow();
        ApplicationSubjectId subjectId = row == null ? selectedApplicationSubjectId : row.subjectId;
        if (subjectId == null || row == null || !row.canUnbind()) {
            action("No selected bound application subject to unbind.");
            return;
        }
        backend.unbindProductApplication(this, subjectId);
        action("Unbind requested for application subject " + subjectId.encode() + ".");
        refreshProductCatalog();
    }

    private void toggleSelectedNetworkGate(AuthoringPolicyBundle.NetworkContextId context) {
        ProductCatalogFormatter.EntryRow row = selectedApplicationRow();
        ApplicationSubjectId subjectId = row == null ? selectedApplicationSubjectId : row.subjectId;
        if (subjectId == null || row == null || !row.canToggleGate()) {
            action("No selected available catalog app for Network Gate.");
            return;
        }
        boolean blocked = !row.isNetworkGateBlocked(context);
        backend.setNetworkGate(this, subjectId, context, blocked);
        action("Network Gate " + (blocked ? "block" : "open")
                + " requested for " + context.wireName
                + " subject " + subjectId.encode() + ".");
        refreshProductCatalog();
    }

    private void requestDebugProductBinding(String encodedSubject, boolean bind) {
        final ApplicationSubjectId subjectId;
        try {
            subjectId = ApplicationSubjectId.parse(encodedSubject);
        } catch (IllegalArgumentException error) {
            action("Invalid debug application subject: " + encodedSubject);
            return;
        }
        if (bind) {
            backend.bindProductApplication(this, subjectId);
            action("Debug bind requested for application subject " + subjectId.encode() + ".");
        } else {
            backend.unbindProductApplication(this, subjectId);
            action("Debug unbind requested for application subject " + subjectId.encode() + ".");
        }
        selectedApplicationSubjectId = subjectId;
        refreshProductCatalog();
    }

    private void requestDebugNetworkGate(String encodedSubject, String contextName,
                                         boolean blocked) {
        final ApplicationSubjectId subjectId;
        final AuthoringPolicyBundle.NetworkContextId context;
        try {
            subjectId = ApplicationSubjectId.parse(encodedSubject);
            context = AuthoringPolicyBundle.NetworkContextId.parse(contextName);
        } catch (IllegalArgumentException error) {
            action("Invalid debug Network Gate request: " + boundedError(error));
            return;
        }
        backend.setNetworkGate(this, subjectId, context, blocked);
        action("Debug Network Gate " + (blocked ? "block" : "open")
                + " requested for " + context.wireName
                + " subject " + subjectId.encode() + ".");
        selectedApplicationSubjectId = subjectId;
        refreshProductCatalog();
    }

    private void requestDebugL4Rule(Intent intent, String encodedSubject) {
        final AuthoringPolicyBundle.L4Rule rule;
        try {
            ApplicationSubjectId subjectId = ApplicationSubjectId.parse(encodedSubject);
            AuthoringPolicyBundle.IpFamily family = AuthoringPolicyBundle.IpFamily.parse(
                    stringExtra(intent, EXTRA_DEBUG_SET_L4_RULE_FAMILY, "ipv4"));
            AuthoringPolicyBundle.PacketDirection direction =
                    AuthoringPolicyBundle.PacketDirection.parse(
                            stringExtra(intent, EXTRA_DEBUG_SET_L4_RULE_DIRECTION, "output"));
            AuthoringPolicyBundle.L4Action action = AuthoringPolicyBundle.L4Action.parse(
                    stringExtra(intent, EXTRA_DEBUG_SET_L4_RULE_ACTION, "drop"));
            AuthoringPolicyBundle.NetworkContextId context = optionalNetworkContext(
                    intent.getStringExtra(EXTRA_DEBUG_SET_L4_RULE_NETWORK_CONTEXT));
            int ipProtocol = intent.getIntExtra(EXTRA_DEBUG_SET_L4_RULE_IP_PROTOCOL, 6);
            int priority = intent.getIntExtra(EXTRA_DEBUG_SET_L4_RULE_PRIORITY, 0);
            int order = intent.getIntExtra(EXTRA_DEBUG_SET_L4_RULE_ORDER, 0);
            rule = AuthoringPolicyBundle.L4Rule.create(subjectId, family,
                    intent.getStringExtra(EXTRA_DEBUG_SET_L4_RULE_SOURCE_CIDR),
                    intent.getStringExtra(EXTRA_DEBUG_SET_L4_RULE_DESTINATION_CIDR),
                    optionalDebugPortRange(intent,
                            EXTRA_DEBUG_SET_L4_RULE_SOURCE_PORT_FIRST,
                            EXTRA_DEBUG_SET_L4_RULE_SOURCE_PORT_LAST),
                    optionalDebugPortRange(intent,
                            EXTRA_DEBUG_SET_L4_RULE_DESTINATION_PORT_FIRST,
                            EXTRA_DEBUG_SET_L4_RULE_DESTINATION_PORT_LAST),
                    ipProtocol, direction, context, action, priority, order);
        } catch (IllegalArgumentException error) {
            action("Invalid debug L4 rule request: " + boundedError(error));
            return;
        }
        backend.setL4Rule(this, rule);
        action("Debug L4 rule " + rule.action.wireName
                + " requested for subject " + rule.subjectId.encode()
                + " ruleId " + Long.toUnsignedString(rule.ruleId) + ".");
        selectedApplicationSubjectId = rule.subjectId;
        refreshProductCatalog();
    }

    private static String stringExtra(Intent intent, String name, String defaultValue) {
        String value = intent.getStringExtra(name);
        return value == null || value.trim().isEmpty() ? defaultValue : value;
    }

    private static AuthoringPolicyBundle.NetworkContextId optionalNetworkContext(String value) {
        return value == null || value.trim().isEmpty()
                ? null : AuthoringPolicyBundle.NetworkContextId.parse(value);
    }

    private static AuthoringPolicyBundle.PortRange optionalDebugPortRange(
            Intent intent, String firstName, String lastName) {
        boolean hasFirst = intent.hasExtra(firstName);
        boolean hasLast = intent.hasExtra(lastName);
        if (!hasFirst && !hasLast) {
            return null;
        }
        if (!hasFirst || !hasLast) {
            throw new IllegalArgumentException(firstName + "/" + lastName
                    + " must be supplied together");
        }
        return AuthoringPolicyBundle.PortRange.inclusive(
                intent.getIntExtra(firstName, -1), intent.getIntExtra(lastName, -1));
    }

    private void runDebugTrafficProbe() {
        runDebugTrafficProbe(DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT,
                0, DEBUG_TRAFFIC_TIMEOUT_MILLIS);
    }

    private void runDebugTrafficProbe(
            String host, int port, int sourcePort, int timeoutMillis) {
        runDebugTrafficProbe(host, port, sourcePort, timeoutMillis, "", false);
    }

    private void runDebugTrafficProbe(
            String host, int port, int sourcePort, int timeoutMillis, boolean bindToVpn) {
        runDebugTrafficProbe(host, port, sourcePort, timeoutMillis, "", bindToVpn);
    }

    private void runDebugTrafficProbe(
            String host, int port, int sourcePort, int timeoutMillis, String nonce,
            boolean bindToVpn) {
        action("Debug traffic probe requested.");
        Thread probe = new Thread(() -> {
            DebugTrafficProbeResult probeResult = runDebugTrafficProbeBlockingWithOptions(
                    host, port, sourcePort, timeoutMillis, true, bindToVpn, nonce);
            writeDebugTrafficProbeResult(
                    host, port, sourcePort, timeoutMillis, bindToVpn, probeResult);
            final String display = probeResult.message;
            main.post(() -> action(display));
        }, "sakamoto-debug-traffic");
        probe.start();
    }

    private void runDebugUdpTrafficProbe(
            String host, int port, int sourcePort, int timeoutMillis, boolean bindToVpn) {
        runDebugUdpTrafficProbe(host, port, sourcePort, timeoutMillis, "", false, bindToVpn);
    }

    private void runDebugUdpTrafficProbe(
            String host, int port, int sourcePort, int timeoutMillis, String nonce,
            boolean expectReply, boolean bindToVpn) {
        action("Debug UDP traffic probe requested.");
        Thread probe = new Thread(() -> {
            DebugUdpTrafficProbeResult probeResult = runDebugUdpTrafficProbeBlocking(
                    host, port, sourcePort, timeoutMillis, nonce, expectReply, bindToVpn);
            writeDebugUdpTrafficProbeResult(
                    host, port, sourcePort, timeoutMillis, bindToVpn, probeResult);
            final String display = probeResult.message;
            main.post(() -> action(display));
        }, "sakamoto-debug-udp-traffic");
        probe.start();
    }

    private void runDebugDownloadProbe(String url, int timeoutMillis, int maxBytes) {
        action("Debug download probe requested.");
        Thread probe = new Thread(() -> {
            DebugDownloadProbeResult result =
                    runDebugDownloadProbeBlocking(url, timeoutMillis, maxBytes);
            writeDebugDownloadProbeResult(url, timeoutMillis, maxBytes, result);
            final String display = result.result.equals("download_succeeded")
                    ? "Debug download probe read " + result.bytes + " bytes in "
                    + result.elapsedMillis + " ms."
                    : "Debug download probe failed: " + result.message;
            main.post(() -> action(display));
        }, "sakamoto-debug-download");
        probe.start();
    }

    private void runDebugTrafficListener(int port, int timeoutMillis) {
        runDebugTrafficListener("0.0.0.0", port, timeoutMillis, "");
    }

    private void runDebugTrafficListener(
            String host, int port, int timeoutMillis, String expectedNonce) {
        action("Debug traffic listener requested on " + host + ":" + port + ".");
        Thread listener = new Thread(() -> {
            DebugListenerProbeResult result = runDebugTrafficListenerBlocking(
                    host, port, timeoutMillis, expectedNonce);
            writeDebugTcpListenerResult(host, port, timeoutMillis, expectedNonce, result);
            final String display = result.message;
            main.post(() -> action(display));
        }, "sakamoto-debug-listener");
        listener.start();
    }

    private void runDebugUdpTrafficListener(
            String host, int port, int timeoutMillis, String expectedNonce) {
        action("Debug UDP traffic listener requested on " + host + ":" + port + ".");
        Thread listener = new Thread(() -> {
            DebugListenerProbeResult result = runDebugUdpTrafficListenerBlocking(
                    host, port, timeoutMillis, expectedNonce);
            writeDebugUdpListenerResult(host, port, timeoutMillis, expectedNonce, result);
            final String display = result.message;
            main.post(() -> action(display));
        }, "sakamoto-debug-udp-listener");
        listener.start();
    }

    private void runDebugApplyGateAndProbe() {
        action("Debug policy gate/probe requested.");
        Thread probe = new Thread(() -> {
            String result;
            try (ControlVNextDebugClient client = new ControlVNextDebugClient()) {
                int uid = android.os.Process.myUid();
                RuntimeSnapshot current = backend.query(this);
                RuntimeProfile profile = current.isActive()
                        ? current.profile : profileFromSpinner();
                String statusCommand = debugPacketStatusCommand(profile);
                client.call(1, "POLICY.APPLY", debugPolicyApplyArgs(uid));
                JSONObject decision = client.call(2, "POLICY.EVALUATE",
                        debugPolicyEvaluateArgs(uid));
                JSONObject countersBefore = client.call(3, statusCommand, new JSONObject());
                String probeResult = runDebugTrafficProbeBlocking(
                        DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT,
                        0, DEBUG_TRAFFIC_TIMEOUT_MILLIS, false);
                writeDebugTrafficProbeResult(DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT,
                        0, DEBUG_TRAFFIC_TIMEOUT_MILLIS, probeResult);
                JSONObject countersAfter = client.call(4, statusCommand, new JSONObject());
                result = formatDebugPolicyProbeResult(
                        uid, profile, DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT, decision,
                        countersBefore, countersAfter, probeResult);
            } catch (IOException | JSONException | RuntimeException error) {
                result = "Debug policy gate/probe failed: " + boundedError(error);
            }
            final String display = result;
            main.post(() -> action(display));
        }, "sakamoto-debug-policy-probe");
        probe.start();
    }

    private void runDebugL4PrefillFromActivity(String host, int port) {
        action("Debug L4 prefill requested.");
        Thread prefill = new Thread(() -> {
            String result;
            try (ControlVNextDebugClient client = new ControlVNextDebugClient()) {
                RuntimeSnapshot current = backend.query(this);
                RuntimeProfile profile = current.isActive()
                        ? current.profile : profileFromSpinner();
                JSONObject status = client.call(1, debugPacketStatusCommand(profile),
                        new JSONObject());
                result = formatActivityL4Prefill(status.optJSONObject("policyDropActivity"));
            } catch (IOException | JSONException | RuntimeException error) {
                result = "L4 prefill: failed " + boundedError(error);
            }
            writeDebugL4PrefillResult(host, port, result);
            final String display = result;
            main.post(() -> action(display));
        }, "sakamoto-debug-l4-prefill");
        prefill.start();
    }

    private JSONObject debugPolicyApplyArgs(int uid) throws JSONException {
        JSONObject gate = new JSONObject()
                .put("blockedNetworkContexts", new JSONArray().put(DEBUG_POLICY_NETWORK_CONTEXT))
                .put("reasonId", DEBUG_POLICY_REASON_ID)
                .put("ruleId", DEBUG_POLICY_RULE_ID);
        JSONObject subject = new JSONObject()
                .put("linuxUid", uid)
                .put("networkGate", gate)
                .put("l4Rules", new JSONArray());
        return new JSONObject()
                .put("revision", DEBUG_POLICY_REVISION)
                .put("subjects", new JSONArray().put(subject));
    }

    private JSONObject debugPolicyEvaluateArgs(int uid) throws JSONException {
        return new JSONObject()
                .put("linuxUid", uid)
                .put("networkContext", DEBUG_POLICY_NETWORK_CONTEXT)
                .put("family", "ipv4")
                .put("direction", "output")
                .put("ipProtocol", 6)
                .put("sourcePort", 40000)
                .put("destinationPort", DEBUG_TRAFFIC_PORT)
                .put("portsAvailable", true);
    }

    private String debugPacketStatusCommand(RuntimeProfile profile) {
        return profile == RuntimeProfile.VPN ? "VPN_TUN.STATUS" : "NFQUEUE.STATUS";
    }

    private String debugPacketAdapterLabel(RuntimeProfile profile) {
        return profile == RuntimeProfile.VPN ? "VPN_TUN" : "NFQUEUE";
    }

    private String debugForwardedCounterName(RuntimeProfile profile) {
        return profile == RuntimeProfile.VPN ? "forwardedPackets" : "acceptedPackets";
    }

    private String runDebugTrafficProbeBlocking(
            String host, int port, int sourcePort, int timeoutMillis, boolean includeEndpoint) {
        return runDebugTrafficProbeBlockingWithOptions(
                host, port, sourcePort, timeoutMillis, includeEndpoint, false, "").message;
    }

    private DebugUdpTrafficProbeResult runDebugUdpTrafficProbeBlocking(
            String host, int port, int sourcePort, int timeoutMillis, String nonce,
            boolean expectReply, boolean bindToVpn) {
        DebugTrafficProbeBinding binding = bindToVpn
                ? DebugTrafficProbeBinding.notAttempted()
                : DebugTrafficProbeBinding.notRequested();
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(true);
            InetAddress address = InetAddress.getByName(host);
            if (address.getAddress().length == 16) {
                socket.bind(new InetSocketAddress(
                        InetAddress.getByName("::"), sourcePort));
            } else {
                socket.bind(new InetSocketAddress(sourcePort));
            }
            if (bindToVpn) {
                binding = bindDebugDatagramSocketToVpn(socket);
                if (!binding.isBound()) {
                    String message = "Debug UDP traffic probe failed before send: VPN "
                            + "Network.bindSocket " + binding.result
                            + (binding.error.isEmpty() ? "" : " (" + binding.error + ")");
                    return new DebugUdpTrafficProbeResult(
                            "udp_bind_failed", message, binding);
                }
            }

            byte[] payload = (nonce == null || nonce.isEmpty()
                    ? "sakamoto-debug-udp" : nonce).getBytes(StandardCharsets.UTF_8);
            DatagramPacket packet = new DatagramPacket(payload, payload.length,
                    address, port);
            socket.send(packet);
            if (expectReply) {
                socket.setSoTimeout(timeoutMillis);
                byte[] response = new byte[Math.max(payload.length, 1)];
                DatagramPacket reply = new DatagramPacket(response, response.length);
                socket.receive(reply);
                boolean matched = reply.getLength() == payload.length
                        && Arrays.equals(payload, Arrays.copyOf(response, reply.getLength()));
                String result = matched ? "udp_echo_matched" : "udp_echo_mismatch";
                String message = matched
                        ? "Debug UDP echo matched."
                        : "Debug UDP echo mismatch.";
                return new DebugUdpTrafficProbeResult(
                        result, message, binding, nonce, payload.length, reply.getLength());
            }
            // Keep the datagram socket alive briefly so the VPN-side owner
            // lookup can observe the just-sent tuple before the fixture closes
            // it.  This is still a send-only probe; no reply is read or
            // required.
            if (timeoutMillis > 0) {
                try {
                    Thread.sleep(Math.min(timeoutMillis, 3000));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            String message = "Debug UDP datagram sent to " + host + ":" + port
                    + (sourcePort > 0 ? " from source port " + sourcePort : "")
                    + ". No external reply is claimed.";
            return new DebugUdpTrafficProbeResult(
                    "udp_datagram_sent", message, binding, nonce, payload.length, 0);
        } catch (IOException error) {
            String message = "Debug UDP traffic probe failed: "
                    + (error.getMessage() == null
                    ? error.getClass().getSimpleName() : error.getMessage());
            return new DebugUdpTrafficProbeResult(
                    "udp_datagram_failed", message, binding, nonce, 0, 0);
        } catch (RuntimeException error) {
            String message = "Debug UDP traffic probe failed: "
                    + error.getClass().getSimpleName();
            return new DebugUdpTrafficProbeResult(
                    "udp_datagram_failed", message, binding, nonce, 0, 0);
        }
    }

    private DebugTrafficProbeResult runDebugTrafficProbeBlockingWithOptions(
            String host, int port, int sourcePort, int timeoutMillis,
            boolean includeEndpoint, boolean bindToVpn, String nonce) {
        DebugTrafficProbeBinding binding = bindToVpn
                ? DebugTrafficProbeBinding.notAttempted()
                : DebugTrafficProbeBinding.notRequested();
        try (Socket socket = new Socket()) {
            if (sourcePort > 0) {
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(sourcePort));
            }
            if (bindToVpn) {
                binding = bindDebugTrafficSocketToVpn(socket);
                if (!binding.isBound()) {
                    String failure = "Debug traffic probe failed before connect: VPN "
                            + "Network.bindSocket " + binding.result
                            + (binding.error.isEmpty() ? "" : " (" + binding.error + ")");
                    return new DebugTrafficProbeResult(
                            includeEndpoint ? failure : "tcp_connect_failed",
                            binding.result, binding.networkHandle, binding.error,
                            nonce, 0, 0);
                }
            }
            socket.connect(new InetSocketAddress(host, port), timeoutMillis);
            if (nonce != null && !nonce.isEmpty()) {
                byte[] request = nonce.getBytes(StandardCharsets.UTF_8);
                byte[] response = new byte[request.length];
                int received = 0;
                socket.setSoTimeout(timeoutMillis);
                OutputStream out = socket.getOutputStream();
                out.write(request);
                out.flush();
                InputStream in = socket.getInputStream();
                while (received < response.length) {
                    int count = in.read(response, received, response.length - received);
                    if (count < 0) {
                        break;
                    }
                    received += count;
                }
                boolean matched = received == request.length
                        && Arrays.equals(request, response);
                return new DebugTrafficProbeResult(
                        matched ? "Debug traffic probe echo matched."
                                : "Debug traffic probe echo mismatch.",
                        binding.result, binding.networkHandle, binding.error,
                        nonce, request.length, received);
            }
            if (includeEndpoint) {
                String message = "Debug traffic probe connected to "
                        + host + ":" + port
                        + (sourcePort > 0 ? " from source port " + sourcePort : "")
                        + ".";
                if (binding.isBound()) {
                    message += " via active VPN Network handle "
                            + binding.networkHandle + ".";
                }
                return new DebugTrafficProbeResult(
                        message, binding.result, binding.networkHandle, binding.error);
            }
            return new DebugTrafficProbeResult(
                    "tcp_connect_succeeded", binding.result,
                    binding.networkHandle, binding.error);
        } catch (IOException error) {
            String message;
            if (includeEndpoint) {
                message = "Debug traffic probe failed: "
                        + (error.getMessage() == null
                        ? error.getClass().getSimpleName()
                        : error.getMessage());
            }
            else {
                message = "tcp_connect_failed";
            }
            return new DebugTrafficProbeResult(
                    message, binding.result, binding.networkHandle, binding.error,
                    nonce, 0, 0);
        } catch (RuntimeException error) {
            String message;
            if (includeEndpoint) {
                message = "Debug traffic probe failed: "
                        + error.getClass().getSimpleName();
            }
            else {
                message = "tcp_connect_failed";
            }
            return new DebugTrafficProbeResult(
                    message, binding.result, binding.networkHandle, binding.error,
                    nonce, 0, 0);
        }
    }

    private DebugTrafficProbeBinding bindDebugTrafficSocketToVpn(Socket socket) {
        DebugVpnNetwork vpnNetwork = findDebugVpnNetwork();
        if (!vpnNetwork.isAvailable()) {
            return vpnNetwork.binding;
        }
        try {
            vpnNetwork.network.bindSocket(socket);
            return DebugTrafficProbeBinding.bound(vpnNetwork.networkHandle);
        } catch (IOException error) {
            return DebugTrafficProbeBinding.failed(
                    "bind_failed", vpnNetwork.networkHandle, boundedError(error));
        } catch (RuntimeException error) {
            return DebugTrafficProbeBinding.failed(
                    "bind_failed", vpnNetwork.networkHandle, boundedError(error));
        }
    }

    private DebugTrafficProbeBinding bindDebugDatagramSocketToVpn(DatagramSocket socket) {
        DebugVpnNetwork vpnNetwork = findDebugVpnNetwork();
        if (!vpnNetwork.isAvailable()) {
            return vpnNetwork.binding;
        }
        try {
            vpnNetwork.network.bindSocket(socket);
            return DebugTrafficProbeBinding.bound(vpnNetwork.networkHandle);
        } catch (IOException error) {
            return DebugTrafficProbeBinding.failed(
                    "bind_failed", vpnNetwork.networkHandle, boundedError(error));
        } catch (RuntimeException error) {
            return DebugTrafficProbeBinding.failed(
                    "bind_failed", vpnNetwork.networkHandle, boundedError(error));
        }
    }

    private DebugVpnNetwork findDebugVpnNetwork() {
        ConnectivityManager connectivityManager = getSystemService(ConnectivityManager.class);
        if (connectivityManager == null) {
            return DebugVpnNetwork.unavailable(
                    "connectivity_manager_unavailable", -1L,
                    "ConnectivityManager unavailable");
        }

        final Network[] networks;
        try {
            networks = connectivityManager.getAllNetworks();
        } catch (RuntimeException error) {
            return DebugVpnNetwork.unavailable(
                    "vpn_network_lookup_failed", -1L, boundedError(error));
        }
        if (networks == null || networks.length == 0) {
            return DebugVpnNetwork.unavailable(
                    "no_networks", -1L, "ConnectivityManager returned no networks");
        }
        for (Network network : networks) {
            if (network == null) {
                continue;
            }
            final long networkHandle;
            try {
                networkHandle = network.getNetworkHandle();
            } catch (RuntimeException ignored) {
                continue;
            }
            final NetworkCapabilities capabilities;
            try {
                capabilities = connectivityManager.getNetworkCapabilities(network);
            } catch (RuntimeException ignored) {
                continue;
            }
            if (capabilities != null
                    && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return DebugVpnNetwork.available(network, networkHandle);
            }
        }
        return DebugVpnNetwork.unavailable(
                "vpn_network_not_found", -1L,
                "no Network has TRANSPORT_VPN capability");
    }

    private DebugDownloadProbeResult runDebugDownloadProbeBlocking(
            String urlText, int timeoutMillis, int maxBytes) {
        long startNanos = System.nanoTime();
        int bytes = 0;
        HttpURLConnection connection = null;
        try {
            URL url = new URL(urlText);
            connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(true);
            connection.setConnectTimeout(timeoutMillis);
            connection.setReadTimeout(timeoutMillis);
            connection.setRequestProperty("User-Agent", "sakamoto-debug-download-probe");
            connection.connect();
            byte[] buffer = new byte[8192];
            try (InputStream in = connection.getInputStream()) {
                while (bytes < maxBytes) {
                    int limit = Math.min(buffer.length, maxBytes - bytes);
                    int read = in.read(buffer, 0, limit);
                    if (read < 0) {
                        break;
                    }
                    bytes += read;
                }
            }
            long elapsedMillis = Math.max(1L, (System.nanoTime() - startNanos) / 1_000_000L);
            if (bytes <= 0) {
                return new DebugDownloadProbeResult(
                        "download_failed", bytes, elapsedMillis, "no_bytes_read");
            }
            return new DebugDownloadProbeResult(
                    "download_succeeded", bytes, elapsedMillis, "ok");
        } catch (IOException error) {
            long elapsedMillis = Math.max(1L, (System.nanoTime() - startNanos) / 1_000_000L);
            return new DebugDownloadProbeResult(
                    "download_failed", bytes, elapsedMillis, boundedError(error));
        } catch (RuntimeException error) {
            long elapsedMillis = Math.max(1L, (System.nanoTime() - startNanos) / 1_000_000L);
            return new DebugDownloadProbeResult(
                    "download_failed", bytes, elapsedMillis, error.getClass().getSimpleName());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void writeDebugTrafficProbeResult(
            String host, int port, int sourcePort, int timeoutMillis, String result) {
        writeDebugTrafficProbeResult(host, port, sourcePort, timeoutMillis, false,
                new DebugTrafficProbeResult(result, "not_requested", -1L, ""));
    }

    private void writeDebugTrafficProbeResult(
            String host, int port, int sourcePort, int timeoutMillis,
            boolean bindToVpn, DebugTrafficProbeResult probeResult) {
        File file = new File(getFilesDir(), DEBUG_TRAFFIC_PROBE_RESULT_PATH);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return;
        }
        String result = probeResult == null ? "" : probeResult.message;
        String bindResult = probeResult == null
                ? (bindToVpn ? "unknown" : "not_requested") : probeResult.bindResult;
        long bindNetworkHandle = probeResult == null ? -1L : probeResult.bindNetworkHandle;
        String bindError = probeResult == null ? "" : probeResult.bindError;
        String nonce = probeResult == null ? "" : probeResult.nonce;
        int requestBytes = probeResult == null ? 0 : probeResult.requestBytes;
        int responseBytes = probeResult == null ? 0 : probeResult.responseBytes;
        String resultCode = debugTrafficProbeResultCode(result);
        String text = "host=" + propertyValue(host) + "\n"
                + "port=" + port + "\n"
                + "sourcePort=" + sourcePort + "\n"
                + "timeoutMillis=" + timeoutMillis + "\n"
                + "nonce=" + propertyValue(nonce) + "\n"
                + "requestBytes=" + requestBytes + "\n"
                + "responseBytes=" + responseBytes + "\n"
                + "bindToVpn=" + bindToVpn + "\n"
                + "bindResult=" + propertyValue(bindResult) + "\n"
                + "bindNetworkHandle=" + bindNetworkHandle + "\n"
                + "bindError=" + propertyValue(bindError) + "\n"
                + "uid=" + android.os.Process.myUid() + "\n"
                + "result=" + propertyValue(resultCode) + "\n"
                + "message=" + propertyValue(result) + "\n";
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // Debug evidence must never change product control behavior.
        }
        backend.queryService(this);
    }

    private void writeDebugUdpTrafficProbeResult(
            String host, int port, int sourcePort, int timeoutMillis,
            boolean bindToVpn, DebugUdpTrafficProbeResult probeResult) {
        File file = new File(getFilesDir(), DEBUG_UDP_TRAFFIC_PROBE_RESULT_PATH);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return;
        }
        String result = probeResult == null ? "udp_probe_unknown" : probeResult.result;
        String message = probeResult == null ? "" : probeResult.message;
        String bindResult = probeResult == null
                ? (bindToVpn ? "unknown" : "not_requested") : probeResult.bindResult;
        long bindNetworkHandle = probeResult == null ? -1L : probeResult.bindNetworkHandle;
        String bindError = probeResult == null ? "" : probeResult.bindError;
        String nonce = probeResult == null ? "" : probeResult.nonce;
        int requestBytes = probeResult == null ? 0 : probeResult.requestBytes;
        int responseBytes = probeResult == null ? 0 : probeResult.responseBytes;
        String text = "host=" + propertyValue(host) + "\n"
                + "port=" + port + "\n"
                + "sourcePort=" + sourcePort + "\n"
                + "timeoutMillis=" + timeoutMillis + "\n"
                + "nonce=" + propertyValue(nonce) + "\n"
                + "requestBytes=" + requestBytes + "\n"
                + "responseBytes=" + responseBytes + "\n"
                + "bindToVpn=" + bindToVpn + "\n"
                + "bindResult=" + propertyValue(bindResult) + "\n"
                + "bindNetworkHandle=" + bindNetworkHandle + "\n"
                + "bindError=" + propertyValue(bindError) + "\n"
                + "uid=" + android.os.Process.myUid() + "\n"
                + "result=" + propertyValue(result) + "\n"
                + "message=" + propertyValue(message) + "\n";
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // Debug evidence must never change product control behavior.
        }
        backend.queryService(this);
    }

    private void writeDebugTcpListenerResult(
            String host, int port, int timeoutMillis, String expectedNonce,
            DebugListenerProbeResult result) {
        writeDebugListenerResult(DEBUG_TCP_LISTENER_RESULT_PATH, "tcp",
                host, port, timeoutMillis, expectedNonce, result);
    }

    private void writeDebugUdpListenerResult(
            String host, int port, int timeoutMillis, String expectedNonce,
            DebugListenerProbeResult result) {
        writeDebugListenerResult(DEBUG_UDP_LISTENER_RESULT_PATH, "udp",
                host, port, timeoutMillis, expectedNonce, result);
    }

    private void writeDebugListenerResult(
            String relativePath, String protocol, String host, int port, int timeoutMillis,
            String expectedNonce, DebugListenerProbeResult result) {
        File file = new File(getFilesDir(), relativePath);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return;
        }
        DebugListenerProbeResult safe = result == null
                ? new DebugListenerProbeResult(
                protocol + "_listener_unknown", "Debug listener result unavailable.",
                "", 0, 0, "")
                : result;
        String text = "protocol=" + propertyValue(protocol) + "\n"
                + "host=" + propertyValue(host) + "\n"
                + "port=" + port + "\n"
                + "timeoutMillis=" + timeoutMillis + "\n"
                + "expectedNonce=" + propertyValue(expectedNonce) + "\n"
                + "remote=" + propertyValue(safe.remote) + "\n"
                + "requestBytes=" + safe.requestBytes + "\n"
                + "responseBytes=" + safe.responseBytes + "\n"
                + "result=" + propertyValue(safe.result) + "\n"
                + "message=" + propertyValue(safe.message) + "\n";
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // Debug evidence must never change product control behavior.
        }
        backend.queryService(this);
    }

    private void writeDebugDownloadProbeResult(
            String url, int timeoutMillis, int maxBytes, DebugDownloadProbeResult result) {
        File file = new File(getFilesDir(), DEBUG_DOWNLOAD_PROBE_RESULT_PATH);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return;
        }
        double mbps = (result.bytes * 8.0)
                / Math.max(1.0, result.elapsedMillis / 1000.0) / 1_000_000.0;
        String text = "url=" + propertyValue(url) + "\n"
                + "timeoutMillis=" + timeoutMillis + "\n"
                + "maxBytes=" + maxBytes + "\n"
                + "uid=" + android.os.Process.myUid() + "\n"
                + "result=" + propertyValue(result.result) + "\n"
                + "bytes=" + result.bytes + "\n"
                + "elapsedMs=" + result.elapsedMillis + "\n"
                + "mbps=" + String.format(java.util.Locale.US, "%.2f", mbps) + "\n"
                + "message=" + propertyValue(result.message) + "\n";
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // Debug evidence must never change product control behavior.
        }
    }

    private void writeDebugL4PrefillResult(String host, int port, String result) {
        File file = new File(getFilesDir(), DEBUG_L4_PREFILL_RESULT_PATH);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return;
        }
        String text = "host=" + propertyValue(host) + "\n"
                + "port=" + port + "\n"
                + "result=" + (result != null && result.startsWith("L4 prefill: subject=")
                ? "available" : "unavailable") + "\n"
                + "summary=" + propertyValue(result) + "\n";
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // Debug evidence must never change product control behavior.
        }
    }

    private void exportReleaseDiagnostics() {
        RuntimeSnapshot runtime = backend.query(this);
        ProductCatalogFormatter.Projection projection = ProductCatalogProjectionStore.read(
                getFilesDir());
        AppDetail detail = ProductActivityProjectionStore.read(getFilesDir());
        ProductCatalogFormatter.EntryRow row = selectedApplicationRow();
        String text = ReleaseDiagnosticsExport.format(runtime, projection, detail, row,
                System.currentTimeMillis());
        File file = new File(getFilesDir(), DEBUG_RELEASE_DIAGNOSTICS_RESULT_PATH);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            action("Release diagnostics export failed: cannot create debug directory.");
            return;
        }
        try (FileOutputStream out = new FileOutputStream(file, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            action("Release diagnostics exported to "
                    + DEBUG_RELEASE_DIAGNOSTICS_RESULT_PATH + ".\n"
                    + "Privacy: " + ReleaseDiagnosticsExport.PRIVACY + ".\n"
                    + ReleaseDiagnosticsExport.feedbackSummary());
        } catch (IOException error) {
            action("Release diagnostics export failed: " + boundedError(error));
        }
    }

    private static String debugTrafficProbeResultCode(String result) {
        if ("tcp_echo_matched".equals(result)
                || (result != null && result.startsWith("Debug traffic probe echo matched"))) {
            return "tcp_echo_matched";
        }
        if ("tcp_echo_mismatch".equals(result)
                || (result != null && result.startsWith("Debug traffic probe echo mismatch"))) {
            return "tcp_echo_mismatch";
        }
        if ("tcp_connect_succeeded".equals(result)
                || (result != null && result.startsWith("Debug traffic probe connected"))) {
            return "tcp_connect_succeeded";
        }
        if ("tcp_connect_failed".equals(result)
                || (result != null && result.startsWith("Debug traffic probe failed"))) {
            return "tcp_connect_failed";
        }
        return "tcp_connect_unknown";
    }

    private static String propertyValue(String value) {
        return value == null ? "" : value.replace("\r", "\\r").replace("\n", "\\n");
    }

    private int boundedDownloadBytes(int candidate) {
        if (candidate < 1024 || candidate > 20_000_000) {
            return DEBUG_DOWNLOAD_MAX_BYTES;
        }
        return candidate;
    }

    private DebugListenerProbeResult runDebugTrafficListenerBlocking(
            String host, int port, int timeoutMillis, String expectedNonce) {
        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(InetAddress.getByName(host), port), 1);
            server.setSoTimeout(timeoutMillis);
            try (Socket socket = server.accept()) {
                if (expectedNonce == null || expectedNonce.isEmpty()) {
                    return new DebugListenerProbeResult(
                            "tcp_listener_accepted",
                            "Debug traffic listener accepted from "
                                    + socket.getRemoteSocketAddress() + " on port "
                                    + port + ".",
                            "", 0, 0, String.valueOf(socket.getRemoteSocketAddress()));
                }
                socket.setSoTimeout(timeoutMillis);
                byte[] expected = expectedNonce.getBytes(StandardCharsets.UTF_8);
                byte[] request = new byte[expected.length];
                int received = 0;
                InputStream in = socket.getInputStream();
                while (received < request.length) {
                    int count = in.read(request, received, request.length - received);
                    if (count < 0) {
                        break;
                    }
                    received += count;
                }
                OutputStream out = socket.getOutputStream();
                out.write(request, 0, received);
                out.flush();
                boolean matched = received == expected.length
                        && Arrays.equals(expected, request);
                return new DebugListenerProbeResult(
                        matched ? "tcp_echo_matched" : "tcp_echo_mismatch",
                        matched ? "Debug TCP listener echo matched."
                                : "Debug TCP listener echo mismatch.",
                        expectedNonce, received, received,
                        String.valueOf(socket.getRemoteSocketAddress()));
            }
        } catch (IOException error) {
            String message = "Debug traffic listener failed: "
                    + (error.getMessage() == null ? error.getClass().getSimpleName()
                    : error.getMessage());
            return new DebugListenerProbeResult(
                    "tcp_listener_failed", message, expectedNonce, 0, 0, "");
        } catch (RuntimeException error) {
            String message = "Debug traffic listener failed: " + error.getClass().getSimpleName();
            return new DebugListenerProbeResult(
                    "tcp_listener_failed", message, expectedNonce, 0, 0, "");
        }
    }

    private DebugListenerProbeResult runDebugUdpTrafficListenerBlocking(
            String host, int port, int timeoutMillis, String expectedNonce) {
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(InetAddress.getByName(host), port));
            socket.setSoTimeout(timeoutMillis);
            int capacity = expectedNonce == null || expectedNonce.isEmpty()
                    ? 512 : Math.max(expectedNonce.getBytes(StandardCharsets.UTF_8).length, 1);
            byte[] request = new byte[capacity];
            DatagramPacket packet = new DatagramPacket(request, request.length);
            socket.receive(packet);
            byte[] response = Arrays.copyOf(packet.getData(), packet.getLength());
            socket.send(new DatagramPacket(response, response.length,
                    packet.getAddress(), packet.getPort()));
            if (expectedNonce == null || expectedNonce.isEmpty()) {
                return new DebugListenerProbeResult(
                        "udp_datagram_received",
                        "Debug UDP listener received and echoed a datagram.",
                        "", packet.getLength(), response.length,
                        packet.getAddress().getHostAddress() + ":" + packet.getPort());
            }
            byte[] expected = expectedNonce.getBytes(StandardCharsets.UTF_8);
            boolean matched = packet.getLength() == expected.length
                    && Arrays.equals(expected, response);
            return new DebugListenerProbeResult(
                    matched ? "udp_echo_matched" : "udp_echo_mismatch",
                    matched ? "Debug UDP listener echo matched."
                            : "Debug UDP listener echo mismatch.",
                    expectedNonce, packet.getLength(), response.length,
                    packet.getAddress().getHostAddress() + ":" + packet.getPort());
        } catch (IOException error) {
            String message = "Debug UDP listener failed: "
                    + (error.getMessage() == null ? error.getClass().getSimpleName()
                    : error.getMessage());
            return new DebugListenerProbeResult(
                    "udp_listener_failed", message, expectedNonce, 0, 0, "");
        } catch (RuntimeException error) {
            String message = "Debug UDP listener failed: " + error.getClass().getSimpleName();
            return new DebugListenerProbeResult(
                    "udp_listener_failed", message, expectedNonce, 0, 0, "");
        }
    }

    private int boundedPort(int candidate, int fallback) {
        if (candidate <= 0 || candidate > 65535) {
            return fallback;
        }
        return candidate;
    }

    private int boundedOptionalPort(int candidate) {
        if (candidate < 0 || candidate > 65535) {
            return 0;
        }
        return candidate;
    }

    private int boundedTimeoutMillis(int candidate, int fallback) {
        if (candidate < 100 || candidate > 30000) {
            return fallback;
        }
        return candidate;
    }

    private String boundedNonce(String candidate) {
        if (candidate == null) {
            return "";
        }
        String value = candidate.replace('\r', '_').replace('\n', '_');
        if (value.length() > 128) {
            return value.substring(0, 128);
        }
        return value;
    }

    private String formatDebugPolicyProbeResult(
            int uid, RuntimeProfile profile, String host, int port, JSONObject decision,
            JSONObject countersBefore, JSONObject countersAfter, String probeResult) {
        String adapterLabel = debugPacketAdapterLabel(profile);
        String forwardedCounter = debugForwardedCounterName(profile);
        long packetDelta = countersAfter.optLong("packetsSeen", 0L)
                - countersBefore.optLong("packetsSeen", 0L);
        long forwardDelta = countersAfter.optLong(forwardedCounter, 0L)
                - countersBefore.optLong(forwardedCounter, 0L);
        long dropDelta = countersAfter.optLong("droppedPackets", 0L)
                - countersBefore.optLong("droppedPackets", 0L);
        return "Policy: verdict=" + decision.optString("verdict", "unknown")
                + " stage=" + decision.optString("stage", "unknown")
                + " revision=" + decision.optLong("revision", -1L)
                + " reason=" + decision.optLong("reasonId", -1L)
                + " rule=" + decision.optLong("ruleId", -1L)
                + "\n" + adapterLabel + ": targetUid=" + uid
                + " packetDelta=" + packetDelta
                + " forwardDelta=" + forwardDelta
                + " dropDelta=" + dropDelta
                + " lastObservedLinuxUid="
                + countersAfter.optLong("lastObservedLinuxUid", -1L)
                + " lastObservedResult="
                + countersAfter.optString("lastObservedResult", "unknown")
                + "\nPolicy drop activity: "
                + formatPolicyDropActivity(countersAfter.optJSONObject("policyDropActivity"))
                + "\nAllowed flow activity: "
                + formatAllowedFlowActivity(countersAfter.optJSONObject("allowedFlowActivity"))
                + "\n" + formatActivityL4Prefill(
                countersAfter.optJSONObject("policyDropActivity"))
                + "\nProbe: " + probeResult;
    }

    private String formatPolicyDropActivity(JSONObject activity) {
        if (activity == null || !activity.optBoolean("hasLastRecord", false)) {
            return "none";
        }
        return "records=" + activity.optLong("records", 0L)
                + "/" + activity.optLong("capacity", 0L)
                + " total=" + activity.optLong("totalRecords", 0L)
                + " evicted=" + activity.optLong("evictedRecords", 0L)
                + " uid=" + activity.optLong("lastLinuxUid", -1L)
                + " uidKnown=" + activity.optBoolean("lastUidKnown", false)
                + " context=" + activity.optLong("lastNetworkContext", -1L)
                + " remote=" + remoteEndpoint(activity)
                + " protocol=" + activity.optLong("lastIpProtocol", -1L)
                + " deviceDir=" + activity.optString("lastDeviceDirection", "unknown")
                + " stage=" + activity.optString("lastStage", "unknown")
                + " reason=" + activity.optLong("lastReasonId", -1L)
                + " rule=" + activity.optLong("lastRuleId", -1L)
                + " revision=" + activity.optLong("lastRevision", -1L);
    }

    private String formatAllowedFlowActivity(JSONObject activity) {
        if (activity == null || !activity.optBoolean("hasLastRecord", false)) {
            return "none";
        }
        return "records=" + activity.optLong("records", 0L)
                + "/" + activity.optLong("capacity", 0L)
                + " total=" + activity.optLong("totalRecords", 0L)
                + " evicted=" + activity.optLong("evictedRecords", 0L)
                + " uid=" + activity.optLong("lastLinuxUid", -1L)
                + " uidKnown=" + activity.optBoolean("lastUidKnown", false)
                + " context=" + activity.optLong("lastNetworkContext", -1L)
                + " remote=" + remoteEndpoint(activity)
                + " protocol=" + activity.optLong("lastIpProtocol", -1L)
                + " deviceDir=" + activity.optString("lastDeviceDirection", "unknown")
                + " flowDir=" + activity.optString("lastFlowDirection", "unknown")
                + " packets=" + activity.optLong("lastPackets", 0L)
                + " bytes=" + activity.optLong("lastBytes", 0L)
                + " revision=" + activity.optLong("lastPolicyRevision", -1L);
    }

    private String remoteEndpoint(JSONObject activity) {
        return remoteHost(activity) + ":" + remotePort(activity);
    }

    private String remoteHost(JSONObject activity) {
        boolean input = "input".equals(activity.optString("lastDeviceDirection", ""));
        return input ? activity.optString("lastSourceAddress", "")
                : activity.optString("lastDestinationAddress", "");
    }

    private int remotePort(JSONObject activity) {
        boolean input = "input".equals(activity.optString("lastDeviceDirection", ""));
        return (int) (input ? activity.optLong("lastSourcePort", 0L)
                : activity.optLong("lastDestinationPort", 0L));
    }

    private String formatActivityL4Prefill(JSONObject activity) {
        if (activity == null || !activity.optBoolean("hasLastRecord", false)) {
            return "L4 prefill: unavailable";
        }
        ActivityL4RuleDraft draft = ActivityL4RuleDraft.fromPolicyDropActivity(
                remoteHost(activity), remotePort(activity),
                (int) activity.optLong("lastIpProtocol", 0L),
                (int) activity.optLong("lastLinuxUid", -1L),
                activity.optBoolean("lastUidKnown", false),
                (int) activity.optLong("lastNetworkContext", -1L),
                activity.optString("lastStage", ""));
        return draft == null ? "L4 prefill: unavailable" : draft.summary();
    }

    private String boundedError(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.isEmpty()) {
            message = error.getClass().getSimpleName();
        }
        return BoundedText.value(message, 160);
    }

    private static final class ControlVNextDebugClient implements AutoCloseable {
        private final LocalSocket socket;
        private final InputStream input;
        private final OutputStream output;

        ControlVNextDebugClient() throws IOException {
            socket = new LocalSocket();
            socket.connect(new LocalSocketAddress(
                    CONTROL_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
            socket.setSoTimeout(CONTROL_SOCKET_TIMEOUT_MILLIS);
            input = socket.getInputStream();
            output = socket.getOutputStream();
        }

        JSONObject call(int id, String cmd, JSONObject args) throws IOException, JSONException {
            JSONObject request = new JSONObject()
                    .put("id", id)
                    .put("cmd", cmd)
                    .put("args", args);
            writeNetstring(request.toString().getBytes(StandardCharsets.UTF_8));
            JSONObject response = new JSONObject(
                    new String(readNetstring(), StandardCharsets.UTF_8));
            if (!response.optBoolean("ok", false)) {
                JSONObject error = response.optJSONObject("error");
                String code = error == null ? "RPC_FAILED" : error.optString("code", "RPC_FAILED");
                String message = error == null ? "" : error.optString("message", "");
                throw new IOException(cmd + " failed: " + code
                        + (message.isEmpty() ? "" : ": " + message));
            }
            JSONObject result = response.optJSONObject("result");
            return result == null ? new JSONObject() : result;
        }

        private void writeNetstring(byte[] payload) throws IOException {
            output.write(Integer.toString(payload.length).getBytes(StandardCharsets.US_ASCII));
            output.write(':');
            output.write(payload);
            output.write(',');
            output.flush();
        }

        private byte[] readNetstring() throws IOException {
            int length = readLength();
            byte[] payload = new byte[length];
            int offset = 0;
            while (offset < length) {
                int n = input.read(payload, offset, length - offset);
                if (n < 0) {
                    throw new IOException("control socket closed while reading payload");
                }
                offset += n;
            }
            int comma = input.read();
            if (comma != ',') {
                throw new IOException("invalid netstring terminator");
            }
            return payload;
        }

        private int readLength() throws IOException {
            int value = 0;
            int digits = 0;
            while (true) {
                int ch = input.read();
                if (ch < 0) {
                    throw new IOException("control socket closed while reading length");
                }
                if (ch == ':') {
                    if (digits == 0) {
                        throw new IOException("empty netstring length");
                    }
                    return value;
                }
                if (ch < '0' || ch > '9') {
                    throw new IOException("invalid netstring length");
                }
                if (digits == 0 && ch == '0') {
                    int next = input.read();
                    if (next != ':') {
                        throw new IOException("invalid leading zero netstring length");
                    }
                    return 0;
                }
                value = value * 10 + (ch - '0');
                digits++;
                if (value > CONTROL_MAX_PAYLOAD_BYTES || digits > 8) {
                    throw new IOException("netstring payload too large");
                }
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private void action(String text) {
        if (actionView != null) {
            actionView.setText(text);
        }
    }

    private LinearLayout.LayoutParams fillWrap() {
        return new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams weighted() {
        return new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static final class DebugVpnNetwork {
        final Network network;
        final long networkHandle;
        final DebugTrafficProbeBinding binding;

        private DebugVpnNetwork(Network network, long networkHandle,
                                DebugTrafficProbeBinding binding) {
            this.network = network;
            this.networkHandle = networkHandle;
            this.binding = binding;
        }

        static DebugVpnNetwork available(Network network, long networkHandle) {
            return new DebugVpnNetwork(network, networkHandle,
                    DebugTrafficProbeBinding.notAttempted());
        }

        static DebugVpnNetwork unavailable(String result, long networkHandle, String error) {
            return new DebugVpnNetwork(null, networkHandle,
                    DebugTrafficProbeBinding.failed(result, networkHandle, error));
        }

        boolean isAvailable() {
            return network != null;
        }
    }

    private static final class DebugTrafficProbeBinding {
        final String result;
        final long networkHandle;
        final String error;

        private DebugTrafficProbeBinding(String result, long networkHandle, String error) {
            this.result = result;
            this.networkHandle = networkHandle;
            this.error = error == null ? "" : error;
        }

        static DebugTrafficProbeBinding notRequested() {
            return new DebugTrafficProbeBinding("not_requested", -1L, "");
        }

        static DebugTrafficProbeBinding notAttempted() {
            return new DebugTrafficProbeBinding("not_attempted", -1L, "");
        }

        static DebugTrafficProbeBinding bound(long networkHandle) {
            return new DebugTrafficProbeBinding("bound", networkHandle, "");
        }

        static DebugTrafficProbeBinding failed(
                String result, long networkHandle, String error) {
            return new DebugTrafficProbeBinding(result, networkHandle, error);
        }

        boolean isBound() {
            return "bound".equals(result);
        }
    }

    private static final class DebugUdpTrafficProbeResult {
        final String result;
        final String message;
        final String bindResult;
        final long bindNetworkHandle;
        final String bindError;
        final String nonce;
        final int requestBytes;
        final int responseBytes;

        DebugUdpTrafficProbeResult(String result, String message,
                                   DebugTrafficProbeBinding binding) {
            this(result, message, binding, "", 0, 0);
        }

        DebugUdpTrafficProbeResult(String result, String message,
                                   DebugTrafficProbeBinding binding, String nonce,
                                   int requestBytes, int responseBytes) {
            this.result = result == null ? "udp_probe_unknown" : result;
            this.message = message == null ? "" : message;
            this.bindResult = binding == null ? "unknown" : binding.result;
            this.bindNetworkHandle = binding == null ? -1L : binding.networkHandle;
            this.bindError = binding == null ? "" : binding.error;
            this.nonce = nonce == null ? "" : nonce;
            this.requestBytes = Math.max(0, requestBytes);
            this.responseBytes = Math.max(0, responseBytes);
        }
    }

    private static final class DebugTrafficProbeResult {
        final String message;
        final String bindResult;
        final long bindNetworkHandle;
        final String bindError;
        final String nonce;
        final int requestBytes;
        final int responseBytes;

        DebugTrafficProbeResult(
                String message, String bindResult, long bindNetworkHandle, String bindError) {
            this(message, bindResult, bindNetworkHandle, bindError, "", 0, 0);
        }

        DebugTrafficProbeResult(
                String message, String bindResult, long bindNetworkHandle, String bindError,
                String nonce, int requestBytes, int responseBytes) {
            this.message = message;
            this.bindResult = bindResult == null ? "unknown" : bindResult;
            this.bindNetworkHandle = bindNetworkHandle;
            this.bindError = bindError == null ? "" : bindError;
            this.nonce = nonce == null ? "" : nonce;
            this.requestBytes = Math.max(0, requestBytes);
            this.responseBytes = Math.max(0, responseBytes);
        }
    }

    private static final class DebugListenerProbeResult {
        final String result;
        final String message;
        final String nonce;
        final int requestBytes;
        final int responseBytes;
        final String remote;

        DebugListenerProbeResult(
                String result, String message, String nonce, int requestBytes,
                int responseBytes, String remote) {
            this.result = result == null ? "listener_unknown" : result;
            this.message = message == null ? "" : message;
            this.nonce = nonce == null ? "" : nonce;
            this.requestBytes = Math.max(0, requestBytes);
            this.responseBytes = Math.max(0, responseBytes);
            this.remote = remote == null ? "" : remote;
        }
    }

    private static final class DebugDownloadProbeResult {
        final String result;
        final int bytes;
        final long elapsedMillis;
        final String message;

        DebugDownloadProbeResult(String result, int bytes, long elapsedMillis, String message) {
            this.result = result;
            this.bytes = bytes;
            this.elapsedMillis = elapsedMillis;
            this.message = message;
        }
    }
}
