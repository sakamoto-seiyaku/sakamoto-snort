package com.sakamoto.snort.vpnlite;

import android.app.Activity;
import android.Manifest;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.content.pm.PackageManager;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST_CODE = 1001;
    private static final int NOTIFICATION_REQUEST_CODE = 1002;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final LocalProductBackend productBackend = new LocalProductBackend();
    private TextView logView;
    private TextView runtimeStatusView;
    private boolean pendingRuntimeStart;
    private String pendingMode = SnortVpnService.MODE_NATIVE;
    private String pendingAllowedPackage = "";
    private String pendingDisallowedPackage = "";
    private String pendingBlockIp4Dst = "";
    private String pendingBlockIp6Dst = "";
    private int pendingBlockOwnerUid = -1;
    private int pendingRedirectThread = -1;
    private boolean pendingOwnerCache = false;
    private boolean pendingEnableIpv6 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());
        applyIntentExtras(getIntent());
        appendLog("Snort VPN Lite Phase 1");
        appendLog("Start requests a full-route IPv4 VPN and reads packet headers only.");
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        applyIntentExtras(intent);
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(12);
        root.setPadding(pad, pad, pad, pad);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);

        Button start = new Button(this);
        start.setAllCaps(false);
        start.setText("Start VPN Probe");
        start.setOnClickListener(v -> startVpn(SnortVpnService.MODE_NATIVE));
        row.addView(start, weight());

        Button startVpp = new Button(this);
        startVpp.setAllCaps(false);
        startVpp.setText("Start VPP Runtime");
        startVpp.setOnClickListener(v -> startRuntimeService(false));
        row.addView(startVpp, weight());

        Button startHev = new Button(this);
        startHev.setAllCaps(false);
        startHev.setText("HEV");
        startHev.setOnClickListener(v -> startVpn(SnortVpnService.MODE_HEV));
        row.addView(startHev, weight());

        Button stop = new Button(this);
        stop.setAllCaps(false);
        stop.setText("Stop");
        stop.setOnClickListener(v -> {
            startRuntimeService(true);
            stopVpn();
        });
        row.addView(stop, weight());

        runtimeStatusView = new TextView(this);
        runtimeStatusView.setTextSize(15);
        runtimeStatusView.setText(productBackend.getRuntimeSnapshot(this).displayText());
        runtimeStatusView.setPadding(0, 0, 0, dp(12));
        root.addView(runtimeStatusView, fillWrap());
        root.addView(row, fillWrap());

        logView = new TextView(this);
        logView.setTextSize(13);
        logView.setTextIsSelectable(true);
        logView.setPadding(dp(8), dp(8), dp(8), dp(8));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(logView, fillWrap());
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1
        ));

        return root;
    }

    private void startVpn(String mode) {
        startVpn(mode, "", "", "", "", -1, -1, false, false);
    }

    private void startVpn(String mode, String allowedPackage, String disallowedPackage,
                          String blockIp4Dst, String blockIp6Dst, int blockOwnerUid,
                          int redirectThread, boolean ownerCache, boolean enableIpv6) {
        if (SnortVpnService.MODE_HEV.equals(mode)) {
            appendLog("starting HEV probe without VPN");
            startVpnService(mode, allowedPackage, disallowedPackage, blockIp4Dst,
                    blockIp6Dst, blockOwnerUid, redirectThread, ownerCache, enableIpv6);
            return;
        }

        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            appendLog("requesting VPN permission");
            pendingMode = mode;
            pendingAllowedPackage = allowedPackage;
            pendingDisallowedPackage = disallowedPackage;
            pendingBlockIp4Dst = blockIp4Dst;
            pendingBlockIp6Dst = blockIp6Dst;
            pendingBlockOwnerUid = blockOwnerUid;
            pendingRedirectThread = redirectThread;
            pendingOwnerCache = ownerCache;
            pendingEnableIpv6 = enableIpv6;
            startActivityForResult(prepare, VPN_REQUEST_CODE);
            return;
        }
        appendLog("VPN permission already granted");
        startVpnService(mode, allowedPackage, disallowedPackage, blockIp4Dst, blockIp6Dst,
                blockOwnerUid, redirectThread, ownerCache, enableIpv6);
    }

    private void stopVpn() {
        appendLog("stop requested");
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_STOP);
        startService(intent);
    }

    private void startAppHttpProbe(String host, int port, String path, int durationSeconds) {
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_HTTP_PROBE);
        intent.putExtra(SnortVpnService.EXTRA_HOST, host);
        intent.putExtra(SnortVpnService.EXTRA_PORT, port);
        intent.putExtra(SnortVpnService.EXTRA_PATH, path);
        intent.putExtra(SnortVpnService.EXTRA_DURATION_SECONDS, durationSeconds);
        startService(intent);
        appendLog("app HTTP probe requested: " + host + ":" + port + path);
    }

    private void startAppUdpProbe(String host, int port, int count, int durationSeconds,
                                  int payloadBytes) {
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_UDP_PROBE);
        intent.putExtra(SnortVpnService.EXTRA_HOST, host);
        intent.putExtra(SnortVpnService.EXTRA_PORT, port);
        intent.putExtra(SnortVpnService.EXTRA_COUNT, count);
        intent.putExtra(SnortVpnService.EXTRA_PAYLOAD_BYTES, payloadBytes);
        intent.putExtra(SnortVpnService.EXTRA_DURATION_SECONDS, durationSeconds);
        startService(intent);
        appendLog("app UDP probe requested: " + host + ":" + port + " count=" + count);
    }

    private void startAppPingProbe(String host, int size, int count) {
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_PING_PROBE);
        intent.putExtra(SnortVpnService.EXTRA_HOST, host);
        intent.putExtra(SnortVpnService.EXTRA_SIZE, size);
        intent.putExtra(SnortVpnService.EXTRA_COUNT, count);
        startService(intent);
        appendLog("app ping probe requested: " + host + " size=" + size
                + " count=" + count);
    }

    private void startVpnService(String mode) {
        startVpnService(mode, "", "", "", "", -1, -1, false, false);
    }

    private void startVpnService(String mode, String allowedPackage, String disallowedPackage,
                                 String blockIp4Dst, String blockIp6Dst, int blockOwnerUid,
                                 int redirectThread, boolean ownerCache, boolean enableIpv6) {
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_START);
        intent.putExtra(SnortVpnService.EXTRA_MODE, mode);
        intent.putExtra(SnortVpnService.EXTRA_ALLOWED_PACKAGE, allowedPackage);
        intent.putExtra(SnortVpnService.EXTRA_DISALLOWED_PACKAGE, disallowedPackage);
        intent.putExtra(SnortVpnService.EXTRA_BLOCK_IP4_DST, blockIp4Dst);
        intent.putExtra(SnortVpnService.EXTRA_BLOCK_IP6_DST, blockIp6Dst);
        intent.putExtra(SnortVpnService.EXTRA_BLOCK_OWNER_UID, blockOwnerUid);
        intent.putExtra(SnortVpnService.EXTRA_REDIRECT_THREAD, redirectThread);
        intent.putExtra(SnortVpnService.EXTRA_OWNER_CACHE, ownerCache);
        intent.putExtra(SnortVpnService.EXTRA_ENABLE_IPV6, enableIpv6);
        startService(intent);
        appendLog("service start requested: " + mode);
    }

    private void applyIntentExtras(Intent intent) {
        if (intent != null && intent.getBooleanExtra("runtimeStart", false)) {
            appendLog("intent runtimeStart=true");
            main.postDelayed(() -> startRuntimeService(false), 300);
        }

        if (intent != null && intent.getBooleanExtra("runtimeStop", false)) {
            appendLog("intent runtimeStop=true");
            main.postDelayed(() -> startRuntimeService(true), 300);
        }

        if (intent != null && intent.getBooleanExtra("stop", false)) {
            appendLog("intent stop=true");
            main.postDelayed(this::stopVpn, 300);
            return;
        }

        if (intent != null && intent.getBooleanExtra("appHttpProbe", false)) {
            String host = intent.getStringExtra(SnortVpnService.EXTRA_HOST);
            if (host == null || host.isEmpty()) {
                host = "93.184.216.34";
            }
            int port = intent.getIntExtra(SnortVpnService.EXTRA_PORT, 80);
            String path = intent.getStringExtra(SnortVpnService.EXTRA_PATH);
            int durationSeconds = intent.getIntExtra(SnortVpnService.EXTRA_DURATION_SECONDS, 0);
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            String requestedHost = host;
            String requestedPath = path;
            appendLog("intent appHttpProbe=true host=" + host + " port=" + port
                    + " path=" + path);
            main.postDelayed(() -> startAppHttpProbe(requestedHost, port, requestedPath,
                    durationSeconds), 300);
        }

        if (intent != null && intent.getBooleanExtra("appUdpProbe", false)) {
            String host = intent.getStringExtra(SnortVpnService.EXTRA_HOST);
            if (host == null || host.isEmpty()) {
                host = "8.8.8.8";
            }
            int port = intent.getIntExtra(SnortVpnService.EXTRA_PORT, 53);
            int count = intent.getIntExtra(SnortVpnService.EXTRA_COUNT, 1);
            int payloadBytes = intent.getIntExtra(SnortVpnService.EXTRA_PAYLOAD_BYTES, 0);
            int durationSeconds = intent.getIntExtra(SnortVpnService.EXTRA_DURATION_SECONDS, 0);
            String requestedHost = host;
            appendLog("intent appUdpProbe=true host=" + host + " port=" + port
                    + " count=" + count);
            main.postDelayed(() -> startAppUdpProbe(requestedHost, port, count, durationSeconds,
                    payloadBytes), 300);
        }

        if (intent != null && intent.getBooleanExtra("appPingProbe", false)) {
            String host = intent.getStringExtra(SnortVpnService.EXTRA_HOST);
            if (host == null || host.isEmpty()) {
                host = "1.1.1.1";
            }
            int size = intent.getIntExtra(SnortVpnService.EXTRA_SIZE, 4000);
            int count = intent.getIntExtra(SnortVpnService.EXTRA_COUNT, 1);
            String requestedHost = host;
            appendLog("intent appPingProbe=true host=" + host + " size=" + size
                    + " count=" + count);
            main.postDelayed(() -> startAppPingProbe(requestedHost, size, count), 300);
        }

        if (intent != null && intent.getBooleanExtra("controlProbe", false)) {
            int blockOwnerUid = intent.getIntExtra(SnortVpnService.EXTRA_BLOCK_OWNER_UID, -1);
            int rounds = intent.getIntExtra(SnortVpnService.EXTRA_ROUNDS, 1);
            appendLog("intent controlProbe=true blockOwnerUid=" + blockOwnerUid
                    + " rounds=" + rounds);
            Intent control = new Intent(this, SnortVpnService.class);
            control.setAction(SnortVpnService.ACTION_CONTROL_PROBE);
            control.putExtra(SnortVpnService.EXTRA_BLOCK_OWNER_UID, blockOwnerUid);
            control.putExtra(SnortVpnService.EXTRA_ROUNDS, rounds);
            main.postDelayed(() -> startService(control), 300);
        }

        if (intent != null && intent.getBooleanExtra("rustControlProbe", false)) {
            int blockOwnerUid = intent.getIntExtra(SnortVpnService.EXTRA_BLOCK_OWNER_UID, -1);
            int rounds = intent.getIntExtra(SnortVpnService.EXTRA_ROUNDS, 1);
            appendLog("intent rustControlProbe=true blockOwnerUid=" + blockOwnerUid
                    + " rounds=" + rounds);
            Intent control = new Intent(this, SnortVpnService.class);
            control.setAction(SnortVpnService.ACTION_RUST_CONTROL_PROBE);
            control.putExtra(SnortVpnService.EXTRA_BLOCK_OWNER_UID, blockOwnerUid);
            control.putExtra(SnortVpnService.EXTRA_ROUNDS, rounds);
            main.postDelayed(() -> startService(control), 300);
        }

        if (intent != null && intent.getBooleanExtra("rustReconnectProbe", false)) {
            int timeoutSeconds = intent.getIntExtra(SnortVpnService.EXTRA_DURATION_SECONDS, 60);
            appendLog("intent rustReconnectProbe=true timeoutSeconds=" + timeoutSeconds);
            Intent reconnect = new Intent(this, SnortVpnService.class);
            reconnect.setAction(SnortVpnService.ACTION_RUST_RECONNECT_PROBE);
            reconnect.putExtra(SnortVpnService.EXTRA_DURATION_SECONDS, timeoutSeconds);
            main.postDelayed(() -> startService(reconnect), 300);
        }

        if (intent != null && intent.getBooleanExtra("start", false)) {
            String mode = intent.getStringExtra(SnortVpnService.EXTRA_MODE);
            if (mode == null) {
                mode = SnortVpnService.MODE_NATIVE;
            }
            appendLog("intent start=true mode=" + mode);
            String requestedMode = mode;
            String allowedPackage = intent.getStringExtra(SnortVpnService.EXTRA_ALLOWED_PACKAGE);
            if (allowedPackage == null) {
                allowedPackage = "";
            }
            String disallowedPackage = intent.getStringExtra(
                    SnortVpnService.EXTRA_DISALLOWED_PACKAGE);
            if (disallowedPackage == null) {
                disallowedPackage = "";
            }
            String blockIp4Dst = intent.getStringExtra(SnortVpnService.EXTRA_BLOCK_IP4_DST);
            if (blockIp4Dst == null) {
                blockIp4Dst = "";
            }
            String blockIp6Dst = intent.getStringExtra(SnortVpnService.EXTRA_BLOCK_IP6_DST);
            if (blockIp6Dst == null) {
                blockIp6Dst = "";
            }
            boolean enableIpv6 = intent.getBooleanExtra(SnortVpnService.EXTRA_ENABLE_IPV6,
                    false);
            int blockOwnerUid = intent.getIntExtra(SnortVpnService.EXTRA_BLOCK_OWNER_UID, -1);
            int redirectThread = intent.getIntExtra(SnortVpnService.EXTRA_REDIRECT_THREAD, -1);
            boolean ownerCache = intent.getBooleanExtra(SnortVpnService.EXTRA_OWNER_CACHE, false);
            String requestedAllowedPackage = allowedPackage;
            String requestedDisallowedPackage = disallowedPackage;
            String requestedBlockIp4Dst = blockIp4Dst;
            String requestedBlockIp6Dst = blockIp6Dst;
            main.postDelayed(() -> startVpn(requestedMode, requestedAllowedPackage,
                    requestedDisallowedPackage, requestedBlockIp4Dst, requestedBlockIp6Dst,
                    blockOwnerUid, redirectThread, ownerCache, enableIpv6), 300);
        }
    }

    private void startRuntimeService(boolean stop) {
        if (!stop && !SnortRuntimeService.notificationsReady(this)) {
            pendingRuntimeStart = true;
            if (android.os.Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        NOTIFICATION_REQUEST_CODE);
            }
            appendLog("runtime start blocked: notification permission required");
            return;
        }
        if (stop) {
            productBackend.stopProtection(this);
        } else {
            productBackend.startProtection(this);
        }
        appendLog(stop ? "runtime stop requested" : "runtime start requested");
        refreshRuntimeStatus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshRuntimeStatus();
        main.postDelayed(runtimeStatusPoll, 500L);
    }

    @Override
    protected void onPause() {
        main.removeCallbacks(runtimeStatusPoll);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        main.removeCallbacks(runtimeStatusPoll);
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode != NOTIFICATION_REQUEST_CODE) {
            return;
        }
        boolean granted = results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED;
        boolean shouldStart = pendingRuntimeStart;
        pendingRuntimeStart = false;
        appendLog(granted ? "notification permission granted" : "notification permission denied");
        if (granted && shouldStart) {
            startRuntimeService(false);
        }
    }

    private final Runnable runtimeStatusPoll = new Runnable() {
        @Override
        public void run() {
            refreshRuntimeStatus();
            main.postDelayed(this, 500L);
        }
    };

    private void refreshRuntimeStatus() {
        if (runtimeStatusView != null) {
            runtimeStatusView.setText(productBackend.getRuntimeSnapshot(this).displayText());
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_REQUEST_CODE) {
            return;
        }
        if (resultCode == RESULT_OK) {
            appendLog("VPN permission granted");
            startVpnService(pendingMode, pendingAllowedPackage, pendingDisallowedPackage,
                    pendingBlockIp4Dst, pendingBlockIp6Dst, pendingBlockOwnerUid,
                    pendingRedirectThread, pendingOwnerCache, pendingEnableIpv6);
        } else {
            appendLog("VPN permission denied: result=" + resultCode);
        }
        pendingMode = SnortVpnService.MODE_NATIVE;
        pendingAllowedPackage = "";
        pendingDisallowedPackage = "";
        pendingBlockIp4Dst = "";
        pendingBlockIp6Dst = "";
        pendingBlockOwnerUid = -1;
        pendingRedirectThread = -1;
        pendingOwnerCache = false;
        pendingEnableIpv6 = false;
    }

    private void appendLog(String line) {
        String now = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        String text = now + " " + line + "\n";
        main.post(() -> logView.append(text));
    }

    private LinearLayout.LayoutParams fillWrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
    }

    private LinearLayout.LayoutParams weight() {
        return new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
