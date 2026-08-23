package com.sakamoto.snort.vpnlite;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Temporary SAKAMOTO-46 acceptance shell.
 *
 * <p>The active surface deliberately crosses only {@link LocalProductBackend}.
 * Historical VPN/HEV probes remain separate experiments.  They are still
 * accepted as a compatibility control plane for source-owned POC harnesses, and
 * are bridged directly to {@link SnortVpnService} rather than to product
 * runtime lifecycle.</p>
 */
public final class MainActivity extends Activity {
    private static final int NOTIFICATION_REQUEST_CODE = 1002;
    private static final int VPN_REQUEST_CODE = 1003;
    private static final long STATUS_POLL_MILLIS = 500L;
    private static final String EXTRA_RUNTIME_START = "runtimeStart";
    private static final String EXTRA_RUNTIME_STOP = "runtimeStop";
    private static final String EXTRA_LEGACY_START = "start";
    private static final String EXTRA_LEGACY_STOP = "stop";
    private static final String EXTRA_LEGACY_HTTP_PROBE = "appHttpProbe";
    private static final String EXTRA_LEGACY_UDP_PROBE = "appUdpProbe";
    private static final String EXTRA_LEGACY_L4_STRESS_PROBE = "appL4StressProbe";
    private static final String EXTRA_LEGACY_PING_PROBE = "appPingProbe";
    private static final String EXTRA_LEGACY_CONTROL_PROBE = "controlProbe";
    private static final String EXTRA_LEGACY_RUST_CONTROL_PROBE = "rustControlProbe";
    private static final String EXTRA_LEGACY_RUST_RECONNECT_PROBE = "rustReconnectProbe";

    private final Handler main = new Handler(Looper.getMainLooper());
    private final LocalProductBackend productBackend = new LocalProductBackend();
    private TextView runtimeStatusView;
    private TextView actionStatusView;
    private boolean pendingRuntimeStart;
    private Intent pendingLegacyVpnIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());
        applyProductIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        applyProductIntent(intent);
    }

    private LinearLayout buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(16);
        root.setPadding(padding, padding, padding, padding);

        TextView title = new TextView(this);
        title.setText("Sakamoto Runtime Acceptance Shell");
        title.setTextSize(20);
        root.addView(title, fillWrap());

        runtimeStatusView = new TextView(this);
        runtimeStatusView.setTextSize(15);
        runtimeStatusView.setPadding(0, dp(12), 0, dp(12));
        root.addView(runtimeStatusView, fillWrap());

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);

        Button start = new Button(this);
        start.setAllCaps(false);
        start.setText("Start Protection");
        start.setOnClickListener(view -> requestStart());
        actions.addView(start, weight());

        Button stop = new Button(this);
        stop.setAllCaps(false);
        stop.setText("Stop Protection");
        stop.setOnClickListener(view -> requestStop());
        actions.addView(stop, weight());
        root.addView(actions, fillWrap());

        actionStatusView = new TextView(this);
        actionStatusView.setPadding(0, dp(12), 0, 0);
        root.addView(actionStatusView, fillWrap());
        refreshRuntimeStatus();
        return root;
    }

    private void applyProductIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.getBooleanExtra(EXTRA_RUNTIME_STOP, false)) {
            main.post(this::requestStop);
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_START, false)) {
            main.post(this::requestStart);
        } else if (applyLegacyPocIntent(intent)) {
            refreshRuntimeStatus();
        }
    }

    private boolean applyLegacyPocIntent(Intent intent) {
        if (intent.getBooleanExtra(SnortVpnService.EXTRA_UID_CONTRACT_REFRESH_APP, false)
                || intent.getBooleanExtra(SnortVpnService.EXTRA_UID_CONTRACT_REFRESH_NETWORK,
                        false)
                || intent.hasExtra(SnortVpnService.EXTRA_UID_CONTRACT_UNAVAILABLE)
                || intent.getBooleanExtra(SnortVpnService.EXTRA_UID_CONTRACT_REPLAY, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_UID_CONTRACT_CONTROL, intent);
            showAction("UID attribution contract control requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_STOP, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_STOP, intent);
            showAction("Legacy VPN/TUN POC stop requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_HTTP_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_HTTP_PROBE, intent);
            showAction("Legacy HTTP probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_UDP_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_UDP_PROBE, intent);
            showAction("Legacy UDP probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_L4_STRESS_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_L4_STRESS_PROBE, intent);
            showAction("POC-7 L4 stress probe requested.");
            return true;
        }
        if (intent.getBooleanExtra("appTcpProbe", false)) {
            startLegacyVpnService(SnortVpnService.ACTION_TCP_PROBE, intent);
            showAction("Legacy TCP probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_PING_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_PING_PROBE, intent);
            showAction("Legacy ping probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_CONTROL_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_CONTROL_PROBE, intent);
            showAction("Legacy VPP control probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_RUST_CONTROL_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_RUST_CONTROL_PROBE, intent);
            showAction("Legacy Rust control probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_RUST_RECONNECT_PROBE, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_RUST_RECONNECT_PROBE, intent);
            showAction("Legacy Rust reconnect probe requested.");
            return true;
        }
        if (intent.getBooleanExtra(EXTRA_LEGACY_START, false)) {
            startLegacyVpnService(SnortVpnService.ACTION_START, intent);
            showAction("Legacy VPN/TUN POC start requested.");
            return true;
        }
        return false;
    }

    private void startLegacyVpnService(String action, Intent source) {
        Intent serviceIntent = new Intent(this, SnortVpnService.class);
        serviceIntent.setAction(action);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_MODE);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_HOST);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_PATH);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_ALLOWED_PACKAGE);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_DISALLOWED_PACKAGE);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_BLOCK_IP4_DST);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_BLOCK_IP6_DST);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_PORT);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_COUNT);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_PAYLOAD_BYTES);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_SIZE);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_DURATION_SECONDS);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_BLOCK_OWNER_UID);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_REDIRECT_THREAD);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_ROUNDS);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_FLOWS);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_PROTOCOL);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_LOAD);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_S124_PATH);
        copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_S124_OBSERVE);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_BURST);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_WARMUP_SECONDS);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_STEADY_SECONDS);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_DRAIN_SECONDS);
        copyIntExtra(source, serviceIntent, SnortVpnService.EXTRA_RECONNECT_EVERY);
        copyBooleanExtra(source, serviceIntent, SnortVpnService.EXTRA_EXPECT_ECHO);
        copyBooleanExtra(source, serviceIntent, SnortVpnService.EXTRA_OWNER_CACHE);
        copyBooleanExtra(source, serviceIntent, SnortVpnService.EXTRA_ENABLE_IPV6);
        copyBooleanExtra(source, serviceIntent,
                SnortVpnService.EXTRA_UID_CONTRACT_REFRESH_APP);
        copyBooleanExtra(source, serviceIntent,
                SnortVpnService.EXTRA_UID_CONTRACT_REFRESH_NETWORK);
        copyBooleanExtra(source, serviceIntent,
                SnortVpnService.EXTRA_UID_CONTRACT_UNAVAILABLE);
        copyBooleanExtra(source, serviceIntent, SnortVpnService.EXTRA_UID_CONTRACT_REPLAY);
        if (!SnortVpnService.ACTION_STOP.equals(action)
                && !SnortVpnService.ACTION_UID_CONTRACT_CONTROL.equals(action)) {
            Intent prepare = VpnService.prepare(this);
            if (prepare != null) {
                pendingLegacyVpnIntent = serviceIntent;
                startActivityForResult(prepare, VPN_REQUEST_CODE);
                return;
            }
        }
        startService(serviceIntent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_REQUEST_CODE) {
            return;
        }
        Intent serviceIntent = pendingLegacyVpnIntent;
        pendingLegacyVpnIntent = null;
        if (resultCode == RESULT_OK && serviceIntent != null) {
            startService(serviceIntent);
            showAction("VPN permission granted; legacy POC starting.");
        } else {
            showAction("VPN permission denied; legacy POC not started.");
        }
    }

    private static void copyStringExtra(Intent source, Intent target, String name) {
        if (source.hasExtra(name)) {
            target.putExtra(name, source.getStringExtra(name));
        }
    }

    private static void copyIntExtra(Intent source, Intent target, String name) {
        if (source.hasExtra(name)) {
            target.putExtra(name, source.getIntExtra(name, 0));
        }
    }

    private static void copyBooleanExtra(Intent source, Intent target, String name) {
        if (source.hasExtra(name)) {
            target.putExtra(name, source.getBooleanExtra(name, false));
        }
    }

    private void requestStart() {
        LocalProductBackend.StartResult result = productBackend.startProtection(this);
        if (result == LocalProductBackend.StartResult.NOTIFICATION_REQUIRED) {
            pendingRuntimeStart = true;
            if (android.os.Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        NOTIFICATION_REQUEST_CODE);
            }
            showAction("Start requires the visible protection notification.");
            return;
        }
        showAction("Start requested.");
        refreshRuntimeStatus();
    }

    private void requestStop() {
        pendingRuntimeStart = false;
        productBackend.stopProtection(this);
        showAction("Stop requested.");
        refreshRuntimeStatus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshRuntimeStatus();
        main.postDelayed(runtimeStatusPoll, STATUS_POLL_MILLIS);
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
        showAction(granted ? "Notification permission granted."
                : "Notification permission denied; protection was not started.");
        if (granted && shouldStart) {
            requestStart();
        }
    }

    private final Runnable runtimeStatusPoll = new Runnable() {
        @Override
        public void run() {
            refreshRuntimeStatus();
            main.postDelayed(this, STATUS_POLL_MILLIS);
        }
    };

    private void refreshRuntimeStatus() {
        if (runtimeStatusView != null) {
            runtimeStatusView.setText(productBackend.getRuntimeSnapshot(this).displayText());
        }
    }

    private void showAction(String text) {
        if (actionStatusView != null) {
            actionStatusView.setText(text);
        }
    }

    private LinearLayout.LayoutParams fillWrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams weight() {
        return new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
