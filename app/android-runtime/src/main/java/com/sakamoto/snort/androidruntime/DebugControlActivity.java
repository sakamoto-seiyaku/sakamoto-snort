package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
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
import java.util.List;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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
    private static final long STATUS_POLL_MILLIS = 500L;
    private static final String EXTRA_RUNTIME_START = "runtimeStart";
    private static final String EXTRA_RUNTIME_STOP = "runtimeStop";
    private static final String EXTRA_RUNTIME_PROFILE = "runtimeProfile";
    private static final String EXTRA_RUNTIME_CLEANUP_FAULT = "runtimeCleanupFault";
    private static final String EXTRA_DEBUG_TRAFFIC = "debugTraffic";
    private static final String EXTRA_DEBUG_TRAFFIC_HOST = "debugTrafficHost";
    private static final String EXTRA_DEBUG_TRAFFIC_PORT = "debugTrafficPort";
    private static final String EXTRA_DEBUG_TRAFFIC_TIMEOUT_MILLIS =
            "debugTrafficTimeoutMillis";
    private static final String EXTRA_DEBUG_APPLY_GATE_AND_PROBE = "debugApplyGateAndProbe";
    private static final String EXTRA_DEBUG_LISTEN = "debugListen";
    private static final String EXTRA_DEBUG_LISTEN_PORT = "debugListenPort";
    private static final String EXTRA_DEBUG_LISTEN_TIMEOUT_MILLIS =
            "debugListenTimeoutMillis";
    private static final String DEBUG_TRAFFIC_HOST = "1.1.1.1";
    private static final int DEBUG_TRAFFIC_PORT = 80;
    private static final int DEBUG_TRAFFIC_TIMEOUT_MILLIS = 1000;
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
    private ApplicationCatalogProvider catalogProvider;
    private Spinner profileSpinner;
    private TextView statusView;
    private TextView actionView;
    private TextView productView;
    private Spinner appSpinner;
    private ImageView selectedAppIcon;
    private Button bindSelectedButton;
    private Button unbindSelectedButton;
    private boolean suppressAppSelection;
    private ApplicationSubjectId selectedApplicationSubjectId;
    private boolean pendingStart;
    private boolean suppressProfileSelectionPersist;
    private int productCatalogGeneration;
    private ProductCatalogFormatter.Projection productProjection =
            ProductCatalogFormatter.loading(ProductStateSnapshot.empty());
    /** Keeps an explicit user selection visible until the service publishes it. */
    private RuntimeProfile requestedProfile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        catalogProvider = new PackageManagerApplicationCatalogProvider(this);
        setContentView(buildUi());
        refreshProductCatalog();
        refreshStatus();
        applyControlIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        applyControlIntent(intent);
    }

    private void applyControlIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.hasExtra(EXTRA_RUNTIME_CLEANUP_FAULT)) {
            backend.setCleanupFault(this,
                    intent.getBooleanExtra(EXTRA_RUNTIME_CLEANUP_FAULT, false));
        }
        if (intent.getBooleanExtra(EXTRA_RUNTIME_STOP, false)) {
            main.post(this::stopRuntime);
        } else if (intent.getBooleanExtra(EXTRA_RUNTIME_START, false)) {
            String profile = intent.getStringExtra(EXTRA_RUNTIME_PROFILE);
            if (profileSpinner != null && profile != null) {
                RuntimeProfile selected = RuntimeProfile.VPN.wireName.equalsIgnoreCase(profile)
                        ? RuntimeProfile.VPN : RuntimeProfile.ROOT;
                requestedProfile = selected;
                setProfileSpinnerSelection(selected);
            }
            main.post(this::startSelected);
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_TRAFFIC, false)) {
            String host = intent.getStringExtra(EXTRA_DEBUG_TRAFFIC_HOST);
            if (host == null || host.isEmpty()) {
                host = DEBUG_TRAFFIC_HOST;
            }
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_TRAFFIC_PORT, DEBUG_TRAFFIC_PORT), DEBUG_TRAFFIC_PORT);
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_TRAFFIC_TIMEOUT_MILLIS, DEBUG_TRAFFIC_TIMEOUT_MILLIS),
                    DEBUG_TRAFFIC_TIMEOUT_MILLIS);
            final String probeHost = host;
            final int probePort = port;
            final int probeTimeoutMillis = timeoutMillis;
            main.post(() -> runDebugTrafficProbe(
                    probeHost, probePort, probeTimeoutMillis));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_LISTEN, false)) {
            int port = boundedPort(intent.getIntExtra(
                    EXTRA_DEBUG_LISTEN_PORT, DEBUG_LISTEN_PORT), DEBUG_LISTEN_PORT);
            int timeoutMillis = boundedTimeoutMillis(intent.getIntExtra(
                    EXTRA_DEBUG_LISTEN_TIMEOUT_MILLIS, DEBUG_LISTEN_TIMEOUT_MILLIS),
                    DEBUG_LISTEN_TIMEOUT_MILLIS);
            main.post(() -> runDebugTrafficListener(port, timeoutMillis));
        }
        if (intent.getBooleanExtra(EXTRA_DEBUG_APPLY_GATE_AND_PROBE, false)) {
            main.post(this::runDebugApplyGateAndProbe);
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
        setProfileSpinnerSelection(ProductStateStore.read(getFilesDir()).selectedProfile);
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
        root.addView(productButtons, fillWrap());

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
        RuntimeProfile profile = profileFromSpinner();
        requestedProfile = profile;
        RuntimeControlBackend.StartResult result;
        try {
            result = backend.start(this, profile);
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
        backend.stop(this);
        action("Stop requested.");
        refreshStatus();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // SAKAMOTO-67 VPN is an app-UID core profile; TUN authorization is a
        // later adapter seam and is intentionally not requested here.
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
            statusView.setText(current.displayText());
        }
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

    private void refreshProductCatalog() {
        if (catalogProvider == null || productView == null) {
            return;
        }
        final int generation = ++productCatalogGeneration;
        ProductStateStore.ReadResult initialState = ProductStateStore.readResult(getFilesDir());
        renderProductProjection(ProductCatalogFormatter.loading(initialState));
        Thread loader = new Thread(() -> {
            try {
                List<ApplicationCatalogEntry> catalog = catalogProvider.listApplications();
                ProductStateStore.ReadResult productState =
                        ProductStateStore.readResult(getFilesDir());
                ProductCatalogFormatter.Projection projection =
                        ProductCatalogFormatter.result(productState, catalog);
                main.post(() -> {
                    if (generation == productCatalogGeneration) {
                        renderProductProjection(projection);
                    }
                });
            } catch (RuntimeException error) {
                ProductCatalogFormatter.Projection projection = ProductCatalogFormatter.error(
                        ProductStateStore.readResult(getFilesDir()), "catalog_load_failed",
                        error.getMessage() == null ? "catalog could not be loaded"
                                : error.getMessage());
                main.post(() -> {
                    if (generation == productCatalogGeneration) {
                        renderProductProjection(projection);
                    }
                });
            }
        }, "sakamoto-product-catalog");
        loader.start();
    }

    private void renderProductProjection(ProductCatalogFormatter.Projection projection) {
        productProjection = projection;
        if (productView != null) {
            productView.setText(projection.displayText);
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

    private void runDebugTrafficProbe() {
        runDebugTrafficProbe(DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT,
                DEBUG_TRAFFIC_TIMEOUT_MILLIS);
    }

    private void runDebugTrafficProbe(String host, int port, int timeoutMillis) {
        action("Debug traffic probe requested.");
        Thread probe = new Thread(() -> {
            String result = runDebugTrafficProbeBlocking(
                    host, port, timeoutMillis, true);
            final String display = result;
            main.post(() -> action(display));
        }, "sakamoto-debug-traffic");
        probe.start();
    }

    private void runDebugTrafficListener(int port, int timeoutMillis) {
        action("Debug traffic listener requested on 0.0.0.0:" + port + ".");
        Thread listener = new Thread(() -> {
            String result = runDebugTrafficListenerBlocking(port, timeoutMillis);
            final String display = result;
            main.post(() -> action(display));
        }, "sakamoto-debug-listener");
        listener.start();
    }

    private void runDebugApplyGateAndProbe() {
        action("Debug policy gate/probe requested.");
        Thread probe = new Thread(() -> {
            String result;
            try (ControlVNextDebugClient client = new ControlVNextDebugClient()) {
                int uid = android.os.Process.myUid();
                client.call(1, "POLICY.APPLY", debugPolicyApplyArgs(uid));
                JSONObject decision = client.call(2, "POLICY.EVALUATE",
                        debugPolicyEvaluateArgs(uid));
                JSONObject nfqueueBefore = client.call(3, "NFQUEUE.STATUS", new JSONObject());
                String probeResult = runDebugTrafficProbeBlocking(
                        DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT,
                        DEBUG_TRAFFIC_TIMEOUT_MILLIS, false);
                JSONObject nfqueueAfter = client.call(4, "NFQUEUE.STATUS", new JSONObject());
                result = formatDebugPolicyProbeResult(
                        uid, decision, nfqueueBefore, nfqueueAfter, probeResult);
            } catch (IOException | JSONException | RuntimeException error) {
                result = "Debug policy gate/probe failed: " + boundedError(error);
            }
            final String display = result;
            main.post(() -> action(display));
        }, "sakamoto-debug-policy-probe");
        probe.start();
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

    private String runDebugTrafficProbeBlocking(
            String host, int port, int timeoutMillis, boolean includeEndpoint) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMillis);
            if (includeEndpoint) {
                return "Debug traffic probe connected to "
                        + host + ":" + port + ".";
            }
            return "tcp_connect_succeeded";
        } catch (IOException error) {
            if (includeEndpoint) {
                return "Debug traffic probe failed: "
                        + (error.getMessage() == null
                        ? error.getClass().getSimpleName()
                        : error.getMessage());
            }
            return "tcp_connect_failed";
        } catch (RuntimeException error) {
            if (includeEndpoint) {
                return "Debug traffic probe failed: "
                        + error.getClass().getSimpleName();
            }
            return "tcp_connect_failed";
        }
    }

    private String runDebugTrafficListenerBlocking(int port, int timeoutMillis) {
        try (ServerSocket server = new ServerSocket(port)) {
            server.setSoTimeout(timeoutMillis);
            try (Socket socket = server.accept()) {
                return "Debug traffic listener accepted from "
                        + socket.getRemoteSocketAddress() + " on port " + port + ".";
            }
        } catch (IOException error) {
            return "Debug traffic listener failed: "
                    + (error.getMessage() == null
                    ? error.getClass().getSimpleName()
                    : error.getMessage());
        } catch (RuntimeException error) {
            return "Debug traffic listener failed: "
                    + error.getClass().getSimpleName();
        }
    }

    private int boundedPort(int candidate, int fallback) {
        if (candidate <= 0 || candidate > 65535) {
            return fallback;
        }
        return candidate;
    }

    private int boundedTimeoutMillis(int candidate, int fallback) {
        if (candidate < 100 || candidate > 30000) {
            return fallback;
        }
        return candidate;
    }

    private String formatDebugPolicyProbeResult(
            int uid, JSONObject decision, JSONObject nfqueueBefore,
            JSONObject nfqueueAfter, String probeResult) {
        long packetDelta = nfqueueAfter.optLong("packetsSeen", 0L)
                - nfqueueBefore.optLong("packetsSeen", 0L);
        long acceptDelta = nfqueueAfter.optLong("acceptedPackets", 0L)
                - nfqueueBefore.optLong("acceptedPackets", 0L);
        long dropDelta = nfqueueAfter.optLong("droppedPackets", 0L)
                - nfqueueBefore.optLong("droppedPackets", 0L);
        return "Policy: verdict=" + decision.optString("verdict", "unknown")
                + " stage=" + decision.optString("stage", "unknown")
                + " revision=" + decision.optLong("revision", -1L)
                + " reason=" + decision.optLong("reasonId", -1L)
                + " rule=" + decision.optLong("ruleId", -1L)
                + "\nNFQUEUE: targetUid=" + uid
                + " packetDelta=" + packetDelta
                + " acceptDelta=" + acceptDelta
                + " dropDelta=" + dropDelta
                + " lastObservedLinuxUid="
                + nfqueueAfter.optLong("lastObservedLinuxUid", -1L)
                + " lastObservedResult="
                + nfqueueAfter.optString("lastObservedResult", "unknown")
                + "\nProbe: " + probeResult;
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
}
