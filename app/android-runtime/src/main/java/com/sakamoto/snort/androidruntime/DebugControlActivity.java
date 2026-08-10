package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
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
import java.net.Socket;
import java.io.IOException;

/** Minimal debug shell. It only issues versioned requests and renders snapshots. */
public class DebugControlActivity extends Activity {
    private static final int NOTIFICATION_PERMISSION = 1001;
    private static final long STATUS_POLL_MILLIS = 500L;
    private static final String EXTRA_RUNTIME_START = "runtimeStart";
    private static final String EXTRA_RUNTIME_STOP = "runtimeStop";
    private static final String EXTRA_RUNTIME_PROFILE = "runtimeProfile";
    private static final String EXTRA_RUNTIME_CLEANUP_FAULT = "runtimeCleanupFault";
    private static final String EXTRA_DEBUG_TRAFFIC = "debugTraffic";
    private static final String DEBUG_TRAFFIC_HOST = "1.1.1.1";
    private static final int DEBUG_TRAFFIC_PORT = 80;
    private static final int DEBUG_TRAFFIC_TIMEOUT_MILLIS = 1000;

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
            main.post(this::runDebugTrafficProbe);
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
        action("Debug traffic probe requested.");
        Thread probe = new Thread(() -> {
            String result;
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(
                        DEBUG_TRAFFIC_HOST, DEBUG_TRAFFIC_PORT),
                        DEBUG_TRAFFIC_TIMEOUT_MILLIS);
                result = "Debug traffic probe connected to "
                        + DEBUG_TRAFFIC_HOST + ":" + DEBUG_TRAFFIC_PORT + ".";
            } catch (IOException error) {
                result = "Debug traffic probe failed: "
                        + (error.getMessage() == null
                        ? error.getClass().getSimpleName()
                        : error.getMessage());
            } catch (RuntimeException error) {
                result = "Debug traffic probe failed: "
                        + error.getClass().getSimpleName();
            }
            final String display = result;
            main.post(() -> action(display));
        }, "sakamoto-debug-traffic");
        probe.start();
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
