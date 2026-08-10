package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.util.List;

/** Minimal debug shell. It only issues versioned requests and renders snapshots. */
public class DebugControlActivity extends Activity {
    private static final int NOTIFICATION_PERMISSION = 1001;
    private static final long STATUS_POLL_MILLIS = 500L;
    private static final String EXTRA_RUNTIME_START = "runtimeStart";
    private static final String EXTRA_RUNTIME_STOP = "runtimeStop";
    private static final String EXTRA_RUNTIME_PROFILE = "runtimeProfile";
    private static final String EXTRA_RUNTIME_CLEANUP_FAULT = "runtimeCleanupFault";

    private final RuntimeControlBackend backend = new RuntimeControlBackend();
    private final Handler main = new Handler(Looper.getMainLooper());
    private LocalProductBackend productBackend;
    private Spinner profileSpinner;
    private TextView statusView;
    private TextView actionView;
    private TextView productView;
    private Button bindFirstButton;
    private Button unbindFirstButton;
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
        productBackend = new LocalProductBackend(getFilesDir(),
                new PackageManagerApplicationCatalogProvider(this));
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
        setProfileSpinnerSelection(productBackend.productState().selectedProfile);
        profileSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (suppressProfileSelectionPersist) {
                    return;
                }
                persistSelectedProductProfile(profileFromSpinner(), "Product profile selected");
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
        root.addView(buttons, fillWrap());

        LinearLayout productButtons = new LinearLayout(this);
        bindFirstButton = new Button(this);
        bindFirstButton.setText("Bind first app");
        bindFirstButton.setAllCaps(false);
        bindFirstButton.setOnClickListener(view -> bindFirstAvailableApplication());
        productButtons.addView(bindFirstButton, weighted());
        unbindFirstButton = new Button(this);
        unbindFirstButton.setText("Unbind first");
        unbindFirstButton.setAllCaps(false);
        unbindFirstButton.setOnClickListener(view -> unbindFirstApplication());
        productButtons.addView(unbindFirstButton, weighted());
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
        persistSelectedProductProfile(profile, "Product profile selected for start");
        RuntimeControlBackend.StartResult result = backend.start(this, profile);
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

    private void persistSelectedProductProfile(RuntimeProfile profile, String successPrefix) {
        ProductStore.MutationResult result = productBackend.selectRuntimeProfile(profile);
        if (result.persisted) {
            action(successPrefix + ": " + profile.wireName + ".");
            renderProductProjection(ProductCatalogFormatter.loading(result.snapshot));
            refreshProductCatalog();
            return;
        }
        action("Product profile write failed: "
                + (result.errorCode.isEmpty() ? "product_state_persistence_failed"
                : result.errorCode)
                + (result.errorMessage.isEmpty() ? "" : ": " + result.errorMessage));
        refreshProductCatalog();
    }

    private void refreshProductCatalog() {
        if (productBackend == null || productView == null) {
            return;
        }
        final int generation = ++productCatalogGeneration;
        renderProductProjection(ProductCatalogFormatter.loading(productBackend.productState()));
        Thread loader = new Thread(() -> {
            try {
                List<ApplicationCatalogEntry> catalog = productBackend.applicationCatalog();
                ProductStateSnapshot productState = productBackend.productState();
                ProductCatalogFormatter.Projection projection =
                        ProductCatalogFormatter.result(productState, catalog);
                main.post(() -> {
                    if (generation == productCatalogGeneration) {
                        renderProductProjection(projection);
                    }
                });
            } catch (RuntimeException error) {
                ProductCatalogFormatter.Projection projection = ProductCatalogFormatter.error(
                        productBackend.productState(), "catalog_load_failed",
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
        if (bindFirstButton != null) {
            bindFirstButton.setEnabled(projection.firstAvailableSubjectId != null);
        }
        if (unbindFirstButton != null) {
            unbindFirstButton.setEnabled(projection.firstBoundSubjectId != null);
        }
    }

    private void bindFirstAvailableApplication() {
        ApplicationSubjectId subjectId = productProjection.firstAvailableSubjectId;
        if (subjectId == null) {
            action("No available catalog app to bind.");
            return;
        }
        ProductStore.MutationResult result = productBackend.bindApplication(subjectId);
        if (result.persisted) {
            action("Bound application subject " + subjectId.encode() + ".");
        } else {
            action("Bind failed: " + (result.errorCode.isEmpty()
                    ? "product_state_persistence_failed" : result.errorCode)
                    + (result.errorMessage.isEmpty() ? "" : ": " + result.errorMessage));
        }
        refreshProductCatalog();
    }

    private void unbindFirstApplication() {
        ApplicationSubjectId subjectId = productProjection.firstBoundSubjectId;
        if (subjectId == null) {
            action("No bound application subject to unbind.");
            return;
        }
        ProductStore.MutationResult result = productBackend.unbindApplication(subjectId);
        if (result.persisted) {
            action("Unbound application subject " + subjectId.encode() + ".");
        } else {
            action("Unbind failed: " + (result.errorCode.isEmpty()
                    ? "product_state_persistence_failed" : result.errorCode)
                    + (result.errorMessage.isEmpty() ? "" : ": " + result.errorMessage));
        }
        refreshProductCatalog();
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
