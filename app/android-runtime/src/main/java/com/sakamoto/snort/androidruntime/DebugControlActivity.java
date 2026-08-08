package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.TextView;

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
    private Spinner profileSpinner;
    private TextView statusView;
    private TextView actionView;
    private boolean pendingStart;
    /** Keeps an explicit user selection visible until the service publishes it. */
    private RuntimeProfile requestedProfile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());
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
                profileSpinner.setSelection(selected == RuntimeProfile.VPN ? 1 : 0);
            }
            main.post(this::startSelected);
        }
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(16);
        root.setPadding(padding, padding, padding, padding);

        TextView title = new TextView(this);
        title.setText("Sakamoto Debug Control");
        title.setTextSize(20);
        root.addView(title, fillWrap());

        profileSpinner = new Spinner(this);
        profileSpinner.setAdapter(new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_dropdown_item,
                new String[]{RuntimeProfile.ROOT.displayName, RuntimeProfile.VPN.displayName}));
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
        query.setOnClickListener(view -> refreshStatus());
        buttons.addView(query, weighted());
        root.addView(buttons, fillWrap());

        statusView = new TextView(this);
        statusView.setTextSize(15);
        statusView.setPadding(0, dp(12), 0, dp(8));
        root.addView(statusView, fillWrap());
        actionView = new TextView(this);
        root.addView(actionView, fillWrap());
        return root;
    }

    private void startSelected() {
        RuntimeProfile profile = profileSpinner.getSelectedItemPosition() == 1
                ? RuntimeProfile.VPN : RuntimeProfile.ROOT;
        requestedProfile = profile;
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
            if (requestedProfile == null && profileSpinner != null) {
                profileSpinner.setSelection(current.profile == RuntimeProfile.VPN ? 1 : 0);
            }
            statusView.setText(current.displayText());
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
