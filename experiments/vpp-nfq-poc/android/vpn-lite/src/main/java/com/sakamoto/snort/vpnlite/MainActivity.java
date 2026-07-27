package com.sakamoto.snort.vpnlite;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
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
 * Historical VPN/HEV probes remain separate experiments and are not lifecycle
 * entry points from this exported Activity.</p>
 */
public final class MainActivity extends Activity {
    private static final int NOTIFICATION_REQUEST_CODE = 1002;
    private static final long STATUS_POLL_MILLIS = 500L;
    private static final String EXTRA_RUNTIME_START = "runtimeStart";
    private static final String EXTRA_RUNTIME_STOP = "runtimeStop";

    private final Handler main = new Handler(Looper.getMainLooper());
    private final LocalProductBackend productBackend = new LocalProductBackend();
    private TextView runtimeStatusView;
    private TextView actionStatusView;
    private boolean pendingRuntimeStart;

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
