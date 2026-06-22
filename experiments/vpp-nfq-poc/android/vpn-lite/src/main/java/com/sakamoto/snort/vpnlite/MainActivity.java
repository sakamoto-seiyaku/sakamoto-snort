package com.sakamoto.snort.vpnlite;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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

    private final Handler main = new Handler(Looper.getMainLooper());
    private TextView logView;
    private String pendingMode = SnortVpnService.MODE_NATIVE;

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
        startVpp.setText("Start VPP");
        startVpp.setOnClickListener(v -> startVpn(SnortVpnService.MODE_VPP));
        row.addView(startVpp, weight());

        Button stop = new Button(this);
        stop.setAllCaps(false);
        stop.setText("Stop");
        stop.setOnClickListener(v -> stopVpn());
        row.addView(stop, weight());

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
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            appendLog("requesting VPN permission");
            pendingMode = mode;
            startActivityForResult(prepare, VPN_REQUEST_CODE);
            return;
        }
        appendLog("VPN permission already granted");
        startVpnService(mode);
    }

    private void stopVpn() {
        appendLog("stop requested");
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_STOP);
        startService(intent);
    }

    private void startVpnService(String mode) {
        Intent intent = new Intent(this, SnortVpnService.class);
        intent.setAction(SnortVpnService.ACTION_START);
        intent.putExtra(SnortVpnService.EXTRA_MODE, mode);
        startService(intent);
        appendLog("service start requested: " + mode);
    }

    private void applyIntentExtras(Intent intent) {
        if (intent != null && intent.getBooleanExtra("start", false)) {
            String mode = intent.getStringExtra(SnortVpnService.EXTRA_MODE);
            if (mode == null) {
                mode = SnortVpnService.MODE_NATIVE;
            }
            appendLog("intent start=true mode=" + mode);
            String requestedMode = mode;
            main.postDelayed(() -> startVpn(requestedMode), 300);
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
            startVpnService(pendingMode);
        } else {
            appendLog("VPN permission denied: result=" + resultCode);
        }
        pendingMode = SnortVpnService.MODE_NATIVE;
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
