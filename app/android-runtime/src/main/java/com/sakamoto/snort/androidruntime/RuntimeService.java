package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Sole Android lifecycle authority for one profile-owned VPP runtime.
 *
 * <p>The Activity sends only versioned product requests. This service owns
 * profile selection, foreground visibility, core-runtime health, process
 * supervision, and cleanup. It intentionally remains alive when the Activity
 * is closed or recreated.</p>
 */
public final class RuntimeService extends VpnService {
    public static final String ACTION_START = RuntimeControlProtocol.ACTION_START;
    public static final String ACTION_QUERY = RuntimeControlProtocol.ACTION_QUERY;
    public static final String ACTION_STOP = RuntimeControlProtocol.ACTION_STOP;
    public static final String ACTION_PROTECTION_PAUSE =
            RuntimeControlProtocol.ACTION_PROTECTION_PAUSE;
    public static final String ACTION_PROTECTION_RESUME =
            RuntimeControlProtocol.ACTION_PROTECTION_RESUME;
    public static final String ACTION_PRODUCT_PROFILE_SELECT =
            RuntimeControlProtocol.ACTION_PRODUCT_PROFILE_SELECT;
    public static final String ACTION_PRODUCT_BIND_APP =
            RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP;
    public static final String ACTION_PRODUCT_UNBIND_APP =
            RuntimeControlProtocol.ACTION_PRODUCT_UNBIND_APP;
    public static final String ACTION_PRODUCT_SET_NETWORK_GATE =
            RuntimeControlProtocol.ACTION_PRODUCT_SET_NETWORK_GATE;
    public static final String ACTION_PRODUCT_SET_L4_RULE =
            RuntimeControlProtocol.ACTION_PRODUCT_SET_L4_RULE;
    public static final String ACTION_PRODUCT_APPLY_EMPTY_POLICY =
            RuntimeControlProtocol.ACTION_PRODUCT_APPLY_EMPTY_POLICY;

    private static final String TAG = "SakamotoRuntimeService";
    private static final String SU_PATH = "/system/bin/su";
    private static final String VPP_BINARY = "libvpp_runtime.so";
    private static final String PRODUCT_MANIFEST_ASSET = "product-stage.properties";
    private static final String PRODUCT_PLUGIN_BINARY = "libproduct_core_plugin.so";
    private static final String PRODUCT_ROOT_NFQUEUE_QUEUE = "176";
    private static final String PRODUCT_ROOT_NFQUEUE_QUEUE_LAST = "176";
    private static final String PRODUCT_ROOT_NFQUEUE_LANES = "1";
    private static final String PRODUCT_ROOT_NFQUEUE_CHAIN = "SAKAMOTO_PRODUCT_S176_OUTPUT";
    private static final String PRODUCT_ROOT_NFQUEUE_INPUT_CHAIN = "SAKAMOTO_PRODUCT_S178_INPUT";
    private static final int PRODUCT_ROOT_NFQUEUE_HOOK_INSTALL_ATTEMPTS = 3;
    private static final long PRODUCT_ROOT_NFQUEUE_HOOK_INSTALL_RETRY_MILLIS = 250L;
    private static final String PRODUCT_CORE_GENERATION_STATE =
            "product-state/product-core-generation.properties";
    private static final String S176_ROOT_NFQUEUE_OUTPUT_STATUS =
            "product-state/s176-root-nfqueue-output.properties";
    private static final String S176_ROOT_NFQUEUE_CLEANUP_STATUS =
            "product-state/s176-root-nfqueue-cleanup.properties";
    private static final String S177_ROOT_NFQUEUE_MULTILANE_STATUS =
            "product-state/s177-root-nfqueue-multilane.properties";
    private static final String S178_ROOT_NFQUEUE_MATRIX_STATUS =
            "product-state/s178-root-nfqueue-matrix.properties";
    private static final String S179_ROOT_FAULT_RECOVERY_STATUS =
            "product-state/s179-root-fault-recovery.properties";
    private static final String S180_VPN_UDP4_DIRECT_EGRESS_STATUS =
            "product-state/s180-vpn-udp4-direct-egress.properties";
    private static final String S181_VPN_TCP4_DIRECT_EGRESS_STATUS =
            "product-state/s181-vpn-tcp4-direct-egress.properties";
    private static final String S182_VPN_UDP6_DIRECT_EGRESS_STATUS =
            "product-state/s182-vpn-udp6-direct-egress.properties";
    private static final String S183_VPN_TCP6_DIRECT_EGRESS_STATUS =
            "product-state/s183-vpn-tcp6-direct-egress.properties";
    private static final String S184_VPN_NETWORK_EPOCH_STATUS =
            "product-state/s184-vpn-network-epoch.properties";
    private static final String S185_VPN_FAULT_RECOVERY_STATUS =
            "product-state/s185-vpn-fault-recovery.properties";
    private static final String S186_PROFILE_SWITCH_BARRIER_STATUS =
            "product-state/s186-profile-switch-barrier.properties";
    private static final String S187_WORKER_CORE_GUARDRAILS_STATUS =
            "product-state/s187-worker-core-guardrails.properties";
    private static final String S188_EMPTY_POLICY_SNAPSHOT_STATUS =
            "product-state/s188-empty-policy-snapshot.properties";
    private static final String S189_ROOT_NETWORK_GATE_STATUS =
            "product-state/s189-root-network-gate.properties";
    private static final String S190_VPN_NETWORK_GATE_STATUS =
            "product-state/s190-vpn-network-gate.properties";
    private static final String S191_ROOT_L4_STATUS =
            "product-state/s191-root-tcp4-l4.properties";
    private static final String S192_ROOT_VPN_L4_MATRIX_STATUS =
            "product-state/s192-root-vpn-l4-matrix.properties";
    private static final String S194_PRODUCT_MUTATION_STATUS =
            "product-state/s194-product-mutation.properties";
    private static final String S194_POLICY_MUTATION_FAULT_STATUS =
            "debug/policy-mutation-fault.properties";
    private static final String PRODUCT_CORE_MAIN_CORE = "0";
    private static final String PRODUCT_CORE_WORKER_COUNT = "2";
    private static final String PRODUCT_CORE_WORKER_CORES = "1-2";
    private static final String PRODUCT_CORE_WORKER0_CORE = "1";
    private static final String PRODUCT_CORE_WORKER1_CORE = "2";
    private static final String PRODUCT_CORE_OWNER_MAPPING =
            "single-runtime-owner";
    private static final String PRODUCT_CORE_OWNER_MAPPING_SEED =
            "generation";
    private static final String DEBUG_TRAFFIC_PROBE_RESULT =
            "debug/traffic-probe.properties";
    private static final String DEBUG_UDP_TRAFFIC_PROBE_RESULT =
            "debug/udp-traffic-probe.properties";
    private static final String CHANNEL_ID = "sakamoto-runtime";
    private static final int NOTIFICATION_ID = 6701;
    private static final int HEALTH_ATTEMPTS = 80;
    private static final long HEALTH_RETRY_MILLIS = 250L;
    private static final long STOP_TERM_MILLIS = 1500L;
    private static final long STOP_KILL_MILLIS = 1500L;
    private static final int PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE = 1;
    private static final int PRODUCT_POLICY_WINNER_L4 = 2;
    private static final int PRODUCT_POLICY_VERDICT_PASS_NEXT = 1;
    private static final int PRODUCT_POLICY_VERDICT_DROP = 2;
    private static final int PRODUCT_L4_DIRECTION_INPUT = 1;
    private static final int PRODUCT_L4_DIRECTION_OUTPUT = 3;
    private static final int PRODUCT_DEVICE_DIRECTION_INPUT = 1;
    private static final int PRODUCT_DEVICE_DIRECTION_OUTPUT = 3;
    private static final int PRODUCT_L4_IP_FAMILY_IPV4 = 4;
    private static final int PRODUCT_L4_IP_FAMILY_IPV6 = 6;
    private static final int PRODUCT_L4_IP_PROTOCOL_TCP = 6;
    private static final int PRODUCT_L4_IP_PROTOCOL_UDP = 17;
    private static final int PRODUCT_L4_EVALUATION_MATCH = 1;
    private static final int PRODUCT_L4_EVALUATION_NO_MATCH = 2;
    private static final long PRODUCT_UINT32_MAX = 0xffffffffL;
    private static final long OWNERSHIP_RETRY_MILLIS = 50L;
    private static final int OWNERSHIP_RETRY_ATTEMPTS = 2;
    private static final int ROOT_COMMAND_UNAVAILABLE = -125;
    /**
     * Android can create the replacement service before the old instance's
     * asynchronous onDestroy callback runs.  Only the latest instance may
     * perform cross-profile residue cleanup.
     */
    private static volatile RuntimeService activeServiceInstance;
    private static final Object SERVICE_INSTANCE_LOCK = new Object();

    /** Android instantiates the production service through the no-arg path. */
    public RuntimeService() {
        this(RuntimeStateStore.defaultWriter());
    }

    /**
     * Host/instrumentation seam for deterministic durable-projection failure
     * injection. The lifecycle still owns all Android side effects; only the
     * filesystem publication boundary is replaceable.
     */
    public RuntimeService(RuntimeStateStore.Writer stateWriter) {
        this.persistenceGate = new RuntimeStateStore.PersistenceGate(stateWriter,
                RuntimeSnapshot.stopped());
    }

    private final Object stateLock = new Object();
    private final ExecutorService lifecycle = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(8), runnable -> {
                Thread thread = new Thread(runnable, "sakamoto-runtime-lifecycle");
                thread.setDaemon(false);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());
    /** Coalesce Activity polling while one bounded generated-VAPI query runs. */
    private final AtomicBoolean healthQueryScheduled = new AtomicBoolean();
    /** Monotonic bounded evidence revision for explicit QUERY requests. */
    private final AtomicLong healthQueryRevision = new AtomicLong();
    /** Reject delayed START/STOP intents before they can mutate lifecycle state. */
    private final RuntimeControlOrdering controlOrdering = new RuntimeControlOrdering();
    private final RuntimeStateStore.PersistenceGate persistenceGate;
    private volatile boolean stopRequested;
    private volatile boolean foregroundStarted;
    private volatile boolean destroying;
    private volatile boolean serviceInstanceSuperseded;
    private volatile boolean cleanupFaultInjected;
    private volatile String rootNfqueueFaultMode = "";
    private volatile String vpnFaultMode = "";
    private volatile int latestStartId;
    private RuntimeSnapshot snapshot;
    private LocalProductBackend productBackend;
    private Process vppProcess;
    private RuntimeControlNative.Session productCoreSession;
    private String productVppRevision = "";
    private String productArtifactId = "";
    private String productApiIdentity = "";
    private int productAbiVersion = -1;
    private int productApiVersion = -1;
    private String productVppBinarySha256 = "";
    private String productCoreConnectFailureCode = "";
    private String productCoreConnectFailureMessage = "";
    private VpnTunPlatformSession vpnTunSession;
    private VpnHevTransportSession vpnHevSession;
    private VpnDirectUdp4TransportSession vpnDirectUdp4Session;
    private VpnDirectUdp6TransportSession vpnDirectUdp6Session;
    private VpnDirectTcp4TransportSession vpnDirectTcp4Session;
    private VpnDirectTcp6TransportSession vpnDirectTcp6Session;
    private volatile long vpnDirectUnderlayEpoch = -1L;
    private volatile String vpnDirectUnderlayTransport = "";
    private volatile long vpnDirectUnderlayNetworkHandle = -1L;
    private volatile long vpnDirectUdp4NetworkHandle = -1L;
    private volatile long vpnDirectUdp6NetworkHandle = -1L;
    private volatile long vpnDirectTcp4NetworkHandle = -1L;
    private volatile long vpnDirectTcp6NetworkHandle = -1L;
    private volatile String lastVpnFaultEvent = "";
    private volatile long lastVpnFaultInfrastructureFaults = -1L;
    private volatile long lastVpnFaultDuplicateOrStaleDrops = -1L;
    private volatile boolean lastVpnFaultTunReady;
    private volatile boolean lastVpnFaultTransportFdAttached;
    private RuntimeProfile activeProfile;
    private File profileRoot;
    private File pidFile;
    private File runtimeLog;
    private long generation;
    /**
     * Latest successful Network Gate apply stage used by generic status refreshes.
     * The binding is lifecycle-owned and never crosses a profile, generation, or
     * policy revision boundary.
     */
    private String lastNetworkGateEvidenceStage = "";
    private RuntimeProfile lastNetworkGateEvidenceProfile;
    private long lastNetworkGateEvidenceGeneration = -1L;
    private long lastNetworkGateEvidenceRevision = -1L;
    /**
     * S192 probe evidence is deliberately in-memory and bounded.  A probe
     * result is useful only when the next native status observes a counter
     * transition in the same Product Core generation/revision/snapshot.
     */
    private final Object s192EvidenceLock = new Object();
    private boolean s192ObservedStatus;
    private long s192ObservedGeneration;
    private long s192ObservedPolicyGeneration;
    private long s192ObservedPolicyRevision;
    private long s192ObservedSnapshotHash;
    private String s192ObservedSnapshotIdentity = "";
    private String s192ObservedProbeIdentity = "";
    private long s192ObservedMatchRecords;
    private long s192ObservedNoMatchRecords;
    private long s192ObservedDropRecords;
    private boolean s192ProbeEpochFallbackCandidate;
    private boolean s192PolicyBaselineKnown;
    private long s192PolicyBaselineMatchRecords;
    private long s192PolicyBaselineNoMatchRecords;
    private long s192PolicyBaselineDropRecords;
    private boolean s192ProbeBaselineKnown;
    private long s192ProbeBaselineMatchRecords;
    private long s192ProbeBaselineNoMatchRecords;
    private long s192ProbeBaselineDropRecords;
    private RuntimeProfile lastNativePolicyDropActivityProfile;
    private long lastNativePolicyDropActivityGeneration = -1L;
    private long lastNativePolicyDropActivityTotalRecords;
    private RuntimeProfile lastNativeAllowedFlowActivityProfile;
    private long lastNativeAllowedFlowActivityGeneration = -1L;
    private long lastNativeAllowedFlowActivityTotalRecords;

    @Override
    public void onCreate() {
        super.onCreate();
        RuntimeService previousInstance;
        synchronized (SERVICE_INSTANCE_LOCK) {
            previousInstance = activeServiceInstance;
            activeServiceInstance = this;
            if (previousInstance != null && previousInstance != this) {
                previousInstance.serviceInstanceSuperseded = true;
                previousInstance.stopRequested = true;
            }
        }
        if (previousInstance != null && previousInstance != this) {
            previousInstance.appendLog("runtime_service_instance=superseded");
        }
        createNotificationChannel();
        RuntimeStateStore.ReadResult durable = RuntimeStateStore.readResult(getFilesDir());
        productBackend = new LocalProductBackend(getFilesDir(),
                new PackageManagerApplicationCatalogProvider(this),
                this::applyCommittedProductPolicy);
        snapshot = durable.snapshot;
        persistenceGate.setSnapshot(snapshot);
        generation = snapshot.generation;
        activeProfile = snapshot.profile;
        initializeProfilePaths(activeProfile);
        enqueueLifecycle(() -> refreshProductCatalogProjection("service_create"));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        latestStartId = Math.max(latestStartId, startId);
        String action = intent == null ? ACTION_QUERY : intent.getAction();
        if (action == null) {
            action = ACTION_QUERY;
        }
        if (!isSupportedAction(action)) {
            final String rejectedAction = action;
            enqueueLifecycle(() -> publishError("unsupported_runtime_action",
                    "unknown runtime action: " + rejectedAction,
                    currentMayBeActive(), currentPid()));
            return START_NOT_STICKY;
        }
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_ACTION)
                && !action.equals(intent.getStringExtra(RuntimeControlProtocol.EXTRA_ACTION))) {
            enqueueLifecycle(() -> publishError("runtime_action_mismatch",
                    "intent action and versioned action disagree", currentMayBeActive(), currentPid()));
            return START_NOT_STICKY;
        }
        int protocolVersion = intent == null ? RuntimeControlProtocol.VERSION
                : intent.getIntExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION, -1);
        if (protocolVersion != RuntimeControlProtocol.VERSION) {
            enqueueLifecycle(() -> publishError("unsupported_control_protocol",
                    "expected " + RuntimeControlProtocol.NAME, currentMayBeActive(), currentPid()));
            return START_STICKY;
        }
        if (destroying
                && (ACTION_START.equals(action) || ACTION_PROTECTION_RESUME.equals(action))) {
            repostStartAfterDestroy(intent, action);
            return START_STICKY;
        }

        long requestTimeMillis = intent == null ? 0L
                : intent.getLongExtra(RuntimeControlProtocol.EXTRA_REQUEST_TIME_MILLIS, 0L);
        if (ACTION_START.equals(action) || ACTION_STOP.equals(action)
                || ACTION_PROTECTION_PAUSE.equals(action)
                || ACTION_PROTECTION_RESUME.equals(action)) {
            RuntimeControlOrdering.Decision ordering = controlOrdering.observe(
                    requestTimeMillis, startId);
            if (ordering == RuntimeControlOrdering.Decision.STALE) {
                appendLog("ignored stale " + action + " request=" + requestTimeMillis
                        + " latest=" + controlOrdering.latestRequestTimeMillis()
                        + " latestStartId=" + controlOrdering.latestRequestStartId());
                return START_NOT_STICKY;
            }
        }
        RuntimeProfile requested = null;
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_PROFILE)) {
            try {
                requested = RuntimeProfile.parse(
                        intent.getStringExtra(RuntimeControlProtocol.EXTRA_PROFILE));
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_runtime_profile", error.getMessage(),
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }
        ApplicationSubjectId requestedSubject = null;
        if (intent != null
                && intent.hasExtra(RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT)) {
            try {
                requestedSubject = ApplicationSubjectId.parse(intent.getStringExtra(
                        RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT));
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_application_subject",
                        error.getMessage(), currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }
        AuthoringPolicyBundle.NetworkContextId requestedNetworkContext = null;
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_NETWORK_CONTEXT)) {
            try {
                requestedNetworkContext = AuthoringPolicyBundle.NetworkContextId.parse(
                        intent.getStringExtra(RuntimeControlProtocol.EXTRA_NETWORK_CONTEXT));
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_network_context",
                        error.getMessage(), currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }
        final boolean requestedNetworkGateBlocked = intent != null
                && intent.getBooleanExtra(RuntimeControlProtocol.EXTRA_NETWORK_GATE_BLOCKED,
                        false);

        if (ACTION_START.equals(action) || ACTION_PROTECTION_RESUME.equals(action)) {
            // A user retry is an explicit new lifecycle transaction. Clear a
            // stale active error synchronously so queued health polls cannot
            // make a still-pending retry look permanently failed. The
            // serialized start/reconciliation audit remains authoritative and
            // will immediately republish a fail-closed error if ownership is
            // still ambiguous or cleanup still fails.
            markExplicitStartPending();
            // A valid start request is authoritative over any delayed stop
            // from an Activity instance that has already been replaced.
            stopRequested = false;
        }

        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_CLEANUP_FAULT)) {
            final boolean enabled = intent.getBooleanExtra(
                    RuntimeControlProtocol.EXTRA_CLEANUP_FAULT, false);
            enqueueLifecycle(() -> setCleanupFault(enabled));
        }
        if (intent != null
                && intent.hasExtra(RuntimeControlProtocol.EXTRA_ROOT_NFQUEUE_FAULT_MODE)) {
            final String mode = intent.getStringExtra(
                    RuntimeControlProtocol.EXTRA_ROOT_NFQUEUE_FAULT_MODE);
            enqueueLifecycle(() -> setRootNfqueueFaultMode(mode));
        }
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_VPN_FAULT_MODE)) {
            final String mode = intent.getStringExtra(
                    RuntimeControlProtocol.EXTRA_VPN_FAULT_MODE);
            enqueueLifecycle(() -> setVpnFaultMode(mode));
        }
        final boolean hasVpnFaultEvent = intent != null
                && intent.hasExtra(RuntimeControlProtocol.EXTRA_VPN_FAULT_EVENT);
        if (hasVpnFaultEvent) {
            final String event = intent.getStringExtra(
                    RuntimeControlProtocol.EXTRA_VPN_FAULT_EVENT);
            enqueueLifecycle(() -> handleVpnFaultEvent(event));
        }
        if (intent != null
                && intent.hasExtra(RuntimeControlProtocol.EXTRA_POLICY_MUTATION_FAULT_MODE)) {
            final String mode = intent.getStringExtra(
                    RuntimeControlProtocol.EXTRA_POLICY_MUTATION_FAULT_MODE);
            enqueueLifecycle(() -> setPolicyMutationFaultMode(mode));
        }

        if (ACTION_STOP.equals(action)) {
            stopRequested = true;
            enqueueLifecycle(this::stopRuntime);
            return START_NOT_STICKY;
        }
        if (ACTION_PROTECTION_PAUSE.equals(action)) {
            stopRequested = true;
            enqueueLifecycle(this::pauseProtection);
            return START_NOT_STICKY;
        }
        if (ACTION_PRODUCT_PROFILE_SELECT.equals(action)) {
            if (requested == null) {
                enqueueLifecycle(() -> publishError("invalid_product_profile_request",
                        "product profile selection requires a runtime profile",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final RuntimeProfile profile = requested;
            enqueueLifecycle(() -> selectProductProfile(profile));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_BIND_APP.equals(action)) {
            if (requestedSubject == null) {
                enqueueLifecycle(() -> publishError("invalid_product_bind_request",
                        "product app bind requires an application subject",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final ApplicationSubjectId subject = requestedSubject;
            enqueueLifecycle(() -> bindProductApplication(subject));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_UNBIND_APP.equals(action)) {
            if (requestedSubject == null) {
                enqueueLifecycle(() -> publishError("invalid_product_unbind_request",
                        "product app unbind requires an application subject",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final ApplicationSubjectId subject = requestedSubject;
            enqueueLifecycle(() -> unbindProductApplication(subject));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_SET_NETWORK_GATE.equals(action)) {
            if (requestedSubject == null || requestedNetworkContext == null) {
                enqueueLifecycle(() -> publishError("invalid_product_network_gate_request",
                        "Network Gate mutation requires an application subject and network context",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final ApplicationSubjectId subject = requestedSubject;
            final AuthoringPolicyBundle.NetworkContextId context = requestedNetworkContext;
            enqueueLifecycle(() -> setProductNetworkGate(
                    subject, context, requestedNetworkGateBlocked));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_SET_L4_RULE.equals(action)) {
            final AuthoringPolicyBundle.L4Rule rule;
            try {
                rule = parseL4RuleIntent(intent, requestedSubject, requestedNetworkContext);
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_product_l4_rule_request",
                        error.getMessage(), currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            enqueueLifecycle(() -> setProductL4Rule(rule));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_APPLY_EMPTY_POLICY.equals(action)) {
            enqueueLifecycle(this::applyProductEmptyPolicy);
            return START_STICKY;
        }
        if (ACTION_START.equals(action)) {
            final RuntimeProfile profile = requested == null ? activeProfile : requested;
            if (!ensureForeground(profile)) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            enqueueLifecycle(() -> startRuntime(profile));
            return START_STICKY;
        }
        if (ACTION_PROTECTION_RESUME.equals(action)) {
            final RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT
                    : activeProfile;
            if (!ensureForeground(profile)) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            enqueueLifecycle(() -> startRuntime(profile));
            return START_STICKY;
        }
        if (hasVpnFaultEvent && ACTION_QUERY.equals(action)) {
            return START_STICKY;
        }
        // QUERY is a public health request. It must reconcile the durable
        // owner and issue a bounded generated-VAPI show_version call even
        // when this service already monitors the same PID.
        if (currentMayBeActive() && !ensureForeground(activeProfile)) {
            return START_NOT_STICKY;
        }
        queueHealthQuery(startId);
        return START_STICKY;
    }

    private static boolean isSupportedAction(String action) {
        return ACTION_START.equals(action)
                || ACTION_QUERY.equals(action)
                || ACTION_STOP.equals(action)
                || ACTION_PROTECTION_PAUSE.equals(action)
                || ACTION_PROTECTION_RESUME.equals(action)
                || ACTION_PRODUCT_PROFILE_SELECT.equals(action)
                || ACTION_PRODUCT_BIND_APP.equals(action)
                || ACTION_PRODUCT_UNBIND_APP.equals(action)
                || ACTION_PRODUCT_SET_NETWORK_GATE.equals(action)
                || ACTION_PRODUCT_SET_L4_RULE.equals(action)
                || ACTION_PRODUCT_APPLY_EMPTY_POLICY.equals(action);
    }

    private static AuthoringPolicyBundle.L4Rule parseL4RuleIntent(
            Intent intent, ApplicationSubjectId subjectId,
            AuthoringPolicyBundle.NetworkContextId context) {
        if (intent == null || subjectId == null) {
            throw new IllegalArgumentException("L4 rule mutation requires an application subject");
        }
        AuthoringPolicyBundle.IpFamily family = AuthoringPolicyBundle.IpFamily.parse(
                requiredStringExtra(intent, RuntimeControlProtocol.EXTRA_L4_FAMILY));
        String sourceCidr = intent.getStringExtra(RuntimeControlProtocol.EXTRA_L4_SOURCE_CIDR);
        String destinationCidr = intent.getStringExtra(
                RuntimeControlProtocol.EXTRA_L4_DESTINATION_CIDR);
        int ipProtocol = intent.getIntExtra(
                RuntimeControlProtocol.EXTRA_L4_IP_PROTOCOL, -1);
        AuthoringPolicyBundle.PacketDirection direction =
                AuthoringPolicyBundle.PacketDirection.parse(requiredStringExtra(
                        intent, RuntimeControlProtocol.EXTRA_L4_PACKET_DIRECTION));
        AuthoringPolicyBundle.L4Action action = AuthoringPolicyBundle.L4Action.parse(
                requiredStringExtra(intent, RuntimeControlProtocol.EXTRA_L4_ACTION));
        int priority = intent.getIntExtra(RuntimeControlProtocol.EXTRA_L4_PRIORITY, 0);
        int order = intent.getIntExtra(RuntimeControlProtocol.EXTRA_L4_ORDER, 0);
        return AuthoringPolicyBundle.L4Rule.create(subjectId, family, sourceCidr,
                destinationCidr, portRangeExtra(intent,
                        RuntimeControlProtocol.EXTRA_L4_SOURCE_PORT_FIRST,
                        RuntimeControlProtocol.EXTRA_L4_SOURCE_PORT_LAST),
                portRangeExtra(intent,
                        RuntimeControlProtocol.EXTRA_L4_DESTINATION_PORT_FIRST,
                        RuntimeControlProtocol.EXTRA_L4_DESTINATION_PORT_LAST),
                ipProtocol, direction, context, action, priority, order);
    }

    private static String requiredStringExtra(Intent intent, String name) {
        String value = intent.getStringExtra(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("missing " + name);
        }
        return value;
    }

    private static AuthoringPolicyBundle.PortRange portRangeExtra(
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

    private void queueHealthQuery(int requestStartId) {
        long revision = healthQueryRevision.incrementAndGet();
        appendLog("health_query=request revision=" + revision + " startId=" + requestStartId);
        if (!healthQueryScheduled.compareAndSet(false, true)) {
            appendLog("health_query=coalesced revision=" + revision);
            return;
        }
        if ((productCoreSession != null && productCoreSession.isConnected())
                || processAlive(vppProcess)) {
            if (!enqueueLifecycle(() -> {
                try {
                    queryProductCoreRuntime();
                    appendLog("health_query=result revision=" + revision);
                } finally {
                    healthQueryScheduled.set(false);
                }
            })) {
                healthQueryScheduled.set(false);
            }
            return;
        }
        if (!enqueueLifecycle(() -> {
            try {
                reconcileDurableRuntime(true, revision);
                refreshProductCatalogProjection("query");
                refreshProductActivityProjection("query", null);
                appendLog("health_query=result revision=" + revision);
                stopIfInactive(requestStartId);
            } finally {
                healthQueryScheduled.set(false);
            }
        })) {
            healthQueryScheduled.set(false);
        }
    }

    private boolean enqueueLifecycle(Runnable task) {
        try {
            lifecycle.execute(task);
            return true;
        } catch (RejectedExecutionException error) {
            appendLog("lifecycle_backpressure=rejected");
            return false;
        }
    }

    private void markExplicitStartPending() {
        if (persistenceGate.isPersistenceUnavailable()) {
            appendLog("runtime_state_persistence=start_blocked pending_recovery");
            return;
        }
        RuntimeSnapshot current = snapshot;
        if (current == null || !RuntimeSnapshot.STATE_ERROR.equals(current.state)
                || !current.mayBeActive) {
            return;
        }
        publish(RuntimeSnapshot.starting(current.profile, current.protocol, current.version,
                current.artifact, current.generation));
    }

    private void repostStartAfterDestroy(Intent source, String action) {
        Intent replacement = new Intent(getApplicationContext(), RuntimeService.class)
                .setAction(action);
        if (source != null && source.getExtras() != null) {
            replacement.putExtras(source.getExtras());
            replacement.setAction(action);
        }
        replacement.putExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION,
                RuntimeControlProtocol.VERSION);
        replacement.putExtra(RuntimeControlProtocol.EXTRA_ACTION, action);
        replacement.putExtra(RuntimeControlProtocol.EXTRA_REQUEST_ID,
                UUID.randomUUID().toString());
        replacement.putExtra(RuntimeControlProtocol.EXTRA_REQUEST_TIME_MILLIS,
                SystemClock.elapsedRealtime());
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                getApplicationContext().startForegroundService(replacement);
            } else {
                getApplicationContext().startService(replacement);
            }
            appendLog("runtime_start=reposted_after_destroy action=" + action);
        } catch (RuntimeException error) {
            publishError("runtime_start_repost_failed", messageOf(error),
                    currentMayBeActive(), currentPid());
        }
    }

    public static boolean notificationsReady(Context context) {
        if (Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        return manager != null && manager.areNotificationsEnabled();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Sakamoto protection", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Ongoing status for the supervised VPP runtime");
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(channel);
        }
    }

    private synchronized boolean ensureForeground(RuntimeProfile profile) {
        if (foregroundStarted) {
            return true;
        }
        RuntimeSnapshot pending = RuntimeSnapshot.starting(profile, VppHealthHandshake.PROTOCOL,
                "", "", generation);
        try {
            startForeground(NOTIFICATION_ID, buildNotification(pending),
                    Build.VERSION.SDK_INT >= 29 ?
                            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0);
            foregroundStarted = true;
            if (!notificationsReady(this)) {
                publishError("notification_permission_required",
                        "allow the ongoing protection notification before starting", false, -1L);
                stopForeground(true);
                foregroundStarted = false;
                return false;
            }
            return true;
        } catch (RuntimeException error) {
            publishError("foreground_service_start_failed", messageOf(error), false, -1L);
            foregroundStarted = false;
            return false;
        }
    }

    private void startRuntime(RuntimeProfile requestedProfile) {
        if (destroying) {
            return;
        }
        startProductCoreRuntime(requestedProfile);
    }

    /** Start the profile-specific Product VPP runtime under its exact Adapter contract. */
    private void startProductCoreRuntime(RuntimeProfile requestedProfile) {
        RuntimeProfile selected = requestedProfile == null
                ? (activeProfile == null ? RuntimeProfile.ROOT : activeProfile)
                : requestedProfile;
        boolean productProcessAlive = processAlive(vppProcess);
        boolean productSessionLive = productCoreSession != null
                && productCoreSession.isConnected();
        if (productProcessAlive && productSessionLive) {
            RuntimeProfile runningProfile = activeProfile == null
                    ? RuntimeProfile.ROOT : activeProfile;
            if (selected == runningProfile) {
                appendLog("start ignored: exactly one runtime is already active");
                queryProductCoreRuntime();
                return;
            }
            appendLog("product_profile_switch_barrier=begin from="
                    + runningProfile.wireName + " to=" + selected.wireName
                    + " generation=" + generation);
            stopRequested = true;
            if (!stopRuntime(false)) {
                appendLog("product_profile_switch_barrier=blocked from="
                        + runningProfile.wireName + " to=" + selected.wireName
                        + " generation=" + generation);
                stopRequested = false;
                return;
            }
            stopRequested = false;
            if (!cleanProductCoreProfileResidue(runningProfile)) {
                appendLog("product_profile_switch_barrier=cleanup_failed from="
                        + runningProfile.wireName + " to=" + selected.wireName
                        + " generation=" + generation);
                publishError("cleanup_failed",
                        "old Product Core profile cleanup failed before replacement", true,
                        ProductCoreLifecycle.UNKNOWN_PID);
                return;
            }
            appendLog("product_profile_switch_barrier=old_stopped from="
                    + runningProfile.wireName + " to=" + selected.wireName
                    + " generation=" + generation);
            productProcessAlive = false;
            productSessionLive = false;
        }
        VpnTunPlatformSession pendingVpnTunSession = null;
        if (productProcessAlive || productSessionLive) {
            failProductCoreGeneration("product_core_session_missing",
                    "Product Core handles are inconsistent for the active generation");
            return;
        }
        activeProfile = selected;
        initializeProfilePaths(selected);
        ProductPacketAdapterContract adapter =
                ProductPacketAdapterContract.forProfile(selected);
        if (!adapter.productLaunchAllowed) {
            publish(RuntimeSnapshot.error(selected, "", "", "", "",
                    adapter.unavailableErrorCode, adapter.unavailableMessage, false,
                    ProductCoreLifecycle.UNKNOWN_PID, generation));
            stopIfInactive();
            return;
        }
        // The Root adapter can create hooks and an NFQUEUE socket only from a
        // privileged Product VPP process. Do not publish a partial START or
        // remove a Root profile when that authority is unavailable.
        if (selected == RuntimeProfile.ROOT && !rootCommandAvailable()) {
            if (adapter.requiresRootAuthorization) {
                publishError("root_authorization_required",
                        "KernelSU/root execution is unavailable to this app process", false,
                        ProductCoreLifecycle.UNKNOWN_PID);
                stopIfInactive();
                return;
            }
        }
        // ProductCoreLifecycle.shouldClearStaleProfile is retained for the
        // legacy contract vocabulary; Product Core now requires the durable
        // owner audit below before any stale profile can be removed.

        boolean productCoreOwnerWritten = false;
        boolean productCorePreflightClean = false;
        Properties productManifest;
        try {
            productManifest = readProductManifest();
            productVppRevision = requiredProductProperty(productManifest, "vppRevision");
            productArtifactId = requiredProductProperty(productManifest, "artifactId");
            productApiIdentity = requiredProductProperty(productManifest, "apiIdentity");
            productAbiVersion = requiredProductIntProperty(productManifest, "abiVersion");
            productApiVersion = requiredProductIntProperty(productManifest, "apiVersion");
            productVppBinarySha256 = requiredProductProperty(productManifest, "vppBinarySha256");
            if (!productVppBinarySha256.matches("[0-9a-fA-F]{64}")) {
                failWithoutRuntime("product_artifact_hash_mismatch",
                        "product VPP executable hash has an invalid format");
                return;
            }
            if (!"sakamoto-android-product-stage/v1".equals(
                    requiredProductProperty(productManifest, "schema"))) {
                throw new IOException("unsupported product stage schema");
            }
            String packagedAbi = requiredProductProperty(productManifest, "abi");
            if (!packagedAbi.equals(deviceAbi())) {
                failWithoutRuntime("product_abi_mismatch",
                        "product ABI does not match device ABI");
                return;
            }
            if (productAbiVersion != 1 || productApiVersion != 1) {
                failWithoutRuntime("product_protocol_mismatch",
                        "product manifest ABI/API versions are unsupported");
                return;
            }

            File nativeDir = new File(getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File vpp = new File(nativeDir, VPP_BINARY).getCanonicalFile();
            File plugin = new File(nativeDir, PRODUCT_PLUGIN_BINARY).getCanonicalFile();
            if (!nativeDir.isDirectory()
                    || !vpp.isFile() || !vpp.canRead()
                    || !plugin.isFile() || !plugin.canRead()
                    || !nativeDir.equals(vpp.getParentFile())
                    || !nativeDir.equals(plugin.getParentFile())) {
                throw new IOException("Product Core native payload is missing or outside nativeLibraryDir");
            }
            if (!productVppBinarySha256.equalsIgnoreCase(sha256(vpp))) {
                failWithoutRuntime("product_artifact_hash_mismatch",
                        "installed Product Core VPP executable does not match the stage");
                return;
            }
            ProductCoreOwner.GlobalDecision ownerDecision = auditProductCoreOwners(
                    selected, productArtifactId, productVppRevision, vpp, false);
            if (ownerDecision.action == ProductCoreOwner.Action.BLOCK_LIVE
                    || ownerDecision.action == ProductCoreOwner.Action.BLOCK_UNKNOWN) {
                publishError(ownerDecision.errorCode, ownerDecision.detail, true,
                        ProductCoreLifecycle.UNKNOWN_PID);
                return;
            }
            if (ownerDecision.action == ProductCoreOwner.Action.CLEAN_THEN_START) {
                if (cleanupFaultInjected) {
                    publishError("cleanup_failed",
                            "generation-owned Product Core cleanup failed", true,
                            ProductCoreLifecycle.UNKNOWN_PID);
                    return;
                }
                // Every profile selected here was audited exact and gone.
                // Never remove a profile that the global audit did not prove.
                if (!cleanProductCoreResidue(ownerDecision)) {
                    publishError("cleanup_failed",
                            "exact Product Core owner profile cleanup failed", true,
                            ProductCoreLifecycle.UNKNOWN_PID);
                    return;
                }
            }
            productCorePreflightClean = true;
            generation = nextProductCoreGeneration(ownerDecision);
            ProductCoreOwner.OwnerRecord owner = ProductCoreOwner.OwnerRecord.create(
                    generation, UUID.randomUUID().toString(), selected,
                    new File(profileRoot, "runtime").getCanonicalPath(),
                    new File(profileRoot, "runtime/api.sock").getCanonicalPath(),
                    productArtifactId, productVppRevision);
            if (!publish(RuntimeSnapshot.starting(selected, VppHealthHandshake.PROTOCOL,
                    productVppRevision, "", generation))) {
                return;
            }
            pendingVpnTunSession = establishPacketAdapterSession(adapter);
            if (adapter.requiresVpnPlatformSession && pendingVpnTunSession == null) {
                return;
            }
            if (selected == RuntimeProfile.ROOT && !installProductRootNfqueueHook()) {
                failProductCoreGeneration("root_nfqueue_hook_install_failed",
                        "Root NFQUEUE INPUT/OUTPUT hooks could not be installed before Product Core launch");
                return;
            }
            prepareProductCoreProfile(profileRoot, nativeDir, owner);
            productCoreOwnerWritten = true;

            ProcessBuilder builder = buildProductCoreProcessBuilder(
                    vpp, nativeDir, profileRoot, selected, owner);
            File runtime = new File(profileRoot, "runtime");
            File svm = new File(profileRoot, "shm");
            builder.environment().put("LD_LIBRARY_PATH", nativeDir.getPath());
            builder.environment().put("SAKAMOTO_PRODUCT_GENERATION",
                    Long.toString(generation));
            builder.environment().put("SAKAMOTO_VPP_OWNER_TOKEN", owner.token);
            builder.environment().put("SAKAMOTO_VPP_SVM_DIR", svm.getPath());
            builder.environment().put("SAKAMOTO_VPP_RUNTIME_DIR", runtime.getPath());
            builder.environment().put("SAKAMOTO_RUNTIME_PROFILE", selected.wireName);
            if (selected == RuntimeProfile.ROOT) {
                builder.environment().put("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE", "176");
                builder.environment().put("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES",
                        PRODUCT_ROOT_NFQUEUE_LANES);
                builder.environment().put("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID",
                        Integer.toString(getApplicationInfo().uid));
                if (!rootNfqueueFaultMode.isEmpty()) {
                    builder.environment().put("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_FAULT_MODE",
                            rootNfqueueFaultMode);
                }
            }
            builder.redirectErrorStream(true);
            builder.redirectOutput(new File(new File(profileRoot, "logs"), "vpp-stdout.log"));
            Process process = builder.start();
            vppProcess = process;
            // Product Core never consumes stdin.  Close the inherited pipe
            // immediately so the child cannot wait on input that no
            // lifecycle thread drains.  This uses the API-1 Process handle,
            // not an Android-hidden Redirect/PID API.
            process.getOutputStream().close();

            productCoreConnectFailureCode = "";
            productCoreConnectFailureMessage = "";
            RuntimeControlNative.Session session = connectProductCoreSession(
                    new File(runtime, "api.sock"), process, adapter);
            if (session == null) {
                failProductCoreGeneration(productCoreConnectFailureCode.isEmpty()
                                ? "product_core_not_ready" : productCoreConnectFailureCode,
                        productCoreConnectFailureMessage.isEmpty()
                                ? "Product Core did not become ready on its generation"
                                : productCoreConnectFailureMessage);
                return;
            }
            productCoreSession = session;
            RuntimeControlNative.Status status = session.lastStatus();
            boolean adapterReadinessExact = status != null
                    && status.adapterAvailable == adapter.adapterReadyOnStart;
            if (!adapterReadinessExact) {
                failProductCoreGeneration("product_adapter_readiness_mismatch",
                        "Product Core VAPI adapter readiness does not match the selected profile");
                return;
            }
            if (selected == RuntimeProfile.VPN) {
                resetVpnDirectUnderlaySnapshot();
                vpnTunSession = pendingVpnTunSession;
                pendingVpnTunSession = null;
                if (!attachVpnTunSessionForProductCore(vpnTunSession)) {
                    failProductCoreGeneration("vpn_tun_control_attach_failed",
                            "VPN ProductCore TUN fd handoff failed");
                    return;
                }
                UnderlayNetwork directUnderlay = UnderlayNetwork.select(this);
                if (!directUnderlay.available) {
                    failProductCoreGeneration(directUnderlay.errorCode,
                            directUnderlay.errorMessage);
                    return;
                }
                vpnDirectUnderlayEpoch = directUnderlay.networkHandle;
                vpnDirectUnderlayTransport = directUnderlay.transport;
                vpnDirectUnderlayNetworkHandle = directUnderlay.networkHandle;
                appendLog("vpn_direct_underlay_snapshot=ok epoch="
                        + vpnDirectUnderlayEpoch + " transport="
                        + vpnDirectUnderlayTransport + " networkHandle="
                        + vpnDirectUnderlayNetworkHandle);
                VpnDirectUdp4TransportSession.StartResult direct =
                        VpnDirectUdp4TransportSession.start(this, directUnderlay);
                if (!direct.ok) {
                    failProductCoreGeneration(direct.errorCode,
                            direct.errorMessage);
                    return;
                }
                vpnDirectUdp4Session = direct.session;
                vpnDirectUdp4NetworkHandle = direct.networkHandle;
                appendLog("vpn_direct_udp4_transport=ok networkHandle="
                        + direct.networkHandle);
                VpnDirectUdp6TransportSession.StartResult udp6Direct =
                        VpnDirectUdp6TransportSession.start(this, directUnderlay);
                if (!udp6Direct.ok) {
                    failProductCoreGeneration(udp6Direct.errorCode,
                            udp6Direct.errorMessage);
                    return;
                }
                vpnDirectUdp6Session = udp6Direct.session;
                vpnDirectUdp6NetworkHandle = udp6Direct.networkHandle;
                appendLog("vpn_direct_udp6_transport=ok networkHandle="
                        + udp6Direct.networkHandle);
                VpnDirectTcp4TransportSession.StartResult tcp4Direct =
                        VpnDirectTcp4TransportSession.start(this, directUnderlay);
                if (!tcp4Direct.ok) {
                    failProductCoreGeneration(tcp4Direct.errorCode,
                            tcp4Direct.errorMessage);
                    return;
                }
                vpnDirectTcp4Session = tcp4Direct.session;
                vpnDirectTcp4NetworkHandle = tcp4Direct.networkHandle;
                appendLog("vpn_direct_tcp4_transport=ok sockets="
                        + tcp4Direct.socketCount + " networkHandle="
                        + tcp4Direct.networkHandle);
                VpnDirectTcp6TransportSession.StartResult tcp6Direct =
                        VpnDirectTcp6TransportSession.start(this, directUnderlay);
                if (!tcp6Direct.ok) {
                    failProductCoreGeneration(tcp6Direct.errorCode,
                            tcp6Direct.errorMessage);
                    return;
                }
                vpnDirectTcp6Session = tcp6Direct.session;
                vpnDirectTcp6NetworkHandle = tcp6Direct.networkHandle;
                appendLog("vpn_direct_tcp6_transport=ok sockets="
                        + tcp6Direct.socketCount + " networkHandle="
                        + tcp6Direct.networkHandle);
                closeVpnTunSessionAfterNativeHandoff();
                status = waitForVpnAdapterReadyAfterHandoff(session, adapter);
                if (status == null) {
                    failProductCoreGeneration(productCoreConnectFailureCode.isEmpty()
                                    ? "product_adapter_readiness_mismatch"
                                    : productCoreConnectFailureCode,
                            productCoreConnectFailureMessage.isEmpty()
                                    ? "VPN ProductCore adapter did not become ready after fd handoff"
                                    : productCoreConnectFailureMessage);
                    return;
                }
            }
            RuntimeControlNative.Status reconciled =
                    reconcileProductEmptyPolicy(session, "startup_reconcile");
            if (reconciled == null) {
                failProductCoreGeneration(productCoreConnectFailureCode.isEmpty()
                                ? "product_policy_reconcile_failed"
                                : productCoreConnectFailureCode,
                        productCoreConnectFailureMessage.isEmpty()
                                ? "Product policy reconcile failed"
                                : productCoreConnectFailureMessage);
                return;
            }
            status = reconciled;
            if (!publishProductCoreRunning(status, ProductCoreLifecycle.UNKNOWN_PID)) {
                failProductCoreGeneration("runtime_state_persistence_unavailable",
                        "Product Core identity could not be published");
                return;
            }
            appendLog("product_core=running generation=" + generation
                    + " api=" + status.apiIdentity + " adapter=" + adapter.adapterName
                    + " protection=" + status.protectionRunning);
            monitorProductCoreExit(process);
        } catch (Exception error) {
            Log.e(TAG, "Product Core startup failed", error);
            closeVpnTunSessionQuietly(pendingVpnTunSession);
            if (!productCoreOwnerWritten && productCorePreflightClean
                    && !processAlive(vppProcess)
                    && !(productCoreSession != null && productCoreSession.isConnected())) {
                // Preflight proved every existing owner gone. A preparation
                // interruption therefore owns only this new profile and can
                // repair it before the next explicit fresh START.
                boolean repaired = profileRoot == null || !profileRoot.exists()
                        || cleanProductCoreProfile(profileRoot);
                publishError(repaired ? "runtime_start_failed" : "cleanup_failed",
                        repaired ? messageOf(error)
                                : messageOf(error) + "; interrupted profile repair failed",
                        !repaired, ProductCoreLifecycle.UNKNOWN_PID);
                stopIfInactive();
                return;
            }
            failProductCoreGeneration("runtime_start_failed", messageOf(error));
        }
    }

    /**
     * Keep the executable and startup config identical across profiles. Only
     * Root crosses the privilege boundary; VPN/core-only remains a direct
     * app-UID VPP child with no Root NFQUEUE capability.
    */
    private ProcessBuilder buildProductCoreProcessBuilder(
            File vpp, File nativeDir, File currentProfile, RuntimeProfile profile,
            ProductCoreOwner.OwnerRecord owner) {
        File startup = new File(currentProfile, "startup.conf");
        if (profile == RuntimeProfile.ROOT) {
            File runtime = new File(currentProfile, "runtime");
            File svm = new File(currentProfile, "shm");
            String command = "export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                    + "; export SAKAMOTO_PRODUCT_GENERATION="
                    + shellQuote(Long.toString(owner.generation))
                    + "; export SAKAMOTO_VPP_OWNER_TOKEN=" + shellQuote(owner.token)
                    + "; export SAKAMOTO_VPP_SVM_DIR=" + shellQuote(svm.getPath())
                    + "; export SAKAMOTO_VPP_RUNTIME_DIR=" + shellQuote(runtime.getPath())
                    + "; export SAKAMOTO_RUNTIME_PROFILE=" + shellQuote(profile.wireName)
                    + "; export SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE=\"176\""
                    + "; export SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES="
                    + shellQuote(PRODUCT_ROOT_NFQUEUE_LANES)
                    + "; export SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID="
                    + shellQuote(Integer.toString(getApplicationInfo().uid))
                    + productRootNfqueueFaultExport()
                    + "; exec " + shellQuote(vpp.getPath()) + " -c "
                    + shellQuote(startup.getPath());
            return new ProcessBuilder(SU_PATH, "0", "sh", "-c", command);
        }
        return new ProcessBuilder(vpp.getPath(), "-c", startup.getPath());
    }

    private RuntimeControlNative.Session connectProductCoreSession(
            File socket, Process process, ProductPacketAdapterContract adapter)
            throws InterruptedException {
        RuntimeControlNative.Session session = null;
        for (int attempt = 0; attempt < HEALTH_ATTEMPTS; attempt++) {
            if (!ProductCoreLifecycle.canRetryConnection(
                    stopRequested, process.isAlive(), attempt, HEALTH_ATTEMPTS)) {
                if (session != null) {
                    session.close();
                }
                return null;
            }
            if (session != null && session.isConnected()) {
                RuntimeControlNative.Status status = session.query();
                String validation;
                if (status != null && status.code != 0) {
                    validation = ProductCoreLifecycle.failureCode(status);
                } else {
                    validation = ProductCoreLifecycle.validate(generation, productArtifactId,
                            productApiIdentity, productVppRevision, productAbiVersion,
                            productApiVersion, status, adapter.adapterReadyOnStart);
                }
                if (validation.isEmpty()) {
                    return session;
                }
                if (!validation.isEmpty()
                        && !"product_core_not_ready".equals(validation)) {
                    appendProductCoreValidationFailureLog(validation, status);
                    productCoreConnectFailureCode = validation;
                    productCoreConnectFailureMessage = status == null
                            ? validation : status.errorDetail;
                }
                if (!ProductCoreLifecycle.isRetryableStartupReadinessFailure(validation)
                        || !ProductCoreLifecycle.shouldKeepSessionForReadinessRetry(
                                validation, session.isConnected())) {
                    session.close();
                    session = null;
                    if (!ProductCoreLifecycle.isRetryableStartupReadinessFailure(validation)) {
                        return null;
                    }
                }
            } else if (socket.exists()) {
                if (adapter.requiresRootAuthorization) {
                    // The Root Product VPP owns socksvr creation. This is a
                    // bounded control-plane permission handoff only; packet
                    // ownership remains in the VPP-native Adapter.
                    runRootCommand("chmod 0666 " + shellQuote(socket.getPath()), 2L);
                }
                session = RuntimeControlNative.connect(socket.getPath(), generation);
                RuntimeControlNative.Status status = session.lastStatus();
                String validation;
                if (!session.isConnected() || (status != null && status.code != 0)) {
                    validation = ProductCoreLifecycle.failureCode(status);
                } else {
                    validation = ProductCoreLifecycle.validate(generation, productArtifactId,
                            productApiIdentity, productVppRevision, productAbiVersion,
                            productApiVersion, status, adapter.adapterReadyOnStart);
                }
                if (session.isConnected() && validation.isEmpty()) {
                    return session;
                }
                boolean startupTransportRace = !session.isConnected()
                        && process.isAlive()
                        && ProductCoreLifecycle.isRetryableStartupTransportFailure(validation);
                if (!validation.isEmpty()
                        && !"product_core_not_ready".equals(validation)
                        && !startupTransportRace) {
                    appendProductCoreValidationFailureLog(validation, status);
                    productCoreConnectFailureCode = validation;
                    productCoreConnectFailureMessage = status == null
                            ? validation : status.errorDetail;
                }
                if (!ProductCoreLifecycle.isRetryableStartupReadinessFailure(validation)
                        && !startupTransportRace) {
                    session.close();
                    session = null;
                    return null;
                }
                if (!ProductCoreLifecycle.shouldKeepSessionForReadinessRetry(
                        validation, session.isConnected())) {
                    session.close();
                    session = null;
                }
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
        }
        if (session != null) {
            session.close();
        }
        return null;
    }

    private void queryProductCoreRuntime() {
        if (productCoreQueryBlockedByErrorLatch()) {
            return;
        }
        Process process = vppProcess;
        RuntimeControlNative.Session session = productCoreSession;
        if (process == null || !process.isAlive()) {
            if (stopRequested || (snapshot != null
                    && (RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state)
                    || RuntimeSnapshot.STATE_STOPPED.equals(snapshot.state)))) {
                return;
            }
            failProductCoreGeneration("unexpected_exit", "VPP sidecar is not alive");
            return;
        }
        if (session == null || session.generation() != generation || !session.isConnected()) {
            failProductCoreGeneration("product_core_session_missing",
                    "Product Core session is not live for the active generation");
            return;
        }
        RuntimeControlNative.Status status = session.query();
        ProductPacketAdapterContract adapter =
                ProductPacketAdapterContract.forProfile(activeProfile);
        String validation;
            if (status != null && status.code != 0) {
                validation = ProductCoreLifecycle.failureCode(status);
            } else {
                validation = ProductCoreLifecycle.validate(generation, productArtifactId,
                        productApiIdentity, productVppRevision, productAbiVersion,
                        productApiVersion, status, adapter.adapterReadyAfterHandoff);
            }
            if (!validation.isEmpty()) {
                appendProductCoreValidationFailureLog(validation, status);
                String detail = status == null || status.errorDetail.isEmpty()
                        ? validation : status.errorDetail;
                failProductCoreGeneration(validation, detail);
                return;
            }
        publishProductCoreRunning(status, ProductCoreLifecycle.UNKNOWN_PID);
        appendLog("product_core=query generation=" + generation + " api=" + status.apiIdentity);
    }

    private RuntimeControlNative.Status reconcileProductEmptyPolicy(
            RuntimeControlNative.Session session, String stage) {
        if (session == null || !session.isConnected()) {
            productCoreConnectFailureCode = "product_core_session_missing";
            productCoreConnectFailureMessage =
                    "Product Core session is not live for policy reconcile";
            writeS188EmptyPolicySnapshotStatus(null, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            writeS194ProductMutationStatus(null, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            return null;
        }
        RuntimeControlNative.Status status = session.reconcilePolicy(
                getFilesDir().getAbsolutePath());
        if (status == null || status.code != 0) {
            productCoreConnectFailureCode = status == null
                    ? "product_policy_reconcile_failed"
                    : ProductCoreLifecycle.failureCode(status);
            productCoreConnectFailureMessage = status == null || status.errorDetail.isEmpty()
                    ? "Product policy reconcile failed"
                    : status.errorDetail;
            writeS188EmptyPolicySnapshotStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            writeS194ProductMutationStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            return null;
        }
        String reconciliationDetail = status.errorDetail == null ? "" : status.errorDetail;
        boolean reconciliationReadbackOnly =
                isUnknownPolicyMutationReadbackDetail(reconciliationDetail);
        if (status.policyActiveRevision <= 0L) {
            status = session.applyEmptyPolicy(getFilesDir().getAbsolutePath());
            if (status == null || status.code != 0) {
                productCoreConnectFailureCode = status == null
                        ? "product_policy_apply_failed"
                        : ProductCoreLifecycle.failureCode(status);
                productCoreConnectFailureMessage =
                        emptyPolicySnapshotFailureDetail(status,
                                "initial empty policy apply failed");
                writeS188EmptyPolicySnapshotStatus(status, stage + "_apply_failed",
                        productCoreConnectFailureCode, productCoreConnectFailureMessage);
                writeS194ProductMutationStatus(status, stage + "_apply_failed",
                        productCoreConnectFailureCode, productCoreConnectFailureMessage);
                return null;
            }
            stage = stage + "_fresh_apply";
        }
        String validation = validateRuntimePolicySnapshot(status);
        if (!validation.isEmpty()) {
            productCoreConnectFailureCode = validation;
            productCoreConnectFailureMessage =
                    emptyPolicySnapshotFailureDetail(status,
                            "policy reconcile result is invalid");
            writeS188EmptyPolicySnapshotStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            writeS189RootNetworkGateStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            writeS190VpnNetworkGateStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            writeS191RootL4Status(status, currentRootL4PolicyFacts(),
                    stage + "_failed", productCoreConnectFailureCode,
                    productCoreConnectFailureMessage);
            writeS192L4MatrixStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            writeS194ProductMutationStatus(status, stage + "_failed",
                    productCoreConnectFailureCode, productCoreConnectFailureMessage);
            return null;
        }
        if (reconciliationReadbackOnly) {
            appendLog(reconciliationDetail);
        }
        writeS188EmptyPolicySnapshotStatus(status, stage, "", "");
        writeS189RootNetworkGateStatus(status, stage, "", "");
        writeS190VpnNetworkGateStatus(status, stage, "", "");
        writeS191RootL4Status(status, currentRootL4PolicyFacts(), stage, "", "");
        writeS192L4MatrixStatus(status, stage, "", "");
        writeS194ProductMutationStatus(status, stage, "",
                reconciliationReadbackOnly ? reconciliationDetail : "");
        return status;
    }

    private void applyProductEmptyPolicy() {
        RuntimeControlNative.Session session = productCoreSession;
        Process process = vppProcess;
        if (process == null || !process.isAlive()
                || session == null || session.generation() != generation
                || !session.isConnected()) {
            String detail = "Product Core must be running before empty policy apply";
            writeS188EmptyPolicySnapshotStatus(null, "apply_failed",
                    "product_core_session_missing", detail);
            publishError("product_core_session_missing", detail, currentMayBeActive(),
                    currentPid());
            stopIfInactive();
            return;
        }
        RuntimeControlNative.Status status =
                session.applyEmptyPolicy(getFilesDir().getAbsolutePath());
        if (status == null || status.code != 0) {
            String code = status == null ? "product_policy_apply_failed"
                    : ProductCoreLifecycle.failureCode(status);
            String detail = emptyPolicySnapshotFailureDetail(status,
                    "empty policy apply failed");
            writeS188EmptyPolicySnapshotStatus(status, "apply_failed", code, detail);
            publishError(code, detail, currentMayBeActive(), currentPid());
            return;
        }
        String validation = validateEmptyPolicySnapshot(status);
        if (!validation.isEmpty()) {
            String detail = emptyPolicySnapshotFailureDetail(status,
                    "empty policy apply result is invalid");
            writeS188EmptyPolicySnapshotStatus(status, "apply_failed", validation, detail);
            publishError(validation, detail, currentMayBeActive(), currentPid());
            return;
        }
        publishProductCoreRunning(status, ProductCoreLifecycle.UNKNOWN_PID);
        writeS188EmptyPolicySnapshotStatus(status, "applied", "", "");
        appendLog("product_policy=applied revision=" + status.policyRequestedRevision
                + " active=" + status.policyActiveRevision
                + " profile=" + (activeProfile == null ? "" : activeProfile.wireName));
    }

    private LocalProductBackend.PolicyApplyResult applyCommittedProductPolicy(
            String applyArgsJson) {
        try {
            JSONObject payload = new JSONObject(
                    applyArgsJson == null || applyArgsJson.trim().isEmpty()
                            ? "{}" : applyArgsJson);
            JSONArray subjects = payload.optJSONArray("subjects");
            long compiledRevision = payload.optLong("revision", -1L);
            if (subjects == null || compiledRevision < 0L) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "policy payload is missing a revisioned subject list");
            }
            RuntimeControlNative.Session session = productCoreSession;
            Process process = vppProcess;
            if (process == null || !process.isAlive()
                    || session == null || session.generation() != generation
                    || !session.isConnected()) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_runtime_unavailable",
                        "Product Core is not running for the active generation");
            }
            RuntimeControlNative.Status status;
            String validation;
            if (payload.has("bundleAbiVersion") || payload.has("bundlePayload")) {
                // A complete S192 bundle is profile-neutral.  Keep this branch
                // ahead of the Root-only S191 scalar compatibility path.
                if (payload.optInt("bundleAbiVersion", -1)
                        != AuthoringPolicyBundle.BUNDLE_ABI_VERSION
                        || compiledRevision <= 0L) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "complete Product policy bundle identity is invalid");
                }
                String encodedBundle = payload.optString("bundlePayload", "");
                final byte[] bundleWire;
                try {
                    bundleWire = Base64.getDecoder().decode(encodedBundle);
                } catch (IllegalArgumentException error) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "complete Product policy bundle payload is not valid Base64");
                }
                if (bundleWire.length != AuthoringPolicyBundle.BUNDLE_BYTES) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "complete Product policy bundle payload has an invalid fixed size");
                }
                String canonicalHashText = payload.optString("bundleSnapshotHash", "");
                final long canonicalBundleHash;
                try {
                    canonicalBundleHash = Long.parseUnsignedLong(canonicalHashText);
                } catch (NumberFormatException error) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_bundle_hash_mismatch",
                            "complete Product policy bundle canonical hash is invalid");
                }
                long payloadBundleHash = nativeBundleSnapshotHash(bundleWire);
                if (canonicalBundleHash == 0L
                        || payloadBundleHash == 0L
                        || payloadBundleHash != canonicalBundleHash
                        || !nativeBundleHeaderMatches(bundleWire, compiledRevision)) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_bundle_hash_mismatch",
                            "complete Product policy bundle payload hash does not match its canonical identity");
                }
                status = session.applyPolicyBundle(getFilesDir().getAbsolutePath(), bundleWire);
                if (status == null || status.code != 0) {
                    String code = status == null ? "product_policy_apply_failed"
                            : ProductCoreLifecycle.failureCode(status);
                    String detail = emptyPolicySnapshotFailureDetail(status,
                            "complete Product policy bundle apply failed");
                    writeS194ProductMutationStatus(status, "apply_failed", code, detail);
                    return LocalProductBackend.PolicyApplyResult.error(code, detail);
                }
                if (status.policySnapshotHash != canonicalBundleHash) {
                    String detail = emptyPolicySnapshotFailureDetail(status,
                            "complete Product policy bundle hash readback failed");
                    writeS194ProductMutationStatus(status, "apply_failed",
                            "product_policy_bundle_hash_mismatch", detail);
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_bundle_hash_mismatch", detail);
                }
                if (status.policyRequestedRevision != compiledRevision
                        || status.policyActiveRevision != compiledRevision) {
                    String detail = emptyPolicySnapshotFailureDetail(status,
                            "complete Product policy bundle revision readback failed");
                    writeS194ProductMutationStatus(status, "apply_failed",
                            "product_policy_revision_mismatch", detail);
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_revision_mismatch", detail);
                }
                validation = validatePolicyBundleSnapshot(status, compiledRevision);
                if (!validation.isEmpty()) {
                    String detail = emptyPolicySnapshotFailureDetail(status,
                            "complete Product policy bundle readback failed");
                    writeS194ProductMutationStatus(status, "apply_failed", validation, detail);
                    return LocalProductBackend.PolicyApplyResult.error(validation, detail);
                }
                String gateStage = networkGateEvidenceStage(status);
                if (!"running".equals(gateStage)) {
                    rememberNetworkGateEvidenceStage(status, gateStage);
                    if (activeProfile == RuntimeProfile.ROOT) {
                        writeS189RootNetworkGateStatus(status, gateStage, "", "");
                    } else if (activeProfile == RuntimeProfile.VPN) {
                        writeS190VpnNetworkGateStatus(status, gateStage, "", "");
                    }
                }
                if (activeProfile == RuntimeProfile.ROOT
                        && status.policyGateClaimCount == 0
                        && status.policyL4RuleCount == 1) {
                    RootL4PolicyFacts facts = rootL4FactsFromPolicyPayload(subjects);
                    if (facts != null) {
                        writeS191RootL4Status(status, facts, "l4_apply", "", "");
                    }
                }
                writeS192L4MatrixStatus(status, "apply", "", "");
                writeS194ProductMutationStatus(status, "apply", "", "");
                appendLog("product_policy=bundle revision=" + compiledRevision
                        + " active=" + status.policyActiveRevision + " profile="
                        + (activeProfile == null ? "" : activeProfile.wireName));
                return LocalProductBackend.PolicyApplyResult.ok();
            }
            if (!"s191-scalar".equals(payload.optString("nativeApply", ""))) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "scalar Product policy apply requires explicit S191 compatibility");
            }
            if (subjects.length() == 0) {
                status = compiledRevision > 0L
                        ? session.applyEmptyPolicyRevision(
                        getFilesDir().getAbsolutePath(), compiledRevision)
                        : session.applyEmptyPolicy(getFilesDir().getAbsolutePath());
                if (status == null || status.code != 0) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            status == null ? "product_policy_apply_failed"
                                    : ProductCoreLifecycle.failureCode(status),
                            emptyPolicySnapshotFailureDetail(status,
                                    "empty Product policy apply failed"));
                }
                validation = validateEmptyPolicySnapshot(status);
                if (validation.isEmpty() && compiledRevision > 0L
                        && status.policyActiveRevision != compiledRevision) {
                    validation = "product_empty_policy_revision_mismatch";
                }
                if (!validation.isEmpty()) {
                    return LocalProductBackend.PolicyApplyResult.error(validation,
                            emptyPolicySnapshotFailureDetail(status,
                                    "empty Product policy readback failed"));
                }
                clearNetworkGateEvidenceStage();
                writeS188EmptyPolicySnapshotStatus(status, "backend_apply", "", "");
                writeS189RootNetworkGateStatus(status, "gate_open", "", "");
                writeS190VpnNetworkGateStatus(status, "gate_open", "", "");
                appendLog("product_policy=backend_apply revision="
                        + status.policyRequestedRevision + " active="
                        + status.policyActiveRevision + " profile="
                        + (activeProfile == null ? "" : activeProfile.wireName));
                return LocalProductBackend.PolicyApplyResult.ok();
            }
            if (subjects.length() != 1) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "this slice accepts one Network Gate subject at a time");
            }
            JSONObject subject = subjects.getJSONObject(0);
            if (!subject.optBoolean("uidKnown", false)) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "Product policy requires a complete Android UID");
            }
            int subjectUid = subject.optInt("linuxUid", -1);
            JSONObject networkGate = subject.optJSONObject("networkGate");
            JSONArray rules = networkGate == null ? null : networkGate.optJSONArray("rules");
            if (subjectUid < 0) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "Product policy requires a valid Android UID");
            }
            JSONArray l4Rules = subject.optJSONArray("l4Rules");
            // S191 compatibility remains deliberately Root-only and single-rule.
            if (l4Rules != null && l4Rules.length() != 0) {
                if (activeProfile != RuntimeProfile.ROOT) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "S191 L4 policy is Root-profile only");
                }
                if (rules != null && rules.length() != 0) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "S191 accepts L4 without a concurrent Network Gate rule");
                }
                if (l4Rules.length() != 1) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "S191 accepts exactly one L4 rule");
                }
                if (compiledRevision <= 0L) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "L4 rule requires a positive authoring revision");
                }
                RootL4PolicyFacts l4 = parseRootL4PolicyFacts(
                        subjectUid, l4Rules.getJSONObject(0));
                status = session.applyL4PolicyRevision(
                        getFilesDir().getAbsolutePath(), compiledRevision,
                        l4.subjectUid, l4.networkContext, l4.ipFamily,
                        l4.ipProtocol, l4.direction, l4.action, l4.sourceCidr,
                        l4.destinationCidr, l4.sourcePortFirst, l4.sourcePortLast,
                        l4.destinationPortFirst, l4.destinationPortLast,
                        l4.priority, l4.order, l4.ruleId, l4.reasonId);
                if (status == null || status.code != 0) {
                    String code = status == null ? "product_policy_apply_failed"
                            : ProductCoreLifecycle.failureCode(status);
                    String detail = emptyPolicySnapshotFailureDetail(status,
                            "S191 L4 Product policy apply failed");
                    writeS191RootL4Status(status, l4,
                            "l4_apply_failed", code, detail);
                    return LocalProductBackend.PolicyApplyResult.error(code, detail);
                }
                validation = validateRootL4PolicySnapshot(status, compiledRevision);
                if (!validation.isEmpty()) {
                    String detail = emptyPolicySnapshotFailureDetail(status,
                            "S191 L4 Product policy readback failed");
                    writeS191RootL4Status(status, l4,
                            "l4_apply_failed", validation, detail);
                    return LocalProductBackend.PolicyApplyResult.error(validation, detail);
                }
                writeS191RootL4Status(status, l4,
                        "l4_apply",
                        "", "");
                appendLog("product_policy=l4 revision="
                        + status.policyRequestedRevision + " active="
                        + status.policyActiveRevision + " profile="
                        + (activeProfile == null ? "" : activeProfile.wireName)
                        + " subjectUid=" + subjectUid + " context="
                        + l4.networkContext + " action="
                        + (l4.action == PRODUCT_POLICY_VERDICT_DROP ? "drop" : "allow")
                        + " ruleId=" + Long.toUnsignedString(l4.ruleId));
                return LocalProductBackend.PolicyApplyResult.ok();
            }
            if (rules == null || rules.length() == 0) {
                if (compiledRevision <= 0L) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            "product_policy_snapshot_unsupported",
                            "Network Gate clear requires a positive authoring revision");
                }
                status = session.applyEmptyPolicyRevision(
                        getFilesDir().getAbsolutePath(), compiledRevision);
                if (status == null || status.code != 0) {
                    return LocalProductBackend.PolicyApplyResult.error(
                            status == null ? "product_policy_apply_failed"
                                    : ProductCoreLifecycle.failureCode(status),
                            emptyPolicySnapshotFailureDetail(status,
                                    "Network Gate clear apply failed"));
                }
                validation = validateEmptyPolicySnapshot(status);
                if (validation.isEmpty() && status.policyActiveRevision != compiledRevision) {
                    validation = "product_empty_policy_revision_mismatch";
                }
                if (!validation.isEmpty()) {
                    return LocalProductBackend.PolicyApplyResult.error(validation,
                            emptyPolicySnapshotFailureDetail(status,
                                    "Network Gate clear readback failed"));
                }
                clearNetworkGateEvidenceStage();
                writeS188EmptyPolicySnapshotStatus(status, "backend_apply", "", "");
                writeS189RootNetworkGateStatus(status, "gate_open", "", "");
                writeS190VpnNetworkGateStatus(status, "gate_open", "", "");
                appendLog("product_policy=network_gate_clear revision="
                        + status.policyRequestedRevision + " active="
                        + status.policyActiveRevision + " profile="
                        + (activeProfile == null ? "" : activeProfile.wireName)
                        + " subjectUid=" + subjectUid);
                return LocalProductBackend.PolicyApplyResult.ok();
            }
            if (rules.length() != 1) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "this slice accepts exactly one Network Gate rule");
            }
            JSONObject rule = rules.getJSONObject(0);
            int networkContext = rule.optInt("networkContext", -1);
            boolean blocked = rule.optBoolean("blocked", true);
            long ruleId = rule.optLong("ruleId", -1L);
            int reasonId = rule.optInt("reasonId", -1);
            if (compiledRevision <= 0L || networkContext <= 0 || ruleId <= 0L
                    || reasonId <= 0) {
                return LocalProductBackend.PolicyApplyResult.error(
                        "product_policy_snapshot_unsupported",
                        "Network Gate rule identity is incomplete");
            }
            status = session.applyNetworkGatePolicyRevision(getFilesDir().getAbsolutePath(),
                    compiledRevision, subjectUid, networkContext, blocked, ruleId, reasonId);
            if (status == null || status.code != 0) {
                return LocalProductBackend.PolicyApplyResult.error(
                        status == null ? "product_policy_apply_failed"
                                : ProductCoreLifecycle.failureCode(status),
                        emptyPolicySnapshotFailureDetail(status,
                                "Network Gate Product policy apply failed"));
            }
            validation = validateNetworkGatePolicySnapshot(status, compiledRevision, subjectUid,
                    networkContext, blocked, ruleId, reasonId);
            if (!validation.isEmpty()) {
                return LocalProductBackend.PolicyApplyResult.error(validation,
                        emptyPolicySnapshotFailureDetail(status,
                                "Network Gate Product policy readback failed"));
            }
            String gateStage = blocked ? "gate_blocked" : "gate_open";
            rememberNetworkGateEvidenceStage(status, gateStage);
            writeS189RootNetworkGateStatus(status, gateStage, "", "");
            writeS190VpnNetworkGateStatus(status, gateStage, "", "");
            appendLog("product_policy=network_gate revision="
                    + status.policyRequestedRevision + " active="
                    + status.policyActiveRevision + " profile="
                    + (activeProfile == null ? "" : activeProfile.wireName)
                    + " subjectUid=" + subjectUid + " context=" + networkContext
                    + " blocked=" + blocked);
            return LocalProductBackend.PolicyApplyResult.ok();
        } catch (Exception error) {
            return LocalProductBackend.PolicyApplyResult.error(
                    "product_policy_apply_failed",
                    error.getMessage() == null ? "Product policy apply failed"
                            : error.getMessage());
        }
    }

    private static long nativeBundleSnapshotHash(byte[] bundleWire) {
        if (bundleWire == null || bundleWire.length < AuthoringPolicyBundle.BUNDLE_HEADER_BYTES) {
            return 0L;
        }
        return ByteBuffer.wrap(bundleWire).order(ByteOrder.LITTLE_ENDIAN).getLong(16);
    }

    private static boolean nativeBundleHeaderMatches(byte[] bundleWire, long compiledRevision) {
        if (bundleWire == null || bundleWire.length != AuthoringPolicyBundle.BUNDLE_BYTES) {
            return false;
        }
        ByteBuffer header = ByteBuffer.wrap(bundleWire).order(ByteOrder.LITTLE_ENDIAN);
        return header.getInt(0) == AuthoringPolicyBundle.BUNDLE_ABI_VERSION
                && header.getInt(4) == AuthoringPolicyBundle.BUNDLE_BYTES
                && header.getLong(8) == compiledRevision;
    }

    private String validateEmptyPolicySnapshot(RuntimeControlNative.Status status) {
        if (status == null) {
            return "product_empty_policy_status_missing";
        }
        if (status.code != 0) {
            return "product_empty_policy_apply_failed";
        }
        if (status.policyLastApplyStatusCode != 0) {
            return "product_empty_policy_last_apply_failed";
        }
        if (status.policyGeneration != generation || !status.policyGenerationMatch) {
            return "product_empty_policy_generation_mismatch";
        }
        if (status.policyRequestedRevision <= 0L
                || status.policyActiveRevision <= 0L
                || status.policyRequestedRevision != status.policyActiveRevision) {
            return "product_empty_policy_revision_mismatch";
        }
        if (status.policySnapshotHash == 0L
                || status.policySnapshotIdentity == null
                || status.policySnapshotIdentity.isEmpty()) {
            return "product_empty_policy_snapshot_identity_missing";
        }
        if (!status.policySnapshotEmpty || !status.policyDefaultPass
                || status.policyGateClaimCount != 0
                || status.policyL4RuleCount != 0) {
            return "product_empty_policy_default_pass_mismatch";
        }
        if (status.policyWorker0Revision != status.policyActiveRevision
                || status.policyWorker1Revision != status.policyActiveRevision
                || status.policyMixedRevision) {
            return "product_empty_policy_worker_revision_mismatch";
        }
        if (!status.policyArtifactMatch) {
            return "product_empty_policy_artifact_mismatch";
        }
        return "";
    }

    private String validateRuntimePolicySnapshot(RuntimeControlNative.Status status) {
        // The durable bundle identity selects the complete typed validator;
        // never route a multi-rule bundle through the S191 scalar checks.
        if (status != null
                && AuthoringPolicyBundle.BUNDLE_FORMAT.equals(status.policySnapshotIdentity)) {
            return validatePolicyBundleSnapshot(status, -1L);
        }
        String emptyValidation = validateEmptyPolicySnapshot(status);
        if (emptyValidation.isEmpty()) {
            return "";
        }
        String gateValidation = validateNetworkGatePolicySnapshot(
                status, -1L, -1, -1, null, -1L, -1);
        if (gateValidation.isEmpty()) {
            return "";
        }
        String l4Validation = validateRootL4PolicySnapshot(status, -1L);
        return l4Validation.isEmpty()
                ? "" : "product_policy_snapshot_unsupported";
    }

    private String validatePolicyBundleSnapshot(RuntimeControlNative.Status status,
                                                long expectedRevision) {
        if (status == null) {
            return "product_policy_bundle_status_missing";
        }
        if (status.code != 0) {
            return "product_policy_bundle_apply_failed";
        }
        if (status.policyLastApplyStatusCode != 0) {
            return "product_policy_bundle_last_apply_failed";
        }
        if (status.policyGeneration != generation || !status.policyGenerationMatch) {
            return "product_policy_bundle_generation_mismatch";
        }
        if (status.policyRequestedRevision <= 0L
                || status.policyActiveRevision <= 0L
                || status.policyRequestedRevision != status.policyActiveRevision
                || (expectedRevision > 0L
                && status.policyActiveRevision != expectedRevision)) {
            return "product_policy_bundle_revision_mismatch";
        }
        if (status.policySnapshotHash == 0L
                || !AuthoringPolicyBundle.BUNDLE_FORMAT.equals(status.policySnapshotIdentity)) {
            return "product_policy_bundle_identity_mismatch";
        }

        // The native bundle parser enforces each entry's typed fields.  The
        // status readback still must prove bounded counts and a coherent view.
        int gateClaims = status.policyGateClaimCount;
        int l4Rules = status.policyL4RuleCount;
        if (gateClaims < 0 || gateClaims > AuthoringPolicyBundle.MAX_GATE_ENTRIES
                || l4Rules < 0 || l4Rules > AuthoringPolicyBundle.MAX_L4_RULES
                || gateClaims + l4Rules > AuthoringPolicyBundle.MAX_RULE_ENTRIES) {
            return "product_policy_bundle_count_mismatch";
        }
        if (!status.policyDefaultPass
                || (status.policySnapshotEmpty && (gateClaims != 0 || l4Rules != 0))) {
            return "product_policy_bundle_default_pass_mismatch";
        }
        if (status.policyL4ViewActive != 1
                || status.policyL4ViewRuleCount < 0
                || status.policyL4ViewRuleCount > l4Rules
                || status.policyL4ViewMaxProbes < 0
                || status.policyL4ViewMaxProbes > AuthoringPolicyBundle.MAX_RULE_ENTRIES
                || status.policyL4ViewLastMatchWinnerRank < 0
                || status.policyL4ViewLastMatchWinnerRank > l4Rules
                || status.policyL4ViewLastMatchProbes < 0
                || status.policyL4ViewLastMatchProbes > status.policyL4ViewMaxProbes
                || status.policyL4ViewLastMatchCandidateCount < 0
                || status.policyL4ViewLastMatchCandidateCount > l4Rules
                || status.policyL4ViewLastNoMatchReason < 0) {
            return "product_policy_bundle_view_mismatch";
        }
        if (status.policyWorker0Revision != status.policyActiveRevision
                || status.policyWorker1Revision != status.policyActiveRevision
                || status.policyMixedRevision) {
            return "product_policy_bundle_worker_revision_mismatch";
        }
        if (!status.policyArtifactMatch) {
            return "product_policy_bundle_artifact_mismatch";
        }
        return "";
    }

    private String validateNetworkGatePolicySnapshot(RuntimeControlNative.Status status,
                                                     long expectedRevision,
                                                     int expectedSubjectUid,
                                                     int expectedNetworkContext,
                                                     Boolean expectedBlocked,
                                                     long expectedRuleId,
                                                     int expectedReasonId) {
        if (status == null) {
            return "product_network_gate_status_missing";
        }
        if (status.code != 0) {
            return "product_network_gate_apply_failed";
        }
        if (status.policyLastApplyStatusCode != 0) {
            return "product_network_gate_last_apply_failed";
        }
        if (status.policyGeneration != generation || !status.policyGenerationMatch) {
            return "product_network_gate_generation_mismatch";
        }
        if (status.policyRequestedRevision <= 0L
                || status.policyActiveRevision <= 0L
                || status.policyRequestedRevision != status.policyActiveRevision) {
            return "product_network_gate_revision_mismatch";
        }
        if (expectedRevision > 0L && status.policyActiveRevision != expectedRevision) {
            return "product_network_gate_revision_mismatch";
        }
        if (status.policySnapshotHash == 0L
                || status.policySnapshotIdentity == null
                || status.policySnapshotIdentity.isEmpty()) {
            return "product_network_gate_snapshot_identity_missing";
        }
        if (status.policySnapshotEmpty || !status.policyDefaultPass
                || status.policyL4RuleCount != 0) {
            return "product_network_gate_default_pass_mismatch";
        }
        if (status.policyGateClaimCount != (status.policyGateBlocked ? 1 : 0)) {
            return "product_network_gate_claim_count_mismatch";
        }
        if (status.policyGateSubjectUid < 0
                || status.policyGateNetworkContext <= 0
                || status.policyGateReasonId <= 0
                || status.policyGateRuleId <= 0L) {
            return "product_network_gate_fields_missing";
        }
        if (expectedSubjectUid >= 0 && status.policyGateSubjectUid != expectedSubjectUid) {
            return "product_network_gate_subject_mismatch";
        }
        if (expectedNetworkContext > 0
                && status.policyGateNetworkContext != expectedNetworkContext) {
            return "product_network_gate_context_mismatch";
        }
        if (expectedBlocked != null && status.policyGateBlocked != expectedBlocked) {
            return "product_network_gate_blocked_mismatch";
        }
        if (expectedRuleId > 0L && status.policyGateRuleId != expectedRuleId) {
            return "product_network_gate_rule_mismatch";
        }
        if (expectedReasonId > 0 && status.policyGateReasonId != expectedReasonId) {
            return "product_network_gate_reason_mismatch";
        }
        if (status.policyWorker0Revision != status.policyActiveRevision
                || status.policyWorker1Revision != status.policyActiveRevision
                || status.policyMixedRevision) {
            return "product_network_gate_worker_revision_mismatch";
        }
        if (!status.policyArtifactMatch) {
            return "product_network_gate_artifact_mismatch";
        }
        return "";
    }

    private String validateRootL4PolicySnapshot(RuntimeControlNative.Status status,
                                                long expectedRevision) {
        if (status == null) {
            return "product_l4_status_missing";
        }
        if (status.code != 0) {
            return "product_l4_apply_failed";
        }
        if (status.policyLastApplyStatusCode != 0) {
            return "product_l4_last_apply_failed";
        }
        if (status.policyGeneration != generation || !status.policyGenerationMatch) {
            return "product_l4_generation_mismatch";
        }
        if (status.policyRequestedRevision <= 0L
                || status.policyActiveRevision <= 0L
                || status.policyRequestedRevision != status.policyActiveRevision) {
            return "product_l4_revision_mismatch";
        }
        if (expectedRevision > 0L && status.policyActiveRevision != expectedRevision) {
            return "product_l4_revision_mismatch";
        }
        if (status.policySnapshotHash == 0L
                || status.policySnapshotIdentity == null
                || status.policySnapshotIdentity.isEmpty()) {
            return "product_l4_snapshot_identity_missing";
        }
        if (status.policySnapshotEmpty || !status.policyDefaultPass
                || status.policyGateClaimCount != 0
                || status.policyL4RuleCount != 1) {
            return "product_l4_default_pass_mismatch";
        }
        if (status.policyL4ActiveRevision != status.policyActiveRevision
                || status.policyL4RuleId <= 0L
                || status.policyL4IpFamily != PRODUCT_L4_IP_FAMILY_IPV4
                || status.policyL4IpProtocol != PRODUCT_L4_IP_PROTOCOL_TCP
                || (status.policyL4Direction != PRODUCT_L4_DIRECTION_INPUT
                && status.policyL4Direction != PRODUCT_L4_DIRECTION_OUTPUT)
                || (status.policyL4Action != PRODUCT_POLICY_VERDICT_PASS_NEXT
                && status.policyL4Action != PRODUCT_POLICY_VERDICT_DROP)) {
            return "product_l4_fields_missing";
        }
        if (status.policyWorker0Revision != status.policyActiveRevision
                || status.policyWorker1Revision != status.policyActiveRevision
                || status.policyMixedRevision) {
            return "product_l4_worker_revision_mismatch";
        }
        if (!status.policyArtifactMatch) {
            return "product_l4_artifact_mismatch";
        }
        return "";
    }

    private static RootL4PolicyFacts parseRootL4PolicyFacts(int subjectUid,
                                                            JSONObject rule) {
        JSONObject match = rule.optJSONObject("match");
        if (match == null) {
            throw new IllegalArgumentException("L4 rule match is missing");
        }
        String family = match.optString("family", "");
        if (!AuthoringPolicyBundle.IpFamily.IPV4.wireName.equals(family)) {
            throw new IllegalArgumentException("S191 accepts IPv4 L4 rules only");
        }
        int ipProtocol = match.optInt("ipProtocol", -1);
        if (ipProtocol != PRODUCT_L4_IP_PROTOCOL_TCP) {
            throw new IllegalArgumentException("S191 accepts TCP L4 rules only");
        }
        String directionName = match.optString("direction", "");
        int direction;
        if (AuthoringPolicyBundle.PacketDirection.INPUT.wireName.equals(directionName)) {
            direction = PRODUCT_L4_DIRECTION_INPUT;
        } else if (AuthoringPolicyBundle.PacketDirection.OUTPUT.wireName.equals(directionName)) {
            direction = PRODUCT_L4_DIRECTION_OUTPUT;
        } else {
            throw new IllegalArgumentException("S191 L4 direction is unsupported");
        }
        JSONArray contexts = match.optJSONArray("networkContexts");
        if (contexts == null || contexts.length() != 1) {
            throw new IllegalArgumentException("S191 L4 rule requires one network context");
        }
        int networkContext = contexts.optInt(0, -1);
        if (networkContext <= 0) {
            throw new IllegalArgumentException("S191 L4 network context is invalid");
        }
        String actionName = rule.optString("action", "");
        int action;
        if (AuthoringPolicyBundle.L4Action.DROP.wireName.equals(actionName)) {
            action = PRODUCT_POLICY_VERDICT_DROP;
        } else if (AuthoringPolicyBundle.L4Action.ALLOW.wireName.equals(actionName)) {
            action = PRODUCT_POLICY_VERDICT_PASS_NEXT;
        } else {
            throw new IllegalArgumentException("S191 L4 action is unsupported");
        }
        int[] sourcePorts = parseL4PortRange(match.optJSONObject("sourcePorts"));
        int[] destinationPorts = parseL4PortRange(match.optJSONObject("destinationPorts"));
        long ruleId = rule.optLong("ruleId", -1L);
        int reasonId = rule.optInt("reasonId", -1);
        int priority = rule.optInt("priority", -1);
        int order = rule.optInt("order", -1);
        if (ruleId <= 0L || reasonId <= 0) {
            throw new IllegalArgumentException("S191 L4 rule identity is incomplete");
        }
        if (priority < 0 || order < 0) {
            throw new IllegalArgumentException("S191 L4 priority/order must be non-negative");
        }
        return new RootL4PolicyFacts(subjectUid, networkContext,
                PRODUCT_L4_IP_FAMILY_IPV4, ipProtocol, direction, action,
                normalizedL4Cidr(match.optString("sourceCidr", "")),
                normalizedL4Cidr(match.optString("destinationCidr", "")),
                sourcePorts[0], sourcePorts[1], destinationPorts[0],
                destinationPorts[1], priority, order, ruleId, reasonId);
    }

    private RootL4PolicyFacts currentRootL4PolicyFacts() {
        if (productBackend == null) {
            return null;
        }
        ProductStateSnapshot state = productBackend.productState();
        if (state == null || state.authoringPolicyBundle == null
                || state.authoringPolicyBundle.l4Rules.size() != 1
                || state.authoringPolicyBundle.gateEntryCount != 0) {
            return null;
        }
        AuthoringPolicyBundle.L4Rule rule = state.authoringPolicyBundle.l4Rules.get(0);
        if (rule.family != AuthoringPolicyBundle.IpFamily.IPV4
                || rule.ipProtocol != PRODUCT_L4_IP_PROTOCOL_TCP
                || rule.networkContext == null) {
            return null;
        }
        int direction = rule.direction == AuthoringPolicyBundle.PacketDirection.INPUT
                ? PRODUCT_L4_DIRECTION_INPUT : PRODUCT_L4_DIRECTION_OUTPUT;
        int action = rule.action == AuthoringPolicyBundle.L4Action.DROP
                ? PRODUCT_POLICY_VERDICT_DROP : PRODUCT_POLICY_VERDICT_PASS_NEXT;
        int sourceFirst = rule.sourcePorts == null ? 0 : rule.sourcePorts.first;
        int sourceLast = rule.sourcePorts == null ? 65535 : rule.sourcePorts.last;
        int destinationFirst = rule.destinationPorts == null
                ? 0 : rule.destinationPorts.first;
        int destinationLast = rule.destinationPorts == null
                ? 65535 : rule.destinationPorts.last;
        return new RootL4PolicyFacts(rule.subjectId.uid, rule.networkContext.wireId,
                PRODUCT_L4_IP_FAMILY_IPV4, PRODUCT_L4_IP_PROTOCOL_TCP,
                direction, action, normalizedL4Cidr(rule.sourceCidr),
                normalizedL4Cidr(rule.destinationCidr), sourceFirst, sourceLast,
                destinationFirst, destinationLast, rule.priority, rule.order,
                rule.ruleId, rule.reasonId);
    }

    private static RootL4PolicyFacts rootL4FactsFromPolicyPayload(JSONArray subjects) {
        if (subjects == null || subjects.length() != 1) {
            return null;
        }
        JSONObject subject = subjects.optJSONObject(0);
        if (subject == null || !subject.optBoolean("uidKnown", false)) {
            return null;
        }
        JSONArray rules = subject.optJSONArray("l4Rules");
        if (rules == null || rules.length() != 1) {
            return null;
        }
        int subjectUid = subject.optInt("linuxUid", -1);
        if (subjectUid < 0) {
            return null;
        }
        try {
            return parseRootL4PolicyFacts(subjectUid, rules.getJSONObject(0));
        } catch (JSONException | IllegalArgumentException error) {
            return null;
        }
    }

    private static String networkGateEvidenceStage(RuntimeControlNative.Status status) {
        if (status == null || status.policySnapshotEmpty || status.policyL4RuleCount != 0
                || status.policyGateNetworkContext <= 0
                || status.policyGateReasonId <= 0 || status.policyGateRuleId <= 0L) {
            return "running";
        }
        return status.policyGateBlocked ? "gate_blocked" : "gate_open";
    }

    private void clearNetworkGateEvidenceStage() {
        lastNetworkGateEvidenceStage = "";
        lastNetworkGateEvidenceProfile = null;
        lastNetworkGateEvidenceGeneration = -1L;
        lastNetworkGateEvidenceRevision = -1L;
    }

    private void rememberNetworkGateEvidenceStage(RuntimeControlNative.Status status,
                                                   String stage) {
        if (status == null
                || activeProfile == null
                || (!"gate_blocked".equals(stage) && !"gate_open".equals(stage))
                || status.policyGeneration != generation
                || !status.policyGenerationMatch
                || status.policyRequestedRevision <= 0L
                || status.policyRequestedRevision != status.policyActiveRevision
                || !stage.equals(networkGateEvidenceStage(status))) {
            clearNetworkGateEvidenceStage();
            return;
        }
        lastNetworkGateEvidenceStage = stage;
        lastNetworkGateEvidenceProfile = activeProfile;
        lastNetworkGateEvidenceGeneration = status.policyGeneration;
        lastNetworkGateEvidenceRevision = status.policyActiveRevision;
    }

    private String preservedNetworkGateEvidenceStage(RuntimeControlNative.Status status) {
        if (status == null
                || activeProfile == null
                || lastNetworkGateEvidenceStage.isEmpty()
                || lastNetworkGateEvidenceProfile != activeProfile
                || lastNetworkGateEvidenceGeneration != generation
                || status.policyGeneration != lastNetworkGateEvidenceGeneration
                || !status.policyGenerationMatch
                || status.policyRequestedRevision != lastNetworkGateEvidenceRevision
                || status.policyActiveRevision != lastNetworkGateEvidenceRevision
                || !lastNetworkGateEvidenceStage.equals(networkGateEvidenceStage(status))) {
            clearNetworkGateEvidenceStage();
            return "running";
        }
        return lastNetworkGateEvidenceStage;
    }

    private static String rootL4EvidenceStage(RuntimeControlNative.Status status) {
        if (status != null && !status.policySnapshotEmpty
                && status.policyGateClaimCount == 0
                && status.policyL4RuleCount == 1
                && status.policyL4RuleId > 0L) {
            return "l4_apply";
        }
        return "running";
    }

    /** Report the durable Rust store that actually owns the current snapshot. */
    private static String policyStoreEvidencePath(RuntimeControlNative.Status status,
                                                   String scalarStore) {
        if (status != null
                && AuthoringPolicyBundle.BUNDLE_FORMAT.equals(status.policySnapshotIdentity)) {
            return "product-policy/policy-bundle.properties";
        }
        if (status == null || status.policySnapshotEmpty) {
            return "product-policy/empty-intent.properties";
        }
        return scalarStore;
    }

    private static int[] parseL4PortRange(JSONObject value) {
        if (value == null) {
            return new int[] {0, 65535};
        }
        int first = value.optInt("first", -1);
        int last = value.optInt("last", -1);
        if (first < 0 || last < first || last > 65535) {
            throw new IllegalArgumentException("S191 L4 port range is invalid");
        }
        return new int[] {first, last};
    }

    private static String normalizedL4Cidr(String value) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? "0.0.0.0/0" : trimmed;
    }

    private static final class RootL4PolicyFacts {
        final int subjectUid;
        final int networkContext;
        final int ipFamily;
        final int ipProtocol;
        final int direction;
        final int action;
        final String sourceCidr;
        final String destinationCidr;
        final int sourcePortFirst;
        final int sourcePortLast;
        final int destinationPortFirst;
        final int destinationPortLast;
        final int priority;
        final int order;
        final long ruleId;
        final int reasonId;

        RootL4PolicyFacts(int subjectUid, int networkContext, int ipFamily,
                          int ipProtocol, int direction, int action,
                          String sourceCidr, String destinationCidr,
                          int sourcePortFirst, int sourcePortLast,
                          int destinationPortFirst, int destinationPortLast,
                          int priority, int order, long ruleId, int reasonId) {
            this.subjectUid = subjectUid;
            this.networkContext = networkContext;
            this.ipFamily = ipFamily;
            this.ipProtocol = ipProtocol;
            this.direction = direction;
            this.action = action;
            this.sourceCidr = sourceCidr;
            this.destinationCidr = destinationCidr;
            this.sourcePortFirst = sourcePortFirst;
            this.sourcePortLast = sourcePortLast;
            this.destinationPortFirst = destinationPortFirst;
            this.destinationPortLast = destinationPortLast;
            this.priority = priority;
            this.order = order;
            this.ruleId = ruleId;
            this.reasonId = reasonId;
        }
    }

    private String emptyPolicySnapshotFailureDetail(RuntimeControlNative.Status status,
                                                    String prefix) {
        if (status == null) {
            return prefix + ": status=null";
        }
        String nativeDetail = status.errorDetail == null || status.errorDetail.isEmpty()
                ? "" : " detail=" + status.errorDetail;
        return prefix
                + " code=" + status.code
                + " generation=" + status.generation
                + " policyGeneration=" + status.policyGeneration
                + " requestedRevision=" + status.policyRequestedRevision
                + " activeRevision=" + status.policyActiveRevision
                + " worker0Revision=" + status.policyWorker0Revision
                + " worker1Revision=" + status.policyWorker1Revision
                + " snapshotHash=" + Long.toUnsignedString(status.policySnapshotHash)
                + " snapshotIdentity=" + status.policySnapshotIdentity
                + " snapshotEmpty=" + status.policySnapshotEmpty
                + " defaultPass=" + status.policyDefaultPass
                + " gateClaimCount=" + status.policyGateClaimCount
                + " l4RuleCount=" + status.policyL4RuleCount
                + " gateSubjectUid=" + status.policyGateSubjectUid
                + " gateNetworkContext=" + status.policyGateNetworkContext
                + " gateBlocked=" + status.policyGateBlocked
                + " gateRuleId=" + status.policyGateRuleId
                + " gateReasonId=" + status.policyGateReasonId
                + " lastApplyStatusCode=" + status.policyLastApplyStatusCode
                + " mixedRevision=" + status.policyMixedRevision
                + " artifactMatch=" + status.policyArtifactMatch
                + " generationMatch=" + status.policyGenerationMatch
                + nativeDetail;
    }

    private void appendProductCoreValidationFailureLog(String validation,
                                                       RuntimeControlNative.Status status) {
        if (status == null) {
            appendLog("product_core_validation_failed code=" + validation
                    + " status=null");
            return;
        }
        appendLog("product_core_validation_failed code=" + validation
                + " generation=" + status.generation
                + " adapterAvailable=" + status.adapterAvailable
                + " protectionRunning=" + status.protectionRunning
                + " graphWorkerCount=" + status.productGraphWorkerCount
                + " vppWorkerCount=" + status.productGraphVppWorkerCount
                + " workerLayoutReady=" + status.productGraphWorkerLayoutReady
                + " mainCore=" + status.productGraphVppMainCore
                + " worker0Core=" + status.productGraphVppWorker0Core
                + " worker1Core=" + status.productGraphVppWorker1Core
                + " graphEnabled=" + status.productGraphEnabled
                + " graphAccepting=" + status.productGraphAccepting);
    }

    private boolean publishProductCoreRunning(RuntimeControlNative.Status status, long pid) {
        if (productCoreQueryBlockedByErrorLatch()) {
            appendLog("product_core_running_publish=blocked_by_error_latch generation="
                    + generation);
            return true;
        }
        ProductPacketAdapterContract adapter =
                ProductPacketAdapterContract.forProfile(activeProfile);
        String adapterReadiness = status.adapterAvailable ? adapter.adapterName : RuntimeSnapshot.ADAPTER_UNAVAILABLE;
        boolean published = publish(RuntimeSnapshot.runningProduct(activeProfile,
                VppHealthHandshake.PROTOCOL, status.vppRevision, status.artifactId,
                deviceAbi(), adapterReadiness, status.protectionRunning, pid, generation));
        if (published) {
            writeRootNfqueueStatus(status);
            writeS180VpnUdp4DirectEgressStatus(status);
            writeS181VpnTcp4DirectEgressStatus(status);
            writeS182VpnUdp6DirectEgressStatus(status);
            writeS183VpnTcp6DirectEgressStatus(status);
            writeS184VpnNetworkEpochStatus(status);
            writeS185VpnFaultRecoveryStatus(status);
            writeS187WorkerCoreGuardrailsStatus(status);
            writeS188EmptyPolicySnapshotStatus(status, "running", "", "");
            String gateStage = preservedNetworkGateEvidenceStage(status);
            writeS189RootNetworkGateStatus(status, gateStage, "", "");
            writeS190VpnNetworkGateStatus(status, gateStage, "", "");
            writeS191RootL4Status(status, currentRootL4PolicyFacts(),
                    rootL4EvidenceStage(status), "", "");
            writeS192L4MatrixStatus(status, "running", "", "");
        }
        return published;
    }

    private boolean productCoreQueryBlockedByErrorLatch() {
        RuntimeSnapshot current = snapshot;
        return current != null
                && RuntimeSnapshot.STATE_ERROR.equals(current.state)
                && (!current.mayBeActive
                || "cleanup_failed".equals(current.errorCode));
    }

    private void writeRootNfqueueStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.ROOT || status == null) {
            return;
        }
        String text = "product.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nqueue_id=" + status.rootNfqueueQueueId
                + "\nqueue_last=" + status.rootNfqueueQueueLast
                + "\nqueue_range=" + status.rootNfqueueQueueId + "-"
                + status.rootNfqueueQueueLast
                + "\nlane_count=" + status.rootNfqueueLaneCount
                + "\nready_lane_mask=" + status.rootNfqueueReadyLaneMask
                + "\nhook=OUTPUT"
                + "\nhooks=OUTPUT"
                + "\nfamilies=IPv4"
                + "\nprotocols=UDP"
                + "\ngraph_scope=owner-local"
                + "\nroot_nfqueue_generation=" + status.rootNfqueueGeneration
                + "\norigin_verdict_attempts=" + status.rootNfqueueVerdictAttempts
                + "\ninternal_settlements=" + status.rootNfqueueInternalSettlements
                + "\nbuffer_returns=" + status.rootNfqueueBufferReturns
                + "\norigin_local_completions=" + status.rootNfqueueOriginLocalCompletions
                + "\norigin_remote_completions=" + status.rootNfqueueOriginRemoteCompletions
                + "\nlane0_verdict_attempts=" + status.rootNfqueueLane0VerdictAttempts
                + "\nlane1_verdict_attempts=" + status.rootNfqueueLane1VerdictAttempts
                + "\ninput_packets=" + status.rootNfqueueInputPackets
                + "\noutput_packets=" + status.rootNfqueueOutputPackets
                + "\nipv4_packets=" + status.rootNfqueueIpv4Packets
                + "\nipv6_packets=" + status.rootNfqueueIpv6Packets
                + "\ntcp_packets=" + status.rootNfqueueTcpPackets
                + "\nudp_packets=" + status.rootNfqueueUdpPackets
                + "\nuid_known_packets=" + status.rootNfqueueUidKnownPackets
                + "\nuid_unknown_packets=" + status.rootNfqueueUidUnknownPackets
                + "\nlast_ip_family=" + status.rootNfqueueLastIpFamily
                + "\nlast_protocol=" + status.rootNfqueueLastProtocol
                + "\nlast_hook=" + rootNfqueueHookName(status.rootNfqueueLastHook)
                + "\nlast_hook_code=" + status.rootNfqueueLastHook
                + "\nlast_uid_known=" + (status.rootNfqueueLastUidKnown != 0 ? "true" : "false")
                + "\nlast_uid=" + status.rootNfqueueLastUid
                + "\nlast_queue_id=" + status.rootNfqueueLastQueueId
                + "\nlast_packet_id=" + status.rootNfqueueLastPacketId
                + "\nfault_mode=" + rootNfqueueFaultMode
                + "\nverdict_succeeded=" + status.rootNfqueueVerdictSucceeded
                + "\nverdict_failed_definite=" + status.rootNfqueueVerdictFailedDefinite
                + "\nverdict_outcome_unknown=" + status.rootNfqueueVerdictOutcomeUnknown
                + "\ningress_identity_missing=" + status.rootNfqueueIngressIdentityMissing
                + "\ngraph_submit_fail_opens=" + status.rootNfqueueGraphSubmitFailOpens
                + "\nnon_owner_bypasses=" + status.rootNfqueueNonOwnerBypasses
                + "\nduplicate_completion_drops=" + status.rootNfqueueDuplicateCompletionDrops
                + "\nstale_completion_drops=" + status.rootNfqueueStaleCompletionDrops
                + "\ncontrolled_lan_response=" + s176ControlledLanResponse()
                + "\n";
        writeBestEffortEvidenceFile(S176_ROOT_NFQUEUE_OUTPUT_STATUS, text);
        writeBestEffortEvidenceFile(S177_ROOT_NFQUEUE_MULTILANE_STATUS, text);
        writeBestEffortEvidenceFile(S178_ROOT_NFQUEUE_MATRIX_STATUS, text);
        writeBestEffortEvidenceFile(S179_ROOT_FAULT_RECOVERY_STATUS, text);
    }

    private void writeS180VpnUdp4DirectEgressStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.VPN || status == null) {
            return;
        }
        String text = "product.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nadapter=" + ProductPacketAdapterContract.VPN_ADAPTER
                + "\nadapterReadiness=" + RuntimeSnapshot.ADAPTER_UNAVAILABLE
                + "\nprofile=vpn"
                + "\ngeneration=" + status.generation
                + "\npolicy_default_pass=1"
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\nvpn_direct_udp4_socket_attached=" + status.vpnDirectUdp4SocketAttached
                + "\nvpn_direct_udp4_protect_succeeded="
                + status.vpnDirectUdp4ProtectSucceeded
                + "\nvpn_direct_udp4_bind_succeeded="
                + status.vpnDirectUdp4BindSucceeded
                + "\nvpn_tun_ingress_packets=" + (status == null ? 0L
                : status.vpnTunIngressPackets)
                + "\nvpn_tun_udp4_tun_origin_packets="
                + status.vpnTunUdp4TunOriginPackets
                + "\nvpn_flow_stack_admissions=" + (status == null ? 0L
                : status.vpnFlowStackAdmissions)
                + "\nvpn_direct_udp4_send_succeeded="
                + status.vpnDirectUdp4SendSucceeded
                + "\nvpn_direct_udp4_transport_failed="
                + status.vpnDirectUdp4TransportFailed
                + "\nvpn_flow_stack_return_packets=" + status.vpnFlowStackReturnPackets
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\ncontrolled_lan_response=" + s180ControlledLanResponse(status)
                + "\n";
        writeBestEffortEvidenceFile(S180_VPN_UDP4_DIRECT_EGRESS_STATUS, text);
    }

    private static String rootNfqueueHookName(int hook) {
        if (hook == 1) {
            return "INPUT";
        }
        if (hook == 3) {
            return "OUTPUT";
        }
        return Integer.toString(hook);
    }

    private static int l4DirectionToDeviceDirection(int direction) {
        if (direction == PRODUCT_L4_DIRECTION_INPUT) {
            return PRODUCT_DEVICE_DIRECTION_INPUT;
        }
        if (direction == PRODUCT_L4_DIRECTION_OUTPUT) {
            return PRODUCT_DEVICE_DIRECTION_OUTPUT;
        }
        return 0;
    }

    private static String l4DirectionName(int direction) {
        if (direction == PRODUCT_L4_DIRECTION_INPUT) {
            return "INPUT";
        }
        if (direction == PRODUCT_L4_DIRECTION_OUTPUT) {
            return "OUTPUT";
        }
        return Integer.toString(direction);
    }

    private static String vpnPacketOriginName(int origin) {
        if (origin == 1) {
            return "TUN";
        }
        if (origin == 2) {
            return "FLOW_STACK";
        }
        return Integer.toString(origin);
    }

    /* Device direction and adapter provenance are separate facts.  The graph
     * status exposes the former; S190 gets the latter from the VPN adapter's
     * TUN-origin counter rather than reinterpreting the direction value. */
    private static int vpnPolicyDropPacketOriginCode(RuntimeControlNative.Status status,
                                                     JSONObject vpnStatus) {
        if (status == null
                || status.policyLastDropDeviceDirection != PRODUCT_DEVICE_DIRECTION_OUTPUT
                || vpnStatus == null
                || vpnStatus.optLong("vpnTunTcp4TunOriginPackets", 0L) <= 0L) {
            return 0;
        }
        return 1;
    }

    private void writeS176RootNfqueueCleanupStatus(boolean clean) {
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        if (selected != RuntimeProfile.ROOT) {
            return;
        }
        writeBestEffortEvidenceFile(S176_ROOT_NFQUEUE_CLEANUP_STATUS,
                "productRootNfqueueResidueClean=" + clean + "\n");
    }

    private String s176ControlledLanResponse() {
        File file = new File(getFilesDir(), DEBUG_TRAFFIC_PROBE_RESULT);
        if (!file.isFile()) {
            return "not_matched";
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(file)) {
            values.load(input);
        } catch (IOException error) {
            return "not_matched";
        }
        String result = values.getProperty("result", "");
        return ("tcp_connect_succeeded".equals(result) || "tcp_echo_matched".equals(result))
                ? "matched" : "not_matched";
    }

    private String s180ControlledLanResponse(RuntimeControlNative.Status status) {
        return status.vpnFlowStackReturnProvenancePackets > 0
                && status.vpnTunWriteCompletions > 0
                && status.vpnDirectUdp4TransportFailed == 0
                ? "matched" : "not_matched";
    }

    private void writeS181VpnTcp4DirectEgressStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.VPN || status == null) {
            return;
        }
        RuntimeControlFdClient.AttachResult nativeStatus = RuntimeControlFdClient.callJson(
                181, "VPN_TUN.STATUS", new JSONObject());
        JSONObject result = nativeStatus.ok ? nativeStatus.result : new JSONObject();
        long returnPackets = result.optLong("vpnDirectTcp4ReturnPackets", 0L);
        long tunWrites = result.optLong("vpnDirectTcp4TunWriteCompletions", 0L);
        String text = "product.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nadapter=" + ProductPacketAdapterContract.VPN_ADAPTER
                + "\nadapterReadiness=" + RuntimeSnapshot.ADAPTER_UNAVAILABLE
                + "\nprofile=vpn"
                + "\ngeneration=" + status.generation
                + "\npolicy_default_pass=1"
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\nvpn_direct_tcp4_status_available=" + (nativeStatus.ok ? "1" : "0")
                + "\nvpn_direct_tcp4_socket_attached="
                + result.optLong("vpnDirectTcp4SocketAttached", 0L)
                + "\nvpn_direct_tcp4_protect_succeeded="
                + result.optLong("vpnDirectTcp4ProtectSucceeded", 0L)
                + "\nvpn_direct_tcp4_bind_succeeded="
                + result.optLong("vpnDirectTcp4BindSucceeded", 0L)
                + "\nvpn_tun_ingress_packets=" + (status == null ? 0L
                : status.vpnTunIngressPackets)
                + "\nvpn_tun_tcp4_tun_origin_packets="
                + result.optLong("vpnTunTcp4TunOriginPackets", 0L)
                + "\nvpn_flow_stack_admissions=" + (status == null ? 0L
                : status.vpnFlowStackAdmissions)
                + "\nvpn_direct_tcp4_connect_attempts="
                + result.optLong("vpnDirectTcp4ConnectAttempts", 0L)
                + "\nvpn_direct_tcp4_connect_succeeded="
                + result.optLong("vpnDirectTcp4ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp4_payload_bytes_from_tun="
                + result.optLong("vpnDirectTcp4PayloadBytesFromTun", 0L)
                + "\nvpn_direct_tcp4_socket_write_completions="
                + result.optLong("vpnDirectTcp4SocketWriteCompletions", 0L)
                + "\nvpn_direct_tcp4_socket_read_packets="
                + result.optLong("vpnDirectTcp4SocketReadPackets", 0L)
                + "\nvpn_direct_tcp4_return_packets=" + returnPackets
                + "\nvpn_direct_tcp4_tun_write_completions=" + tunWrites
                + "\nvpn_direct_tcp4_transport_failed="
                + result.optLong("vpnDirectTcp4TransportFailed", 0L)
                + "\nvpn_direct_tcp4_close_completions="
                + result.optLong("vpnDirectTcp4CloseCompletions", 0L)
                + "\nvpn_direct_tcp4_last_errno="
                + result.optLong("vpnDirectTcp4LastErrno", 0L)
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\ncontrolled_lan_response="
                + (returnPackets > 0 && tunWrites > 0 ? "matched" : "not_matched")
                + "\n";
        writeBestEffortEvidenceFile(S181_VPN_TCP4_DIRECT_EGRESS_STATUS, text);
    }

    private void writeS182VpnUdp6DirectEgressStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.VPN || status == null) {
            return;
        }
        RuntimeControlFdClient.AttachResult nativeStatus = RuntimeControlFdClient.callJson(
                182, "VPN_TUN.STATUS", new JSONObject());
        JSONObject result = nativeStatus.ok ? nativeStatus.result : new JSONObject();
        long returnPackets = result.optLong("vpnDirectUdp6ReturnPackets", 0L);
        long tunWrites = result.optLong("vpnDirectUdp6TunWriteCompletions", 0L);
        long transportFailed = result.optLong("vpnDirectUdp6TransportFailed", 0L);
        String text = "product.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nadapter=" + ProductPacketAdapterContract.VPN_ADAPTER
                + "\nadapterReadiness=" + RuntimeSnapshot.ADAPTER_UNAVAILABLE
                + "\nprofile=vpn"
                + "\ngeneration=" + status.generation
                + "\npolicy_default_pass=1"
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\nvpn_direct_udp6_status_available=" + (nativeStatus.ok ? "1" : "0")
                + "\nvpn_direct_udp6_socket_attached="
                + result.optLong("vpnDirectUdp6SocketAttached", 0L)
                + "\nvpn_direct_udp6_protect_succeeded="
                + result.optLong("vpnDirectUdp6ProtectSucceeded", 0L)
                + "\nvpn_direct_udp6_bind_succeeded="
                + result.optLong("vpnDirectUdp6BindSucceeded", 0L)
                + "\nvpn_tun_ingress_packets=" + (status == null ? 0L
                : status.vpnTunIngressPackets)
                + "\nvpn_tun_udp6_tun_origin_packets="
                + result.optLong("vpnTunUdp6TunOriginPackets", 0L)
                + "\nvpn_flow_stack_admissions=" + (status == null ? 0L
                : status.vpnFlowStackAdmissions)
                + "\nvpn_direct_udp6_send_succeeded="
                + result.optLong("vpnDirectUdp6SendSucceeded", 0L)
                + "\nvpn_direct_udp6_return_packets=" + returnPackets
                + "\nvpn_direct_udp6_tun_write_completions=" + tunWrites
                + "\nvpn_direct_udp6_transport_failed=" + transportFailed
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\ncontrolled_lan_response="
                + (returnPackets > 0 && tunWrites > 0 && transportFailed == 0
                ? "matched" : "not_matched")
                + "\n";
        writeBestEffortEvidenceFile(S182_VPN_UDP6_DIRECT_EGRESS_STATUS, text);
    }

    private void writeS183VpnTcp6DirectEgressStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.VPN || status == null) {
            return;
        }
        RuntimeControlFdClient.AttachResult nativeStatus = RuntimeControlFdClient.callJson(
                183, "VPN_TUN.STATUS", new JSONObject());
        JSONObject result = nativeStatus.ok ? nativeStatus.result : new JSONObject();
        long returnPackets = result.optLong("vpnDirectTcp6ReturnPackets", 0L);
        long tunWrites = result.optLong("vpnDirectTcp6TunWriteCompletions", 0L);
        long transportFailed = result.optLong("vpnDirectTcp6TransportFailed", 0L);
        String text = "product.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nadapter=" + ProductPacketAdapterContract.VPN_ADAPTER
                + "\nadapterReadiness=" + RuntimeSnapshot.ADAPTER_UNAVAILABLE
                + "\nprofile=vpn"
                + "\ngeneration=" + status.generation
                + "\npolicy_default_pass=1"
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\nvpn_direct_tcp6_status_available=" + (nativeStatus.ok ? "1" : "0")
                + "\nvpn_direct_tcp6_socket_attached="
                + result.optLong("vpnDirectTcp6SocketAttached", 0L)
                + "\nvpn_direct_tcp6_protect_succeeded="
                + result.optLong("vpnDirectTcp6ProtectSucceeded", 0L)
                + "\nvpn_direct_tcp6_bind_succeeded="
                + result.optLong("vpnDirectTcp6BindSucceeded", 0L)
                + "\nvpn_tun_ingress_packets=" + (status == null ? 0L
                : status.vpnTunIngressPackets)
                + "\nvpn_tun_tcp6_tun_origin_packets="
                + result.optLong("vpnTunTcp6TunOriginPackets", 0L)
                + "\nvpn_flow_stack_admissions=" + (status == null ? 0L
                : status.vpnFlowStackAdmissions)
                + "\nvpn_direct_tcp6_connect_attempts="
                + result.optLong("vpnDirectTcp6ConnectAttempts", 0L)
                + "\nvpn_direct_tcp6_connect_succeeded="
                + result.optLong("vpnDirectTcp6ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp6_payload_bytes_from_tun="
                + result.optLong("vpnDirectTcp6PayloadBytesFromTun", 0L)
                + "\nvpn_direct_tcp6_socket_write_completions="
                + result.optLong("vpnDirectTcp6SocketWriteCompletions", 0L)
                + "\nvpn_direct_tcp6_socket_read_packets="
                + result.optLong("vpnDirectTcp6SocketReadPackets", 0L)
                + "\nvpn_direct_tcp6_return_packets=" + returnPackets
                + "\nvpn_direct_tcp6_tun_write_completions=" + tunWrites
                + "\nvpn_direct_tcp6_transport_failed=" + transportFailed
                + "\nvpn_direct_tcp6_close_completions="
                + result.optLong("vpnDirectTcp6CloseCompletions", 0L)
                + "\nvpn_direct_tcp6_last_errno="
                + result.optLong("vpnDirectTcp6LastErrno", 0L)
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\ncontrolled_lan_response="
                + (returnPackets > 0 && tunWrites > 0 && transportFailed == 0
                ? "matched" : "not_matched")
                + "\n";
        writeBestEffortEvidenceFile(S183_VPN_TCP6_DIRECT_EGRESS_STATUS, text);
    }

    private void writeS184VpnNetworkEpochStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.VPN || status == null) {
            return;
        }
        RuntimeControlFdClient.AttachResult nativeStatus = RuntimeControlFdClient.callJson(
                184, "VPN_TUN.STATUS", new JSONObject());
        JSONObject result = nativeStatus.ok ? nativeStatus.result : new JSONObject();
        boolean handlesConsistent = vpnDirectUdp4NetworkHandle >= 0
                && vpnDirectUdp4NetworkHandle == vpnDirectUdp6NetworkHandle
                && vpnDirectUdp4NetworkHandle == vpnDirectTcp4NetworkHandle
                && vpnDirectUdp4NetworkHandle == vpnDirectTcp6NetworkHandle;
        String text = "product.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nadapter=" + ProductPacketAdapterContract.VPN_ADAPTER
                + "\nadapterReadiness=" + RuntimeSnapshot.ADAPTER_UNAVAILABLE
                + "\nprofile=vpn"
                + "\ngeneration=" + status.generation
                + "\nnetwork_context_snapshot=explicit_underlay_at_socket_creation"
                + "\nset_underlying_networks=explicit_bound_underlay"
                + "\nvpn_direct_underlay_epoch=" + vpnDirectUnderlayEpoch
                + "\nvpn_direct_underlay_transport=" + vpnDirectUnderlayTransport
                + "\nvpn_direct_underlay_network_handle=" + vpnDirectUnderlayNetworkHandle
                + "\nvpn_direct_udp4_network_handle=" + vpnDirectUdp4NetworkHandle
                + "\nvpn_direct_udp6_network_handle=" + vpnDirectUdp6NetworkHandle
                + "\nvpn_direct_tcp4_network_handle=" + vpnDirectTcp4NetworkHandle
                + "\nvpn_direct_tcp6_network_handle=" + vpnDirectTcp6NetworkHandle
                + "\nvpn_direct_underlay_handles_consistent=" + handlesConsistent
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\nvpn_direct_udp4_socket_attached="
                + result.optLong("vpnDirectUdp4SocketAttached", 0L)
                + "\nvpn_direct_udp4_protect_succeeded="
                + result.optLong("vpnDirectUdp4ProtectSucceeded", 0L)
                + "\nvpn_direct_udp4_bind_succeeded="
                + result.optLong("vpnDirectUdp4BindSucceeded", 0L)
                + "\nvpn_direct_udp6_socket_attached="
                + result.optLong("vpnDirectUdp6SocketAttached", 0L)
                + "\nvpn_direct_udp6_protect_succeeded="
                + result.optLong("vpnDirectUdp6ProtectSucceeded", 0L)
                + "\nvpn_direct_udp6_bind_succeeded="
                + result.optLong("vpnDirectUdp6BindSucceeded", 0L)
                + "\nvpn_direct_tcp4_socket_attached="
                + result.optLong("vpnDirectTcp4SocketAttached", 0L)
                + "\nvpn_direct_tcp4_protect_succeeded="
                + result.optLong("vpnDirectTcp4ProtectSucceeded", 0L)
                + "\nvpn_direct_tcp4_bind_succeeded="
                + result.optLong("vpnDirectTcp4BindSucceeded", 0L)
                + "\nvpn_direct_tcp6_socket_attached="
                + result.optLong("vpnDirectTcp6SocketAttached", 0L)
                + "\nvpn_direct_tcp6_protect_succeeded="
                + result.optLong("vpnDirectTcp6ProtectSucceeded", 0L)
                + "\nvpn_direct_tcp6_bind_succeeded="
                + result.optLong("vpnDirectTcp6BindSucceeded", 0L)
                + "\nvpn_tun_udp4_tun_origin_packets="
                + result.optLong("vpnTunUdp4TunOriginPackets", 0L)
                + "\nvpn_tun_udp6_tun_origin_packets="
                + result.optLong("vpnTunUdp6TunOriginPackets", 0L)
                + "\nvpn_tun_tcp4_tun_origin_packets="
                + result.optLong("vpnTunTcp4TunOriginPackets", 0L)
                + "\nvpn_tun_tcp6_tun_origin_packets="
                + result.optLong("vpnTunTcp6TunOriginPackets", 0L)
                + "\nvpn_direct_udp4_send_succeeded="
                + result.optLong("vpnDirectUdp4SendSucceeded", 0L)
                + "\nvpn_direct_udp4_transport_failed="
                + status.vpnDirectUdp4TransportFailed
                + "\nvpn_direct_udp6_send_succeeded="
                + result.optLong("vpnDirectUdp6SendSucceeded", 0L)
                + "\nvpn_direct_udp6_transport_failed="
                + result.optLong("vpnDirectUdp6TransportFailed", 0L)
                + "\nvpn_direct_tcp4_connect_succeeded="
                + result.optLong("vpnDirectTcp4ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp4_transport_failed="
                + result.optLong("vpnDirectTcp4TransportFailed", 0L)
                + "\nvpn_direct_tcp6_connect_succeeded="
                + result.optLong("vpnDirectTcp6ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp6_transport_failed="
                + result.optLong("vpnDirectTcp6TransportFailed", 0L)
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\n";
        writeBestEffortEvidenceFile(S184_VPN_NETWORK_EPOCH_STATUS, text);
    }

    private void writeS185VpnFaultRecoveryStatus(RuntimeControlNative.Status status) {
        if (activeProfile != RuntimeProfile.VPN || status == null) {
            return;
        }
        RuntimeControlFdClient.AttachResult nativeStatus = RuntimeControlFdClient.callJson(
                185, "VPN_TUN.STATUS", new JSONObject());
        JSONObject result = nativeStatus.ok ? nativeStatus.result : new JSONObject();
        String text = "schema=s185-vpn-fault-recovery/v1"
                + "\nstage=running"
                + "\nprofile=vpn"
                + "\nstate=running"
                + "\nerrorCode="
                + "\nmayBeActive=true"
                + "\nvpn_fault_mode=" + vpnFaultMode
                + "\nproduct.adapter_available=" + (status.adapterAvailable ? "1" : "0")
                + "\nadapterReadiness="
                + (status.adapterAvailable ? ProductPacketAdapterContract.VPN_ADAPTER
                : RuntimeSnapshot.ADAPTER_UNAVAILABLE)
                + "\nprotectionRunning=" + status.protectionRunning
                + "\ngeneration=" + status.generation
                + "\nvpn_status_available=" + (nativeStatus.ok ? "1" : "0")
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\nvpn_direct_udp4_socket_attached="
                + result.optLong("vpnDirectUdp4SocketAttached", 0L)
                + "\nvpn_direct_udp6_socket_attached="
                + result.optLong("vpnDirectUdp6SocketAttached", 0L)
                + "\nvpn_direct_tcp4_socket_attached="
                + result.optLong("vpnDirectTcp4SocketAttached", 0L)
                + "\nvpn_direct_tcp6_socket_attached="
                + result.optLong("vpnDirectTcp6SocketAttached", 0L)
                + "\nvpn_tun_udp4_tun_origin_packets="
                + result.optLong("vpnTunUdp4TunOriginPackets", 0L)
                + "\nvpn_tun_udp6_tun_origin_packets="
                + result.optLong("vpnTunUdp6TunOriginPackets", 0L)
                + "\nvpn_tun_tcp4_tun_origin_packets="
                + result.optLong("vpnTunTcp4TunOriginPackets", 0L)
                + "\nvpn_tun_tcp6_tun_origin_packets="
                + result.optLong("vpnTunTcp6TunOriginPackets", 0L)
                + "\nvpn_flow_stack_admissions=" + (status == null ? 0L
                : status.vpnFlowStackAdmissions)
                + "\nvpn_direct_udp4_send_succeeded="
                + result.optLong("vpnDirectUdp4SendSucceeded", 0L)
                + "\nvpn_direct_udp4_transport_failed="
                + result.optLong("vpnDirectUdp4TransportFailed", 0L)
                + "\nvpn_direct_udp6_send_succeeded="
                + result.optLong("vpnDirectUdp6SendSucceeded", 0L)
                + "\nvpn_direct_udp6_transport_failed="
                + result.optLong("vpnDirectUdp6TransportFailed", 0L)
                + "\nvpn_direct_tcp4_connect_succeeded="
                + result.optLong("vpnDirectTcp4ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp4_transport_failed="
                + result.optLong("vpnDirectTcp4TransportFailed", 0L)
                + "\nvpn_direct_tcp6_connect_succeeded="
                + result.optLong("vpnDirectTcp6ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp6_transport_failed="
                + result.optLong("vpnDirectTcp6TransportFailed", 0L)
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\npolicy_verdict_separate=policy_default_pass"
                + "\nadapter_completion_separate=vpn_tun_and_flow_stack_counters"
                + "\ntransport_outcome_separate=direct_socket_counters"
                + "\ninfrastructure_fault_separate=vpn_infrastructure_faults"
                + "\n";
        writeBestEffortEvidenceFile(S185_VPN_FAULT_RECOVERY_STATUS, text);
    }

    private void writeS185VpnFaultRecoveryErrorStatus(RuntimeSnapshot value) {
        if (value == null || value.profile != RuntimeProfile.VPN) {
            return;
        }
        String text = "schema=s185-vpn-fault-recovery/v1"
                + "\nstage=error"
                + "\nprofile=vpn"
                + "\nstate=" + value.state
                + "\nerrorCode=" + value.errorCode
                + "\nerrorMessage=" + value.errorMessage
                + "\nmayBeActive=" + value.mayBeActive
                + "\nvpn_fault_mode=" + vpnFaultMode
                + "\nproduct.adapter_available=0"
                + "\nadapterReadiness=" + value.adapterReadiness
                + "\nprotectionRunning=" + value.protectionRunning
                + "\ngeneration=" + value.generation
                + "\nlast_vpn_fault_event=" + lastVpnFaultEvent
                + "\nlast_vpn_fault_tun_ready=" + lastVpnFaultTunReady
                + "\nlast_vpn_fault_transport_fd_attached="
                + lastVpnFaultTransportFdAttached
                + "\nlast_vpn_fault_infrastructure_faults="
                + lastVpnFaultInfrastructureFaults
                + "\nlast_vpn_fault_duplicate_or_stale_drops="
                + lastVpnFaultDuplicateOrStaleDrops
                + "\npolicy_verdict_separate=not_rewritten_by_runtime_fault"
                + "\nadapter_completion_separate=not_rewritten_by_runtime_fault"
                + "\ntransport_outcome_separate=not_rewritten_by_runtime_fault"
                + "\ninfrastructure_fault_separate=runtime_error_projection"
                + "\n";
        writeBestEffortEvidenceFile(S185_VPN_FAULT_RECOVERY_STATUS, text);
    }

    private void writeS185VpnFaultEventStatus(String event,
                                              RuntimeControlFdClient.AttachResult nativeStatus) {
        JSONObject result = nativeStatus != null && nativeStatus.ok
                ? nativeStatus.result : new JSONObject();
        lastVpnFaultEvent = BoundedText.value(event, RuntimeSnapshot.MAX_TEXT_LENGTH);
        lastVpnFaultTunReady = result.optBoolean("tunReady", false);
        lastVpnFaultTransportFdAttached =
                result.optBoolean("transportFdAttached", false);
        lastVpnFaultInfrastructureFaults =
                result.optLong("vpnInfrastructureFaults", -1L);
        lastVpnFaultDuplicateOrStaleDrops =
                result.optLong("vpnDuplicateOrStaleDrops", -1L);
        String text = "schema=s185-vpn-fault-recovery/v1"
                + "\nstage=fault_event"
                + "\nprofile=vpn"
                + "\nfault_event=" + event
                + "\nvpn_fault_mode=" + vpnFaultMode
                + "\nvpn_status_available="
                + (nativeStatus != null && nativeStatus.ok ? "1" : "0")
                + "\nerrorCode="
                + (nativeStatus == null || nativeStatus.ok ? "" : nativeStatus.errorCode)
                + "\nerrorMessage="
                + (nativeStatus == null || nativeStatus.ok ? "" : nativeStatus.errorMessage)
                + "\nproduct.adapter_available="
                + (result.optBoolean("fdAttached", false)
                && result.optBoolean("transportFdAttached", false) ? "1" : "0")
                + "\ntunReady=" + result.optBoolean("tunReady", false)
                + "\ntransportFdAttached=" + result.optBoolean("transportFdAttached", false)
                + "\nvpn_tun_fd_attached=" + result.optLong("vpnTunFdAttached", 0L)
                + "\nvpn_infrastructure_faults="
                + result.optLong("vpnInfrastructureFaults", 0L)
                + "\nvpn_duplicate_or_stale_drops="
                + result.optLong("vpnDuplicateOrStaleDrops", 0L)
                + "\n";
        writeBestEffortEvidenceFile(S185_VPN_FAULT_RECOVERY_STATUS, text);
    }

    private void writeS186ProfileSwitchBarrierStatus(RuntimeSnapshot value) {
        if (value == null) {
            return;
        }
        String text = "schema=s186-profile-switch-barrier/v1"
                + "\nstage=" + value.state
                + "\nprofile=" + value.profile.wireName
                + "\nstate=" + value.state
                + "\nerrorCode=" + value.errorCode
                + "\nmayBeActive=" + value.mayBeActive
                + "\nprotectionRunning=" + value.protectionRunning
                + "\nadapterReadiness=" + value.adapterReadiness
                + "\ngeneration=" + value.generation
                + "\njava_supervisor_single_switch_authority=true"
                + "\nroot_vpn_mutual_exclusion=one_profile_per_generation"
                + "\nreplacement_blocked_on_cleanup_failure=true"
                + "\nold_generation_callbacks_guarded=process_handle_and_vapi_generation"
                + "\n";
        writeBestEffortEvidenceFile(S186_PROFILE_SWITCH_BARRIER_STATUS, text);
    }

    private void writeS187WorkerCoreGuardrailsStatus(RuntimeControlNative.Status status) {
        if (status == null || activeProfile == null) {
            return;
        }
        String text = "schema=s187-worker-core-guardrails/v1"
                + "\nstage=running"
                + "\nprofile=" + activeProfile.wireName
                + "\nstate=running"
                + "\nerrorCode="
                + "\nmayBeActive=true"
                + "\ngeneration=" + status.generation
                + "\nplacement_fixed_before_start=true"
                + "\nmain_core=" + PRODUCT_CORE_MAIN_CORE
                + "\nworker_count=" + PRODUCT_CORE_WORKER_COUNT
                + "\nworker_cores=" + PRODUCT_CORE_WORKER_CORES
                + "\nvpp_main_core=" + status.productGraphVppMainCore
                + "\nvpp_worker_count=" + status.productGraphVppWorkerCount
                + "\nvpp_worker0_thread_index=" + status.productGraphVppWorker0ThreadIndex
                + "\nvpp_worker0_core=" + status.productGraphVppWorker0Core
                + "\nvpp_worker1_thread_index=" + status.productGraphVppWorker1ThreadIndex
                + "\nvpp_worker1_core=" + status.productGraphVppWorker1Core
                + "\nworker_core_config_match=" + s187WorkerCoreConfigMatches(status)
                + "\nowner_mapping=" + PRODUCT_CORE_OWNER_MAPPING
                + "\nowner_mapping_seed=" + PRODUCT_CORE_OWNER_MAPPING_SEED
                + "\ndynamic_worker_change=false"
                + "\nruntime_resize=false"
                + "\nruntime_reshard=false"
                + "\nproduct_graph_worker_count=" + status.productGraphWorkerCount
                + "\nproduct_graph_flow_domain=" + status.productGraphFlowDomain
                + "\nproduct_graph_hash_seed=" + status.productGraphHashSeed
                + "\nproduct_graph_handoff_credits=" + status.productGraphHandoffCredits
                + "\nproduct_graph_enabled=" + status.productGraphEnabled
                + "\nproduct_graph_accepting=" + status.productGraphAccepting
                + "\nproduct_graph_worker_layout_ready="
                + (status.productGraphWorkerLayoutReady != 0)
                + "\nproduct_graph_obligation_debt=" + status.productGraphObligationDebt
                + "\nproduct_graph_buffer_debt=" + status.productGraphBufferDebt
                + "\nproduct_graph_handoff_debt=" + status.productGraphHandoffDebt
                + "\nflow_pool_capacity=0"
                + "\nworker_cache_capacity=0"
                + "\ntelemetry=low_cardinality_status_and_runner_samples"
                + "\nthreshold_scope=engineering_guardrail_not_release_slo"
                + "\nartifact_id=" + status.artifactId
                + "\napi_identity=" + status.apiIdentity
                + "\nvpp_revision=" + status.vppRevision
                + "\nroot_queue_range=" + PRODUCT_ROOT_NFQUEUE_QUEUE + "-"
                + PRODUCT_ROOT_NFQUEUE_QUEUE_LAST
                + "\nroot_nfqueue_lane_count=" + status.rootNfqueueLaneCount
                + "\nvpn_tun_fd_attached=" + status.vpnTunFdAttached
                + "\n";
        writeBestEffortEvidenceFile(S187_WORKER_CORE_GUARDRAILS_STATUS, text);
    }

    private void writeS188EmptyPolicySnapshotStatus(RuntimeControlNative.Status status,
                                                    String stage,
                                                    String errorCode,
                                                    String errorMessage) {
        RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        long statusGeneration = status == null ? generation : status.generation;
        long requestedRevision = status == null ? 0L : status.policyRequestedRevision;
        long activeRevision = status == null ? 0L : status.policyActiveRevision;
        long policyGeneration = status == null ? 0L : status.policyGeneration;
        long worker0Revision = status == null ? 0L : status.policyWorker0Revision;
        long worker1Revision = status == null ? 0L : status.policyWorker1Revision;
        boolean revisionMatch = requestedRevision > 0L && requestedRevision == activeRevision;
        boolean generationMatch = status != null && status.policyGenerationMatch
                && policyGeneration == statusGeneration && statusGeneration > 0L;
        boolean workerRevisionMatch = activeRevision > 0L
                && worker0Revision == activeRevision
                && worker1Revision == activeRevision
                && status != null && !status.policyMixedRevision;
        boolean defaultPass = status != null && status.policySnapshotEmpty
                && status.policyDefaultPass;
        boolean noGateL4Claim = status == null
                || (status.policyGateClaimCount == 0 && status.policyL4RuleCount == 0);
        String code = errorCode == null ? "" : errorCode;
        String detail = errorMessage == null ? "" : errorMessage;
        String text = "schema=s188-empty-policy-snapshot/v1"
                + "\nstage=" + BoundedText.value(stage, RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\nprofile=" + profile.wireName
                + "\nstate=" + (code.isEmpty() ? "running" : "error")
                + "\nerrorCode=" + code
                + "\nerrorMessage=" + BoundedText.value(detail,
                RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\ngeneration=" + statusGeneration
                + "\nrequested_revision=" + requestedRevision
                + "\nactive_revision=" + activeRevision
                + "\nrevision_match=" + revisionMatch
                + "\npolicy_generation=" + policyGeneration
                + "\ngeneration_match=" + generationMatch
                + "\npolicy_snapshot_hash=" + (status == null ? "0"
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity=" + (status == null ? ""
                : status.policySnapshotIdentity)
                + "\npolicy_snapshot_empty=" + (status != null
                && status.policySnapshotEmpty)
                + "\npolicy_default_pass=" + (status != null
                && status.policyDefaultPass)
                + "\nempty_default_pass=" + defaultPass
                + "\ngate_claim_count=" + (status == null ? 0
                : status.policyGateClaimCount)
                + "\nl4_rule_count=" + (status == null ? 0 : status.policyL4RuleCount)
                + "\nno_gate_l4_claim=" + noGateL4Claim
                + "\nworker0_revision=" + worker0Revision
                + "\nworker1_revision=" + worker1Revision
                + "\nworker_revision_match=" + workerRevisionMatch
                + "\npolicy_mixed_revision=" + (status != null
                && status.policyMixedRevision)
                + "\nsubmission_status_code=" + (status == null ? -1
                : status.policyLastApplyStatusCode)
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nartifact_match=" + (status != null && status.policyArtifactMatch)
                + "\nartifact_id=" + (status == null ? "" : status.artifactId)
                + "\napi_identity=" + (status == null ? "" : status.apiIdentity)
                + "\nvpp_revision=" + (status == null ? "" : status.vppRevision)
                + "\nrust_product_store=product-policy/empty-intent.properties"
                + "\nrust_product_store_single_writer=true"
                + "\nui_policy_authority=false"
                + "\nvpp_policy_authority=false"
                + "\ntraffic_behavior_changed=false"
                + "\n";
        writeBestEffortEvidenceFile(S188_EMPTY_POLICY_SNAPSHOT_STATUS, text);
    }

    private void writeS189RootNetworkGateStatus(RuntimeControlNative.Status status,
                                                String stage,
                                                String errorCode,
                                                String errorMessage) {
        RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        if (profile != RuntimeProfile.ROOT) {
            return;
        }
        long statusGeneration = status == null ? generation : status.generation;
        long requestedRevision = status == null ? 0L : status.policyRequestedRevision;
        long activeRevision = status == null ? 0L : status.policyActiveRevision;
        long policyGeneration = status == null ? 0L : status.policyGeneration;
        long worker0Revision = status == null ? 0L : status.policyWorker0Revision;
        long worker1Revision = status == null ? 0L : status.policyWorker1Revision;
        boolean revisionMatch = requestedRevision > 0L && requestedRevision == activeRevision;
        boolean generationMatch = status != null && status.policyGenerationMatch
                && policyGeneration == statusGeneration && statusGeneration > 0L;
        boolean workerRevisionMatch = activeRevision > 0L
                && worker0Revision == activeRevision
                && worker1Revision == activeRevision
                && status != null && !status.policyMixedRevision;
        boolean gateSnapshot = status != null
                && !status.policySnapshotEmpty
                && status.policyDefaultPass
                && status.policyL4RuleCount == 0
                && status.policyGateSubjectUid >= 0
                && status.policyGateNetworkContext > 0
                && status.policyGateReasonId > 0
                && status.policyGateRuleId > 0L
                && status.policyGateClaimCount == (status.policyGateBlocked ? 1 : 0);
        boolean dropRecorded = status != null
                && status.policyDropRecords > 0L
                && status.policyLastDropRevision > 0L
                && status.policyLastDropRuleId > 0L
                && status.policyLastDropCompletionAttempts == 1L
                && status.policyLastDropUidKnown
                && status.policyLastDropVerdict == PRODUCT_POLICY_VERDICT_DROP
                && status.policyLastDropWinner == PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE;
        boolean physicalNfqueueCompletion = dropRecorded
                && status.policyLastDropDeviceDirection == PRODUCT_DEVICE_DIRECTION_OUTPUT
                && status.rootNfqueueVerdictAttempts > 0L
                && status.rootNfqueueVerdictSucceeded > 0L;
        String rustProductStore = policyStoreEvidencePath(status,
                "product-policy/network-gate-intent.properties");
        String code = errorCode == null ? "" : errorCode;
        String detail = errorMessage == null ? "" : errorMessage;
        String text = "schema=s189-root-network-gate/v1"
                + "\nstage=" + BoundedText.value(stage, RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\nprofile=" + profile.wireName
                + "\nstate=" + (code.isEmpty() ? "running" : "error")
                + "\nerrorCode=" + code
                + "\nerrorMessage=" + BoundedText.value(detail,
                RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\ngeneration=" + statusGeneration
                + "\nrequested_revision=" + requestedRevision
                + "\nactive_revision=" + activeRevision
                + "\nrevision_match=" + revisionMatch
                + "\npolicy_generation=" + policyGeneration
                + "\ngeneration_match=" + generationMatch
                + "\npolicy_snapshot_hash=" + (status == null ? "0"
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity=" + (status == null ? ""
                : status.policySnapshotIdentity)
                + "\npolicy_snapshot_empty=" + (status != null
                && status.policySnapshotEmpty)
                + "\npolicy_default_pass=" + (status != null
                && status.policyDefaultPass)
                + "\ngate_snapshot=" + gateSnapshot
                + "\ngate_claim_count=" + (status == null ? 0
                : status.policyGateClaimCount)
                + "\nl4_rule_count=" + (status == null ? 0 : status.policyL4RuleCount)
                + "\ngate_subject_uid=" + (status == null ? 0
                : status.policyGateSubjectUid)
                + "\ngate_network_context=" + (status == null ? 0
                : status.policyGateNetworkContext)
                + "\ngate_blocked=" + (status != null && status.policyGateBlocked)
                + "\ngate_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyGateRuleId))
                + "\ngate_reason_id=" + (status == null ? 0
                : status.policyGateReasonId)
                + "\nworker0_revision=" + worker0Revision
                + "\nworker1_revision=" + worker1Revision
                + "\nworker_revision_match=" + workerRevisionMatch
                + "\npolicy_mixed_revision=" + (status != null
                && status.policyMixedRevision)
                + "\nsubmission_status_code=" + (status == null ? -1
                : status.policyLastApplyStatusCode)
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nartifact_match=" + (status != null && status.policyArtifactMatch)
                + "\npolicy_drop_records=" + (status == null ? 0L
                : status.policyDropRecords)
                + "\npolicy_last_drop_revision=" + (status == null ? 0L
                : status.policyLastDropRevision)
                + "\npolicy_last_drop_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyLastDropRuleId))
                + "\npolicy_last_drop_completion_attempts=" + (status == null ? 0L
                : status.policyLastDropCompletionAttempts)
                + "\npolicy_last_drop_uid=" + (status == null ? 0
                : status.policyLastDropUid)
                + "\npolicy_last_drop_network_context=" + (status == null ? 0
                : status.policyLastDropNetworkContext)
                + "\npolicy_last_drop_reason_id=" + (status == null ? 0
                : status.policyLastDropReasonId)
                + "\npolicy_last_drop_verdict=" + (status == null ? 0
                : status.policyLastDropVerdict)
                + "\npolicy_last_drop_winner=" + (status == null ? 0
                : status.policyLastDropWinner)
                + "\npolicy_last_drop_uid_known=" + (status != null
                && status.policyLastDropUidKnown)
                + "\npolicy_last_drop_device_direction=" + (status == null ? ""
                : rootNfqueueHookName(status.policyLastDropDeviceDirection))
                + "\npolicy_last_drop_device_direction_code=" + (status == null ? 0
                : status.policyLastDropDeviceDirection)
                + "\npolicy_drop_recorded=" + dropRecorded
                + "\nexpected_policy_last_drop_verdict=" + PRODUCT_POLICY_VERDICT_DROP
                + "\nexpected_policy_last_drop_winner="
                + PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE
                + "\nexpected_policy_last_drop_device_direction="
                + PRODUCT_DEVICE_DIRECTION_OUTPUT
                + "\npolicy_stage=network_gate"
                + "\npolicy_winner=network_gate"
                + "\npolicy_verdict=drop"
                + "\npolicy_drop_reason=policy_gate"
                + "\nroot_nfqueue_verdict_attempts=" + (status == null ? 0L
                : status.rootNfqueueVerdictAttempts)
                + "\nroot_nfqueue_verdict_succeeded=" + (status == null ? 0L
                : status.rootNfqueueVerdictSucceeded)
                + "\nroot_nfqueue_internal_settlements=" + (status == null ? 0L
                : status.rootNfqueueInternalSettlements)
                + "\nroot_nfqueue_buffer_returns=" + (status == null ? 0L
                : status.rootNfqueueBufferReturns)
                + "\nroot_nfqueue_origin_local_completions=" + (status == null ? 0L
                : status.rootNfqueueOriginLocalCompletions)
                + "\nroot_nfqueue_origin_remote_completions=" + (status == null ? 0L
                : status.rootNfqueueOriginRemoteCompletions)
                + "\nroot_nfqueue_non_owner_bypasses=" + (status == null ? 0L
                : status.rootNfqueueNonOwnerBypasses)
                + "\nroot_nfqueue_duplicate_completion_drops=" + (status == null ? 0L
                : status.rootNfqueueDuplicateCompletionDrops)
                + "\nroot_nfqueue_stale_completion_drops=" + (status == null ? 0L
                : status.rootNfqueueStaleCompletionDrops)
                + "\nproduct_graph_obligation_debt=" + (status == null ? 0L
                : status.productGraphObligationDebt)
                + "\nproduct_graph_buffer_debt=" + (status == null ? 0L
                : status.productGraphBufferDebt)
                + "\nproduct_graph_handoff_debt=" + (status == null ? 0L
                : status.productGraphHandoffDebt)
                + "\nrust_product_store=" + rustProductStore
                + "\nrust_product_store_single_writer=true"
                + "\nui_policy_authority=false"
                + "\nvpp_policy_authority=false"
                + "\nphysical_nfqueue_completion=" + physicalNfqueueCompletion
                + "\nartifact_id=" + (status == null ? "" : status.artifactId)
                + "\napi_identity=" + (status == null ? "" : status.apiIdentity)
                + "\nvpp_revision=" + (status == null ? "" : status.vppRevision)
                + "\n";
        writeBestEffortEvidenceFile(S189_ROOT_NETWORK_GATE_STATUS, text);
    }

    private void writeS191RootL4Status(RuntimeControlNative.Status status,
                                       RootL4PolicyFacts facts,
                                       String stage,
                                       String errorCode,
                                       String errorMessage) {
        RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        if (profile != RuntimeProfile.ROOT) {
            return;
        }
        if (facts == null && status != null && status.policyL4RuleCount == 0) {
            return;
        }
        long statusGeneration = status == null ? generation : status.generation;
        long requestedRevision = status == null ? 0L : status.policyRequestedRevision;
        long activeRevision = status == null ? 0L : status.policyActiveRevision;
        long policyGeneration = status == null ? 0L : status.policyGeneration;
        long worker0Revision = status == null ? 0L : status.policyWorker0Revision;
        long worker1Revision = status == null ? 0L : status.policyWorker1Revision;
        boolean revisionMatch = requestedRevision > 0L && requestedRevision == activeRevision;
        boolean generationMatch = status != null && status.policyGenerationMatch
                && policyGeneration == statusGeneration && statusGeneration > 0L;
        boolean workerRevisionMatch = activeRevision > 0L
                && worker0Revision == activeRevision
                && worker1Revision == activeRevision
                && status != null && !status.policyMixedRevision;
        boolean l4Snapshot = status != null
                && !status.policySnapshotEmpty
                && status.policyDefaultPass
                && status.policyGateClaimCount == 0
                && status.policyL4RuleCount == 1
                && status.policyL4ActiveRevision == status.policyActiveRevision
                && status.policyL4RuleId > 0L
                && status.policyL4IpFamily == PRODUCT_L4_IP_FAMILY_IPV4
                && status.policyL4IpProtocol == PRODUCT_L4_IP_PROTOCOL_TCP;
        boolean dropAction = facts != null && facts.action == PRODUCT_POLICY_VERDICT_DROP;
        boolean l4FactsReadback = status != null && facts != null
                && status.policyL4RuleId == facts.ruleId
                && status.policyL4SubjectUid == facts.subjectUid
                && status.policyL4NetworkContext == facts.networkContext
                && status.policyL4Direction == facts.direction
                && status.policyL4Action == facts.action
                && status.policyL4Priority == facts.priority
                && status.policyL4Order == facts.order
                && status.policyL4ReasonId == facts.reasonId;
        boolean l4MatchRecorded = status != null && facts != null
                && status.policyL4MatchRecords > 0L
                && status.policyL4LastMatchRevision == status.policyActiveRevision
                && status.policyL4LastMatchRuleId == facts.ruleId
                && status.policyL4LastMatchUid == facts.subjectUid
                && status.policyL4LastMatchNetworkContext == facts.networkContext
                && status.policyL4LastMatchReasonId == facts.reasonId
                && status.policyL4LastMatchWinner == PRODUCT_POLICY_WINNER_L4
                && status.policyL4LastMatchAction == facts.action
                && status.policyL4LastMatchDeviceDirection
                == l4DirectionToDeviceDirection(facts.direction);
        boolean dropRecorded = l4MatchRecorded && status != null && facts != null && dropAction
                && status.policyL4LastMatchVerdict == PRODUCT_POLICY_VERDICT_DROP
                && status.policyL4LastMatchUidKnown != 0
                && status.policyDropRecords > 0L
                && status.policyLastDropRevision == status.policyActiveRevision
                && status.policyLastDropRuleId == facts.ruleId
                && status.policyLastDropCompletionAttempts == 1L
                && status.policyLastDropUid == facts.subjectUid
                && status.policyLastDropNetworkContext == facts.networkContext
                && status.policyLastDropReasonId == facts.reasonId
                && status.policyLastDropUidKnown
                && status.policyLastDropVerdict == PRODUCT_POLICY_VERDICT_DROP
                && status.policyLastDropWinner == PRODUCT_POLICY_WINNER_L4
                && status.policyLastDropDeviceDirection
                == l4DirectionToDeviceDirection(facts.direction);
        boolean physicalNfqueueCompletion = dropRecorded
                && status.rootNfqueueVerdictAttempts > 0L
                && status.rootNfqueueVerdictSucceeded > 0L;
        String code = errorCode == null ? "" : errorCode;
        String detail = errorMessage == null ? "" : errorMessage;
        String actionName = facts == null ? ""
                : (dropAction ? "drop" : "allow");
        String text = "schema=s191-root-tcp4-l4/v1"
                + "\nstage=" + BoundedText.value(stage, RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\nprofile=" + profile.wireName
                + "\nstate=" + (code.isEmpty() ? "running" : "error")
                + "\nerrorCode=" + code
                + "\nerrorMessage=" + BoundedText.value(detail,
                RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\ngeneration=" + statusGeneration
                + "\nrequested_revision=" + requestedRevision
                + "\nactive_revision=" + activeRevision
                + "\nrevision_match=" + revisionMatch
                + "\npolicy_generation=" + policyGeneration
                + "\ngeneration_match=" + generationMatch
                + "\npolicy_snapshot_hash=" + (status == null ? "0"
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity=" + (status == null ? ""
                : status.policySnapshotIdentity)
                + "\npolicy_snapshot_empty=" + (status != null
                && status.policySnapshotEmpty)
                + "\npolicy_default_pass=" + (status != null
                && status.policyDefaultPass)
                + "\nl4_snapshot=" + l4Snapshot
                + "\ngate_claim_count=" + (status == null ? 0
                : status.policyGateClaimCount)
                + "\nl4_rule_count=" + (status == null ? 0
                : status.policyL4RuleCount)
                + "\nuid_complete=" + (facts != null && facts.subjectUid >= 0)
                + "\nl4_subject_uid=" + (facts == null ? 0 : facts.subjectUid)
                + "\nl4_network_context=" + (facts == null ? 0
                : facts.networkContext)
                + "\nl4_family=" + (facts == null ? 0 : facts.ipFamily)
                + "\nl4_protocol=" + (facts == null ? 0 : facts.ipProtocol)
                + "\nl4_ip_family=" + (facts == null ? 0 : facts.ipFamily)
                + "\nl4_ip_protocol=" + (facts == null ? 0 : facts.ipProtocol)
                + "\nl4_direction=" + (facts == null ? "" : l4DirectionName(facts.direction))
                + "\nl4_direction_code=" + (facts == null ? 0 : facts.direction)
                + "\nl4_action=" + actionName
                + "\nl4_action_code=" + (facts == null ? 0 : facts.action)
                + "\nl4_source_cidr=" + (facts == null ? "" : facts.sourceCidr)
                + "\nl4_destination_cidr=" + (facts == null ? "" : facts.destinationCidr)
                + "\nl4_source_port_first=" + (facts == null ? 0
                : facts.sourcePortFirst)
                + "\nl4_source_port_last=" + (facts == null ? 0
                : facts.sourcePortLast)
                + "\nl4_destination_port_first=" + (facts == null ? 0
                : facts.destinationPortFirst)
                + "\nl4_destination_port_last=" + (facts == null ? 0
                : facts.destinationPortLast)
                + "\nl4_priority=" + (facts == null ? 0 : facts.priority)
                + "\nl4_order=" + (facts == null ? 0 : facts.order)
                + "\nl4_rule_id=" + (facts == null ? "0"
                : Long.toUnsignedString(facts.ruleId))
                + "\nl4_reason_id=" + (facts == null ? 0 : facts.reasonId)
                + "\npolicy_l4_active_revision=" + (status == null ? 0L
                : status.policyL4ActiveRevision)
                + "\npolicy_l4_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyL4RuleId))
                + "\npolicy_l4_match_records=" + (status == null ? 0L
                : status.policyL4MatchRecords)
                + "\npolicy_l4_no_match_records=" + (status == null ? 0L
                : status.policyL4NoMatchRecords)
                + "\npolicy_l4_last_match_revision=" + (status == null ? 0L
                : status.policyL4LastMatchRevision)
                + "\npolicy_l4_last_match_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyL4LastMatchRuleId))
                + "\npolicy_l4_subject_uid=" + (status == null ? 0
                : status.policyL4SubjectUid)
                + "\npolicy_l4_network_context=" + (status == null ? 0
                : status.policyL4NetworkContext)
                + "\npolicy_l4_ip_family=" + (status == null ? 0
                : status.policyL4IpFamily)
                + "\npolicy_l4_ip_protocol=" + (status == null ? 0
                : status.policyL4IpProtocol)
                + "\npolicy_l4_direction_code=" + (status == null ? 0
                : status.policyL4Direction)
                + "\npolicy_l4_action_code=" + (status == null ? 0
                : status.policyL4Action)
                + "\npolicy_l4_priority=" + (status == null ? 0
                : status.policyL4Priority)
                + "\npolicy_l4_order=" + (status == null ? 0
                : status.policyL4Order)
                + "\npolicy_l4_reason_id=" + (status == null ? 0
                : status.policyL4ReasonId)
                + "\npolicy_l4_last_match_uid=" + (status == null ? 0
                : status.policyL4LastMatchUid)
                + "\npolicy_l4_last_match_network_context=" + (status == null ? 0
                : status.policyL4LastMatchNetworkContext)
                + "\npolicy_l4_last_match_reason_id=" + (status == null ? 0
                : status.policyL4LastMatchReasonId)
                + "\npolicy_l4_last_match_verdict=" + (status == null ? 0
                : status.policyL4LastMatchVerdict)
                + "\npolicy_l4_last_match_winner=" + (status == null ? 0
                : status.policyL4LastMatchWinner)
                + "\npolicy_l4_last_match_uid_known=" + (status == null ? 0
                : status.policyL4LastMatchUidKnown)
                + "\npolicy_l4_last_match_device_direction_code=" + (status == null ? 0
                : status.policyL4LastMatchDeviceDirection)
                + "\npolicy_l4_last_match_action=" + (status == null ? 0
                : status.policyL4LastMatchAction)
                + "\npolicy_l4_last_evaluation_result=" + (status == null ? 0
                : status.policyL4LastEvaluationResult)
                + "\npolicy_l4_last_evaluation_verdict=" + (status == null ? 0
                : status.policyL4LastEvaluationVerdict)
                + "\npolicy_l4_last_evaluation_device_direction_code="
                + (status == null ? 0
                : status.policyL4LastEvaluationDeviceDirection)
                + "\nl4_facts_readback=" + l4FactsReadback
                + "\nl4_match_recorded=" + l4MatchRecorded
                + "\nworker0_revision=" + worker0Revision
                + "\nworker1_revision=" + worker1Revision
                + "\nworker_revision_match=" + workerRevisionMatch
                + "\npolicy_mixed_revision=" + (status != null
                && status.policyMixedRevision)
                + "\nsubmission_status_code=" + (status == null ? -1
                : status.policyLastApplyStatusCode)
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nartifact_match=" + (status != null && status.policyArtifactMatch)
                + "\npolicy_drop_records=" + (status == null ? 0L
                : status.policyDropRecords)
                + "\npolicy_last_drop_revision=" + (status == null ? 0L
                : status.policyLastDropRevision)
                + "\npolicy_last_drop_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyLastDropRuleId))
                + "\npolicy_last_drop_completion_attempts=" + (status == null ? 0L
                : status.policyLastDropCompletionAttempts)
                + "\npolicy_last_drop_uid=" + (status == null ? 0
                : status.policyLastDropUid)
                + "\npolicy_last_drop_network_context=" + (status == null ? 0
                : status.policyLastDropNetworkContext)
                + "\npolicy_last_drop_reason_id=" + (status == null ? 0
                : status.policyLastDropReasonId)
                + "\npolicy_last_drop_verdict=" + (status == null ? 0
                : status.policyLastDropVerdict)
                + "\npolicy_last_drop_winner=" + (status == null ? 0
                : status.policyLastDropWinner)
                + "\npolicy_last_drop_uid_known=" + (status != null
                && status.policyLastDropUidKnown)
                + "\npolicy_last_drop_device_direction=" + (status == null ? ""
                : rootNfqueueHookName(status.policyLastDropDeviceDirection))
                + "\npolicy_last_drop_device_direction_code=" + (status == null ? 0
                : status.policyLastDropDeviceDirection)
                + "\npolicy_drop_recorded=" + dropRecorded
                + "\nexpected_policy_last_drop_verdict=" + PRODUCT_POLICY_VERDICT_DROP
                + "\nexpected_policy_last_drop_winner=" + PRODUCT_POLICY_WINNER_L4
                + "\nexpected_policy_last_drop_device_direction=" + (facts == null ? 0
                : l4DirectionToDeviceDirection(facts.direction))
                + "\npolicy_stage=l4"
                + "\npolicy_winner=" + (facts == null ? 0
                : PRODUCT_POLICY_WINNER_L4)
                + "\npolicy_winner_name=l4"
                + "\npolicy_verdict=" + (facts == null ? 0 : facts.action)
                + "\npolicy_verdict_name=" + actionName
                + "\npolicy_reason_id=" + (facts == null ? 0 : facts.reasonId)
                + "\npolicy_revision=" + activeRevision
                + "\npolicy_drop_reason=policy_l4"
                + "\nroot_nfqueue_verdict_attempts=" + (status == null ? 0L
                : status.rootNfqueueVerdictAttempts)
                + "\nroot_nfqueue_verdict_succeeded=" + (status == null ? 0L
                : status.rootNfqueueVerdictSucceeded)
                + "\nroot_nfqueue_internal_settlements=" + (status == null ? 0L
                : status.rootNfqueueInternalSettlements)
                + "\nroot_nfqueue_buffer_returns=" + (status == null ? 0L
                : status.rootNfqueueBufferReturns)
                + "\nroot_nfqueue_origin_local_completions=" + (status == null ? 0L
                : status.rootNfqueueOriginLocalCompletions)
                + "\nroot_nfqueue_origin_remote_completions=" + (status == null ? 0L
                : status.rootNfqueueOriginRemoteCompletions)
                + "\nroot_nfqueue_non_owner_bypasses=" + (status == null ? 0L
                : status.rootNfqueueNonOwnerBypasses)
                + "\nroot_nfqueue_duplicate_completion_drops=" + (status == null ? 0L
                : status.rootNfqueueDuplicateCompletionDrops)
                + "\nroot_nfqueue_stale_completion_drops=" + (status == null ? 0L
                : status.rootNfqueueStaleCompletionDrops)
                + "\nproduct_graph_obligation_debt=" + (status == null ? 0L
                : status.productGraphObligationDebt)
                + "\nproduct_graph_buffer_debt=" + (status == null ? 0L
                : status.productGraphBufferDebt)
                + "\nproduct_graph_handoff_debt=" + (status == null ? 0L
                : status.productGraphHandoffDebt)
                + "\nrust_product_store=" + policyStoreEvidencePath(status,
                "product-policy/l4-intent.properties")
                + "\nrust_product_store_single_writer=true"
                + "\nui_policy_authority=false"
                + "\nvpp_policy_authority=false"
                + "\ngate_before_l4=true"
                + "\nstateless_l4_matcher=true"
                + "\ndeterministic_precedence=priority_order_rule_id"
                + "\nroot_adapter_completion_separate=true"
                + "\nadapter_completion_separate=true"
                + "\nphysical_nfqueue_completion=" + physicalNfqueueCompletion
                + "\nartifact_id=" + (status == null ? "" : status.artifactId)
                + "\napi_identity=" + (status == null ? "" : status.apiIdentity)
                + "\nvpp_revision=" + (status == null ? "" : status.vppRevision)
                + "\n";
        writeBestEffortEvidenceFile(S191_ROOT_L4_STATUS, text);
    }

    private static boolean isUnknownPolicyMutationReadbackDetail(String value) {
        return value != null
                && (value.contains("unknown policy mutation reconciled")
                || value.contains("unknown policy mutation discarded"));
    }

    /** Publish bounded S194 mutation outcome and readback evidence. */
    private void writeS194ProductMutationStatus(RuntimeControlNative.Status status,
                                                 String stage, String errorCode,
                                                 String errorMessage) {
        String detail = status == null ? "" : status.errorDetail;
        boolean readbackOnly = isUnknownPolicyMutationReadbackDetail(detail)
                || isUnknownPolicyMutationReadbackDetail(errorMessage);
        String text = "schema=s194-product-mutation/v1"
                + "\nstage=" + s192PropertyToken(stage)
                + "\nstate=" + (errorCode == null || errorCode.isEmpty() ? "ok" : "error")
                + "\nerrorCode=" + s192PropertyToken(errorCode)
                + "\nerrorMessage=" + s192PropertyToken(errorMessage)
                + "\ngeneration=" + (status == null ? generation : status.generation)
                + "\npolicy_generation=" + (status == null ? 0L : status.policyGeneration)
                + "\npolicy_requested_revision=" + (status == null ? 0L
                : Long.toUnsignedString(status.policyRequestedRevision))
                + "\npolicy_active_revision=" + (status == null ? 0L
                : Long.toUnsignedString(status.policyActiveRevision))
                + "\npolicy_snapshot_hash=" + (status == null ? 0L
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity="
                + (status == null ? "" : s192PropertyToken(status.policySnapshotIdentity))
                + "\npolicy_generation_match=" + (status != null && status.policyGenerationMatch)
                + "\npolicy_artifact_match=" + (status != null && status.policyArtifactMatch)
                + "\npolicy_mixed_revision=" + (status != null && status.policyMixedRevision)
                + "\npolicy_last_apply_status_code=" + (status == null ? 0
                : status.policyLastApplyStatusCode)
                + "\nnative_status_detail=" + s192PropertyToken(detail)
                + "\nartifact_id=" + (status == null ? "" : s192PropertyToken(status.artifactId))
                + "\napi_identity=" + (status == null ? "" : s192PropertyToken(status.apiIdentity))
                + "\nvpp_revision=" + (status == null ? "" : s192PropertyToken(status.vppRevision))
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nreconcile_readback_only=" + readbackOnly
                + "\nreconcile_no_replay=" + readbackOnly
                + "\n";
        writeBestEffortEvidenceFile(S194_PRODUCT_MUTATION_STATUS, text);
    }

    /**
     * Publish one bounded S192 projection of the native L4 view.  Policy
     * identity and matcher counters come from Product Core status; the
     * selected case and packet identity come from the most recent completed
     * debug probe and the durable bundle only supplies its declared rule
     * dimensions.
     */
    private void writeS192L4MatrixStatus(RuntimeControlNative.Status status,
                                         String stage,
                                         String errorCode,
                                         String errorMessage) {
        RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        ProductStateSnapshot state = productBackend == null ? null : productBackend.productState();
        AuthoringPolicyBundle bundle = state == null ? null : state.authoringPolicyBundle;
        S192ProbeFacts probe = readLatestS192Probe();
        S192CounterEvidence counters = observeS192Counters(status, probe);
        AuthoringPolicyBundle.L4Rule lastMatchRule = status == null ? null
                : findS192Rule(bundle, status.policyL4LastMatchRuleId);
        AuthoringPolicyBundle.L4Rule probeRule = findS192RuleForProbe(bundle, probe);
        boolean bundleStatusMatches = s192BundleStatusMatches(status, bundle);
        boolean probeMatchesLastRule = bundleStatusMatches
                && s192ProbeMatchesRule(profile, status, lastMatchRule, probe);
        boolean strongExactProbeIdentity = probeMatchesLastRule;
        boolean perProbeMatchEvidence = counters.matchRecordsAdvanced
                || (counters.dropRecordsAdvanced
                && s192LastDropMatchesRule(status, lastMatchRule));
        // The per-probe boundary can be observed after native has already
        // counted the packet (for example, the first poll after a fast
        // connect failure).  The policy-epoch delta is a bounded fallback,
        // but only the complete native probe identity may consume it.
        boolean policyEpochMatchEvidence = counters.policyMatchRecordsAdvanced
                || (counters.policyDropRecordsAdvanced
                && s192LastDropMatchesRule(status, lastMatchRule));
        // A policy-epoch delta is only a substitute for a per-probe delta on
        // the first/new probe boundary.  Once a probe baseline is known, an
        // older match in the same epoch must not authorize a later no-match.
        boolean epochMatchFallback = policyEpochMatchEvidence
                && counters.probeEpochFallbackCandidate
                && !perProbeMatchEvidence;
        boolean nativeMatchEvidence = perProbeMatchEvidence || epochMatchFallback;
        boolean matched = nativeMatchEvidence && strongExactProbeIdentity;
        // A no-match counter transition is authoritative for a different
        // probe even when native keeps the previous successful match sticky.
        // Only a per-probe match (or the fenced first-probe epoch fallback)
        // may retain the target result.  Never infer a match from
        // policy_l4_last_evaluation_result alone.
        boolean noMatchEpochFallback = counters.policyNoMatchRecordsAdvanced
                && counters.probeEpochFallbackCandidate;
        boolean noMatch = (counters.noMatchRecordsAdvanced || noMatchEpochFallback)
                && !matched;
        AuthoringPolicyBundle.L4Rule rule = matched ? lastMatchRule : probeRule;

        int family = probe.ipFamily;
        int protocol = probe.ipProtocol;
        if (rule != null && matched) {
            family = rule.family == AuthoringPolicyBundle.IpFamily.IPV4
                    ? PRODUCT_L4_IP_FAMILY_IPV4 : PRODUCT_L4_IP_FAMILY_IPV6;
            protocol = rule.ipProtocol;
        }
        if (family == 0 && rule != null) {
            family = rule.family == AuthoringPolicyBundle.IpFamily.IPV4
                    ? PRODUCT_L4_IP_FAMILY_IPV4 : PRODUCT_L4_IP_FAMILY_IPV6;
        }
        if (protocol == 0 && rule != null) {
            protocol = rule.ipProtocol;
        }

        int uid = matched && status != null ? status.policyL4LastMatchUid : probe.uid;
        if (uid < 0 && rule != null) {
            uid = rule.subjectId.uid;
        }
        int networkContext = matched && status != null
                ? status.policyL4LastMatchNetworkContext : 0;
        if (networkContext <= 0 && rule != null && rule.networkContext != null) {
            networkContext = rule.networkContext.wireId;
        }
        int direction = status != null && (matched || noMatch)
                ? status.policyL4LastEvaluationDeviceDirection : 0;
        if (direction == 0 && rule != null) {
            direction = rule.direction == AuthoringPolicyBundle.PacketDirection.INPUT
                    ? PRODUCT_L4_DIRECTION_INPUT : PRODUCT_L4_DIRECTION_OUTPUT;
        }

        int nativeAction = matched && status != null ? status.policyL4LastMatchAction : 0;
        String action = s192ActionName(nativeAction);
        if (matched && "none".equals(action) && rule != null) {
            action = rule.action.wireName;
        }
        if (!matched) {
            action = "none";
        }
        int verdict = matched && status != null ? status.policyL4LastEvaluationVerdict
                : noMatch ? PRODUCT_POLICY_VERDICT_PASS_NEXT : 0;
        if (matched && verdict == 0) {
            verdict = PRODUCT_POLICY_VERDICT_DROP == nativeAction
                    ? PRODUCT_POLICY_VERDICT_DROP : PRODUCT_POLICY_VERDICT_PASS_NEXT;
        }
        String verdictName = verdict == PRODUCT_POLICY_VERDICT_DROP ? "drop"
                : verdict == PRODUCT_POLICY_VERDICT_PASS_NEXT ? "pass_next" : "none";

        int noMatchReason = noMatch && status != null
                ? status.policyL4ViewLastNoMatchReason : 0;
        if (noMatch && noMatchReason == 0) {
            // A native NO_MATCH without a reason is the bounded no-rule case.
            noMatchReason = 7;
        }
        String noMatchReasonName = noMatch ? s192NoMatchReasonName(noMatchReason) : "none";
        int viewActive = status == null ? 0 : status.policyL4ViewActive;
        int viewRuleCount = status == null ? 0 : status.policyL4ViewRuleCount;
        int viewMaxProbes = status == null ? 0 : status.policyL4ViewMaxProbes;
        int viewWinnerRank = matched && status != null
                ? status.policyL4ViewLastMatchWinnerRank : 0;
        int viewProbes = status == null ? 0 : status.policyL4ViewLastMatchProbes;
        int viewCandidates = status == null
                ? 0 : status.policyL4ViewLastMatchCandidateCount;
        long activeRevision = status == null
                ? bundle == null ? 0L : bundle.revision : status.policyActiveRevision;
        long ruleId = matched && status != null ? status.policyL4LastMatchRuleId : 0L;
        int reasonId = matched && status != null ? status.policyL4LastMatchReasonId : 0;
        long ifIndex = rule == null ? PRODUCT_UINT32_MAX : wireS192IfIndex(rule.ifIndex);
        boolean portsAvailable = probe.present && probe.destinationPort >= 0;
        if (!probe.present && rule != null) {
            portsAvailable = rule.destinationPorts != null;
        }
        boolean uidComplete = uid >= 0
                && Integer.toUnsignedLong(uid) != PRODUCT_UINT32_MAX;
        String requestedStage = s192PropertyToken(stage);
        boolean failed = errorCode != null && !errorCode.trim().isEmpty();
        String effectiveStage = "stopped".equals(requestedStage)
                ? "stopped" : (!failed && probe.present ? "probe" : requestedStage);
        String policyCase = s192PolicyCase(family, protocol);
        String code = s192PropertyToken(errorCode);
        String detail = s192PropertyToken(errorMessage);
        String identity = status == null ? "" : s192PropertyToken(status.policySnapshotIdentity);
        String text = "schema=s192-root-vpn-l4-matrix/v1"
                + "\nprofile=" + profile.wireName
                + "\nstage=" + effectiveStage
                + "\nstate=" + ("stopped".equals(effectiveStage)
                ? "stopped" : failed ? "error" : "running")
                + "\nerrorCode=" + code
                + "\nerrorMessage=" + detail
                + "\ngeneration=" + (status == null ? generation : status.generation)
                + "\npolicy_generation=" + (status == null ? 0L : status.policyGeneration)
                + "\npolicy_revision=" + Long.toUnsignedString(activeRevision)
                + "\npolicy_requested_revision=" + (status == null ? 0L
                : Long.toUnsignedString(status.policyRequestedRevision))
                + "\npolicy_snapshot_hash=" + (status == null ? "0"
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity=" + identity
                + "\npolicy_case=" + policyCase
                + "\npolicy_uid=" + Integer.toUnsignedString(uid)
                + "\npolicy_uid_complete=" + uidComplete
                + "\npolicy_network_context=" + networkContext
                + "\npolicy_ifindex=" + Long.toUnsignedString(ifIndex)
                + "\npolicy_family=" + family
                + "\npolicy_protocol=" + protocol
                + "\npolicy_direction=" + direction
                + "\npolicy_ports_available=" + portsAvailable
                + "\npolicy_evaluation=" + (matched ? "match"
                : noMatch ? "no_match" : "none")
                + "\npolicy_action=" + action
                + "\npolicy_rule_id=" + Long.toUnsignedString(ruleId)
                + "\npolicy_reason_id=" + reasonId
                + "\npolicy_winner_rank=" + viewWinnerRank
                + "\npolicy_candidate_count=" + viewCandidates
                + "\npolicy_probe_count=" + viewProbes
                + "\npolicy_probe_limit=" + viewMaxProbes
                + "\npolicy_subject_probe_count=0"
                + "\npolicy_no_match_reason=" + noMatchReasonName
                + "\npolicy_verdict=" + verdictName
                + "\npolicy_verdict_code=" + verdict
                + "\npolicy_view_active=" + viewActive
                + "\npolicy_view_rule_count=" + viewRuleCount
                + "\npolicy_view_max_probes=" + viewMaxProbes
                + "\npolicy_view_last_match_winner_rank=" + (status == null ? 0
                : status.policyL4ViewLastMatchWinnerRank)
                + "\npolicy_view_last_match_probes=" + (status == null ? 0
                : status.policyL4ViewLastMatchProbes)
                + "\npolicy_view_last_match_candidate_count=" + (status == null ? 0
                : status.policyL4ViewLastMatchCandidateCount)
                + "\npolicy_view_last_no_match_reason=" + (status == null ? 0
                : status.policyL4ViewLastNoMatchReason)
                + "\npolicy_l4_rule_count=" + (bundle == null ? 0 : bundle.l4RuleCount)
                + "\npolicy_gate_entry_count=" + (bundle == null ? 0 : bundle.gateEntryCount)
                + "\npolicy_protocol_rule_count=" + (bundle == null ? 0
                : bundle.protocolRuleCount)
                + "\npacket_host=" + s192PropertyToken(probe.host)
                + "\npacket_source_port=" + probe.sourcePort
                + "\npacket_destination_port=" + probe.destinationPort
                + "\npacket_uid=" + Integer.toUnsignedString(probe.uid)
                + "\npacket_bind_to_vpn=" + probe.bindToVpn
                + "\nprobe_result=" + s192PropertyToken(probe.result)
                + "\npolicy_l4_match_records="
                + Long.toUnsignedString(counters.matchRecords)
                + "\npolicy_l4_no_match_records="
                + Long.toUnsignedString(counters.noMatchRecords)
                + "\npolicy_drop_records=" + Long.toUnsignedString(counters.dropRecords)
                + "\npolicy_probe_identity=" + s192PropertyToken(counters.probeIdentity)
                + "\npolicy_probe_baseline_known=" + counters.baselineKnown
                + "\npolicy_probe_baseline_match_records="
                + Long.toUnsignedString(counters.baselineMatchRecords)
                + "\npolicy_probe_baseline_no_match_records="
                + Long.toUnsignedString(counters.baselineNoMatchRecords)
                + "\npolicy_probe_baseline_drop_records="
                + Long.toUnsignedString(counters.baselineDropRecords)
                + "\npolicy_probe_match_delta="
                + Long.toUnsignedString(counters.matchDelta)
                + "\npolicy_probe_no_match_delta="
                + Long.toUnsignedString(counters.noMatchDelta)
                + "\npolicy_probe_drop_delta=" + Long.toUnsignedString(counters.dropDelta)
                + "\npolicy_match_epoch_delta="
                + Long.toUnsignedString(counters.policyMatchDelta)
                + "\npolicy_no_match_epoch_delta="
                + Long.toUnsignedString(counters.policyNoMatchDelta)
                + "\npolicy_drop_epoch_delta="
                + Long.toUnsignedString(counters.policyDropDelta)
                + "\npolicy_probe_match_counter_advanced=" + counters.matchRecordsAdvanced
                + "\npolicy_probe_no_match_counter_advanced=" + counters.noMatchRecordsAdvanced
                + "\npolicy_probe_drop_counter_advanced=" + counters.dropRecordsAdvanced
                + "\npolicy_probe_epoch_fallback_candidate="
                + counters.probeEpochFallbackCandidate
                + "\npolicy_bundle_status_matches=" + bundleStatusMatches
                + "\npolicy_probe_rule_match=" + probeMatchesLastRule
                + "\npolicy_strong_exact_probe_identity=" + strongExactProbeIdentity
                + "\npolicy_probe_match_evidence=" + perProbeMatchEvidence
                + "\npolicy_epoch_match_evidence=" + policyEpochMatchEvidence
                + "\npolicy_epoch_match_fallback=" + epochMatchFallback
                + "\npolicy_epoch_no_match_fallback=" + noMatchEpochFallback
                + "\npolicy_native_match_evidence=" + nativeMatchEvidence
                + "\npolicy_typed_match_policy_key="
                + (status == null ? "0"
                : Long.toUnsignedString(status.policyL4TypedMatchPolicyKey))
                + "\npolicy_typed_match_probe_key="
                + (status == null ? "0"
                : Long.toUnsignedString(status.policyL4TypedMatchProbeKey))
                + "\npolicy_last_evaluation_probe_key="
                + (status == null ? "0"
                : Long.toUnsignedString(status.policyL4LastEvaluationProbeKey))
                + "\npolicy_same_probe=" + (status != null
                && status.policyL4TypedMatchProbeKey != 0L
                && status.policyL4TypedMatchProbeKey
                == status.policyL4LastEvaluationProbeKey)
                + "\nresidue_clean=" + "stopped".equals(effectiveStage)
                + "\nnative_policy_l4_view_active=" + viewActive
                + "\nnative_policy_l4_view_rule_count=" + viewRuleCount
                + "\nnative_policy_l4_view_max_probes=" + viewMaxProbes
                + "\nnative_policy_l4_view_last_match_winner_rank="
                + (status == null ? 0 : status.policyL4ViewLastMatchWinnerRank)
                + "\nnative_policy_l4_view_last_match_probes="
                + (status == null ? 0 : status.policyL4ViewLastMatchProbes)
                + "\nnative_policy_l4_view_last_match_candidate_count="
                + (status == null ? 0 : status.policyL4ViewLastMatchCandidateCount)
                + "\nnative_policy_l4_view_last_no_match_reason="
                + (status == null ? 0 : status.policyL4ViewLastNoMatchReason)
                + "\npolicy_mixed_revision=" + (status != null && status.policyMixedRevision)
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nartifact_id=" + (status == null ? "" : s192PropertyToken(status.artifactId))
                + "\napi_identity=" + (status == null ? "" : s192PropertyToken(status.apiIdentity))
                + "\nvpp_revision=" + (status == null ? "" : s192PropertyToken(status.vppRevision))
                + "\n";
        writeBestEffortEvidenceFile(S192_ROOT_VPN_L4_MATRIX_STATUS, text);
    }

    /**
     * Establish a before/after boundary for the latest probe.  Native status
     * is polled more than once after a probe is written, so the baseline is
     * advanced only when the bounded probe identity changes.  A generation,
     * revision, or snapshot transition invalidates the baseline entirely.
     */
    private S192CounterEvidence observeS192Counters(
            RuntimeControlNative.Status status, S192ProbeFacts probe) {
        long currentGeneration = status == null ? 0L : status.generation;
        long currentPolicyGeneration = status == null ? 0L : status.policyGeneration;
        long currentRevision = status == null ? 0L : status.policyActiveRevision;
        long currentSnapshotHash = status == null ? 0L : status.policySnapshotHash;
        String currentIdentity = status == null || status.policySnapshotIdentity == null
                ? "" : status.policySnapshotIdentity;
        long currentMatchRecords = status == null ? 0L : status.policyL4MatchRecords;
        long currentNoMatchRecords = status == null ? 0L : status.policyL4NoMatchRecords;
        long currentDropRecords = status == null ? 0L : status.policyDropRecords;
        boolean statusUsable = status != null && status.code == 0
                && status.policyLastApplyStatusCode == 0
                && status.policyGenerationMatch
                && status.policyRequestedRevision == status.policyActiveRevision
                && status.policyActiveRevision > 0L
                && status.policySnapshotHash != 0L
                && currentIdentity != null && !currentIdentity.isEmpty();
        String probeIdentity = probe == null ? "" : probe.identity;

        synchronized (s192EvidenceLock) {
            boolean runtimeSame = s192ObservedStatus && statusUsable
                    && s192ObservedGeneration == currentGeneration
                    && s192ObservedPolicyGeneration == currentPolicyGeneration
                    && s192ObservedPolicyRevision == currentRevision
                    && s192ObservedSnapshotHash == currentSnapshotHash
                    && s192ObservedSnapshotIdentity.equals(currentIdentity);
            if (!runtimeSame) {
                // This anchor covers the entire native policy epoch.  It is
                // intentionally separate from the per-probe no-match
                // baseline so an exact SAME_PROBE retransmit can retain an
                // already observed match.
                s192ProbeEpochFallbackCandidate = false;
                s192PolicyBaselineKnown = false;
                s192PolicyBaselineMatchRecords = 0L;
                s192PolicyBaselineNoMatchRecords = 0L;
                s192PolicyBaselineDropRecords = 0L;
                s192ProbeBaselineKnown = false;
                s192ProbeBaselineMatchRecords = 0L;
                s192ProbeBaselineNoMatchRecords = 0L;
                s192ProbeBaselineDropRecords = 0L;
            }
            if (statusUsable && !s192PolicyBaselineKnown) {
                s192PolicyBaselineKnown = true;
                s192PolicyBaselineMatchRecords = currentMatchRecords;
                s192PolicyBaselineNoMatchRecords = currentNoMatchRecords;
                s192PolicyBaselineDropRecords = currentDropRecords;
            }
            boolean probeIdentityChanged = runtimeSame
                    && !probeIdentity.equals(s192ObservedProbeIdentity);
            boolean observedCountersAlreadyAdvanced = runtimeSame
                    && !counterAdvanced(currentMatchRecords, s192ObservedMatchRecords)
                    && !counterAdvanced(currentNoMatchRecords, s192ObservedNoMatchRecords)
                    && !counterAdvanced(currentDropRecords, s192ObservedDropRecords);
            boolean policyCountersAdvanced = s192PolicyBaselineKnown
                    && (counterAdvanced(currentMatchRecords, s192PolicyBaselineMatchRecords)
                    || counterAdvanced(currentNoMatchRecords,
                    s192PolicyBaselineNoMatchRecords)
                    || counterAdvanced(currentDropRecords, s192PolicyBaselineDropRecords));
            if (probeIdentityChanged) {
                // The previous status is the "before" side of this probe.
                s192ProbeBaselineKnown = true;
                s192ProbeBaselineMatchRecords = s192ObservedMatchRecords;
                s192ProbeBaselineNoMatchRecords = s192ObservedNoMatchRecords;
                s192ProbeBaselineDropRecords = s192ObservedDropRecords;
                // If the probe file was already present when the first
                // status poll saw it, the native event may predate the Java
                // boundary.  Permit only this bounded first/new-probe case
                // to use the policy epoch no-match delta.
                s192ProbeEpochFallbackCandidate = observedCountersAlreadyAdvanced
                        && policyCountersAdvanced;
            }

            boolean baselineKnown = s192ProbeBaselineKnown && runtimeSame;
            boolean matchAdvanced = baselineKnown
                    && counterAdvanced(currentMatchRecords, s192ProbeBaselineMatchRecords);
            boolean noMatchAdvanced = baselineKnown
                    && counterAdvanced(currentNoMatchRecords, s192ProbeBaselineNoMatchRecords);
            boolean dropAdvanced = baselineKnown
                    && counterAdvanced(currentDropRecords, s192ProbeBaselineDropRecords);
            long matchDelta = matchAdvanced
                    ? currentMatchRecords - s192ProbeBaselineMatchRecords : 0L;
            long noMatchDelta = noMatchAdvanced
                    ? currentNoMatchRecords - s192ProbeBaselineNoMatchRecords : 0L;
            long dropDelta = dropAdvanced
                    ? currentDropRecords - s192ProbeBaselineDropRecords : 0L;
            boolean policyMatchRecordsAdvanced = s192PolicyBaselineKnown
                    && counterAdvanced(currentMatchRecords, s192PolicyBaselineMatchRecords);
            boolean policyNoMatchRecordsAdvanced = s192PolicyBaselineKnown
                    && counterAdvanced(currentNoMatchRecords, s192PolicyBaselineNoMatchRecords);
            boolean policyDropRecordsAdvanced = s192PolicyBaselineKnown
                    && counterAdvanced(currentDropRecords, s192PolicyBaselineDropRecords);
            long policyMatchDelta = s192PolicyBaselineKnown
                    && policyMatchRecordsAdvanced
                    ? currentMatchRecords - s192PolicyBaselineMatchRecords : 0L;
            long policyNoMatchDelta = policyNoMatchRecordsAdvanced
                    ? currentNoMatchRecords - s192PolicyBaselineNoMatchRecords : 0L;
            long policyDropDelta = policyDropRecordsAdvanced
                    ? currentDropRecords - s192PolicyBaselineDropRecords : 0L;

            s192ObservedStatus = statusUsable;
            s192ObservedGeneration = currentGeneration;
            s192ObservedPolicyGeneration = currentPolicyGeneration;
            s192ObservedPolicyRevision = currentRevision;
            s192ObservedSnapshotHash = currentSnapshotHash;
            s192ObservedSnapshotIdentity = currentIdentity;
            s192ObservedProbeIdentity = probeIdentity;
            s192ObservedMatchRecords = currentMatchRecords;
            s192ObservedNoMatchRecords = currentNoMatchRecords;
            s192ObservedDropRecords = currentDropRecords;
            return new S192CounterEvidence(baselineKnown,
                    s192ProbeBaselineMatchRecords, s192ProbeBaselineNoMatchRecords,
                    s192ProbeBaselineDropRecords, currentMatchRecords,
                    currentNoMatchRecords, currentDropRecords, matchAdvanced,
                    noMatchAdvanced, dropAdvanced, matchDelta, noMatchDelta, dropDelta,
                    policyMatchRecordsAdvanced, policyDropRecordsAdvanced, policyMatchDelta,
                    policyNoMatchRecordsAdvanced, policyNoMatchDelta, policyDropDelta,
                    s192ProbeEpochFallbackCandidate, probeIdentity);
        }
    }

    private static boolean counterAdvanced(long current, long baseline) {
        return Long.compareUnsigned(current, baseline) > 0;
    }

    private static boolean s192BundleStatusMatches(
            RuntimeControlNative.Status status, AuthoringPolicyBundle bundle) {
        if (status == null || bundle == null || status.code != 0
                || status.policyLastApplyStatusCode != 0
                || !status.policyGenerationMatch
                || status.policyGeneration != status.generation
                || status.policyRequestedRevision <= 0L
                || status.policyRequestedRevision != status.policyActiveRevision
                || status.policyActiveRevision != bundle.revision
                || status.policySnapshotHash == 0L
                || !AuthoringPolicyBundle.BUNDLE_FORMAT.equals(status.policySnapshotIdentity)
                || status.policyGateClaimCount != s192BlockedGateClaimCount(bundle)
                || status.policyL4RuleCount != bundle.l4RuleCount
                || status.policyL4ViewActive != 1
                || status.policyL4ViewRuleCount != bundle.l4RuleCount
                || status.policyMixedRevision
                || !status.policyArtifactMatch
                || !status.policyDefaultPass
                || status.policySnapshotEmpty != bundle.isEmpty()
                || status.policyWorker0Revision != status.policyActiveRevision
                || status.policyWorker1Revision != status.policyActiveRevision) {
            return false;
        }
        long bundleHash = s192BundleHash(bundle);
        return bundleHash != 0L && bundleHash == status.policySnapshotHash;
    }

    private static int s192BlockedGateClaimCount(AuthoringPolicyBundle bundle) {
        int claims = 0;
        for (AuthoringPolicyBundle.NetworkGateRule rule : bundle.gateMatrix) {
            if (rule.enabled && rule.blocked) {
                claims++;
            }
        }
        return claims;
    }

    private static long s192BundleHash(AuthoringPolicyBundle bundle) {
        if (bundle == null) {
            return 0L;
        }
        try {
            byte[] payload = bundle.toNativeBundlePayload();
            if (payload.length < 24) {
                return 0L;
            }
            long hash = 0L;
            for (int index = 0; index < 8; ++index) {
                hash |= (payload[16 + index] & 0xffL) << (index * 8);
            }
            return hash;
        } catch (RuntimeException error) {
            return 0L;
        }
    }

    private static boolean s192PolicyKeyMatches(RuntimeControlNative.Status status) {
        if (status == null || status.policyL4TypedMatchPolicyKey == 0L) {
            return false;
        }
        long hash = 0xcbf29ce484222325L;
        hash = s192EvidenceHashLong(hash, status.policyGeneration);
        hash = s192EvidenceHashLong(hash, status.policyActiveRevision);
        hash = s192EvidenceHashLong(hash, status.policySnapshotHash);
        return status.policyL4TypedMatchPolicyKey == (hash == 0L ? 1L : hash);
    }

    private static long s192EvidenceHashLong(long hash, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            hash = (hash ^ ((value >>> shift) & 0xffL)) * 1099511628211L;
        }
        return hash;
    }

    /**
     * The typed view exposes the rule rank separately; the shared
     * last_match_winner field remains the canonical L4 stage winner.  Keep
     * those domains separate when consuming S192 status.
     */
    private static boolean s192TypedWinnerMatches(RuntimeControlNative.Status status) {
        return status != null
                && status.policyL4LastMatchWinner > 0
                && status.policyL4ViewLastMatchWinnerRank > 0
                && status.policyL4ViewLastMatchWinnerRank <= status.policyL4ViewRuleCount
                && status.policyL4LastMatchWinner == PRODUCT_POLICY_WINNER_L4;
    }

    private static boolean s192ProbeMatchesRule(
            RuntimeProfile profile, RuntimeControlNative.Status status,
            AuthoringPolicyBundle.L4Rule rule, S192ProbeFacts probe) {
        if (profile == null || status == null || rule == null || probe == null
                || !probe.present || !rule.enabled || probe.uid < 0
                || probe.destinationPort <= 0
                || rule.networkContext == null
                || (profile == RuntimeProfile.VPN) != probe.bindToVpn) {
            return false;
        }
        int family = rule.family == AuthoringPolicyBundle.IpFamily.IPV4
                ? PRODUCT_L4_IP_FAMILY_IPV4 : PRODUCT_L4_IP_FAMILY_IPV6;
        int expectedDirection = rule.direction == AuthoringPolicyBundle.PacketDirection.INPUT
                ? PRODUCT_DEVICE_DIRECTION_INPUT : PRODUCT_DEVICE_DIRECTION_OUTPUT;
        int expectedAction = rule.action == AuthoringPolicyBundle.L4Action.DROP
                ? PRODUCT_POLICY_VERDICT_DROP : PRODUCT_POLICY_VERDICT_PASS_NEXT;
        if (probe.ipFamily != family || probe.ipProtocol != rule.ipProtocol
                || probe.uid != rule.subjectId.uid
                || status.policyL4LastMatchUidKnown != 1
                || status.policyL4LastMatchUid != probe.uid
                || status.policyL4LastMatchNetworkContext != rule.networkContext.wireId
                || status.policyL4LastMatchDeviceDirection != expectedDirection
                || status.policyL4LastMatchAction != expectedAction
                || !s192TypedWinnerMatches(status)
                || status.policyL4LastMatchRuleId != rule.ruleId
                || status.policyL4LastMatchReasonId != rule.reasonId
                || status.policyL4LastMatchRevision != status.policyActiveRevision
                || status.policyL4ActiveRevision != status.policyActiveRevision
                || !s192PolicyKeyMatches(status)
                || status.policyL4TypedMatchProbeKey == 0L
                || status.policyL4LastEvaluationProbeKey == 0L) {
            return false;
        }
        // Bundle publication clears the scalar policy dimensions.  When a
        // future native status exposes them, this conditional also rejects a
        // family/protocol disagreement without breaking the current ABI.
        if ((status.policyL4IpFamily != 0 && status.policyL4IpFamily != family)
                || (status.policyL4IpProtocol != 0
                && status.policyL4IpProtocol != rule.ipProtocol)) {
            return false;
        }
        if (rule.direction != AuthoringPolicyBundle.PacketDirection.OUTPUT
                || !s192ProbePortsMatch(rule, probe)
                || !s192HostMatchesCidr(probe.host, rule.destinationCidr, family)
                || !s192WildcardCidr(rule.sourceCidr, family)) {
            return false;
        }
        return true;
    }

    private static boolean s192LastDropMatchesRule(
            RuntimeControlNative.Status status, AuthoringPolicyBundle.L4Rule rule) {
        if (status == null || rule == null
                || rule.networkContext == null
                || rule.action != AuthoringPolicyBundle.L4Action.DROP) {
            return false;
        }
        int direction = rule.direction == AuthoringPolicyBundle.PacketDirection.INPUT
                ? PRODUCT_DEVICE_DIRECTION_INPUT : PRODUCT_DEVICE_DIRECTION_OUTPUT;
        return status.policyLastDropRevision == status.policyActiveRevision
                && status.policyLastDropRuleId == rule.ruleId
                && status.policyLastDropUid == rule.subjectId.uid
                && status.policyLastDropNetworkContext == rule.networkContext.wireId
                && status.policyLastDropReasonId == rule.reasonId
                && status.policyLastDropVerdict == PRODUCT_POLICY_VERDICT_DROP
                && s192TypedWinnerMatches(status)
                && status.policyLastDropWinner == PRODUCT_POLICY_WINNER_L4
                && status.policyLastDropUidKnown
                && status.policyLastDropDeviceDirection == direction;
    }

    private static boolean s192ProbePortsMatch(
            AuthoringPolicyBundle.L4Rule rule, S192ProbeFacts probe) {
        if (!s192PortContains(rule.destinationPorts, probe.destinationPort)) {
            return false;
        }
        if (probe.sourcePort > 0) {
            return s192PortContains(rule.sourcePorts, probe.sourcePort);
        }
        // Debug probes record 0 when the kernel selected an ephemeral source
        // port.  That is evidence only for an unconstrained source range.
        return s192WildcardPortRange(rule.sourcePorts);
    }

    private static boolean s192PortContains(
            AuthoringPolicyBundle.PortRange range, int port) {
        return port > 0 && (range == null || (port >= range.first && port <= range.last));
    }

    private static boolean s192WildcardPortRange(AuthoringPolicyBundle.PortRange range) {
        return range == null || (range.first == 0 && range.last == 65535);
    }

    private static boolean s192WildcardCidr(String cidr, int family) {
        String value = cidr == null ? "" : cidr.trim();
        return value.isEmpty()
                || (family == PRODUCT_L4_IP_FAMILY_IPV4 && "0.0.0.0/0".equals(value))
                || (family == PRODUCT_L4_IP_FAMILY_IPV6 && "::/0".equals(value));
    }

    private static boolean s192HostMatchesCidr(String host, String cidr, int family) {
        String value = cidr == null ? "" : cidr.trim();
        if (value.isEmpty()) {
            return host != null && !host.trim().isEmpty();
        }
        if (host == null || host.trim().isEmpty()) {
            return false;
        }
        String[] parts = value.split("/", -1);
        int maxBits = family == PRODUCT_L4_IP_FAMILY_IPV4 ? 32 : 128;
        if (parts.length > 2 || parts[0].isEmpty()) {
            return false;
        }
        int prefix = maxBits;
        if (parts.length == 2) {
            prefix = parseFixedInt(parts[1], -1);
        }
        if (prefix < 0 || prefix > maxBits) {
            return false;
        }
        byte[] network = s192LiteralAddress(parts[0], family);
        byte[] address = s192LiteralAddress(host.trim(), family);
        if (network == null || address == null) {
            return false;
        }
        int fullBytes = prefix / 8;
        int remainingBits = prefix % 8;
        for (int index = 0; index < fullBytes; ++index) {
            if (network[index] != address[index]) {
                return false;
            }
        }
        if (remainingBits != 0) {
            int mask = 0xff << (8 - remainingBits);
            if ((network[fullBytes] & mask) != (address[fullBytes] & mask)) {
                return false;
            }
        }
        return true;
    }

    private static byte[] s192LiteralAddress(String value, int family) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
                    || (ch >= 'A' && ch <= 'F') || ch == '.' || ch == ':')) {
                return null;
            }
        }
        if (family == PRODUCT_L4_IP_FAMILY_IPV4) {
            String[] octets = value.split("\\.", -1);
            if (octets.length != 4) {
                return null;
            }
            byte[] address = new byte[4];
            for (int index = 0; index < octets.length; ++index) {
                int octet = parseFixedInt(octets[index], -1);
                if (octet < 0 || octet > 255) {
                    return null;
                }
                address[index] = (byte) octet;
            }
            return address;
        }
        if (family != PRODUCT_L4_IP_FAMILY_IPV6 || value.indexOf(':') < 0) {
            return null;
        }
        try {
            byte[] address = InetAddress.getByName(value).getAddress();
            return address.length == 16 ? address : null;
        } catch (Exception error) {
            return null;
        }
    }

    private static final class S192CounterEvidence {
        final boolean baselineKnown;
        final long baselineMatchRecords;
        final long baselineNoMatchRecords;
        final long baselineDropRecords;
        final long matchRecords;
        final long noMatchRecords;
        final long dropRecords;
        final boolean matchRecordsAdvanced;
        final boolean noMatchRecordsAdvanced;
        final boolean dropRecordsAdvanced;
        final long matchDelta;
        final long noMatchDelta;
        final long dropDelta;
        final boolean policyMatchRecordsAdvanced;
        final boolean policyNoMatchRecordsAdvanced;
        final boolean policyDropRecordsAdvanced;
        final long policyMatchDelta;
        final long policyNoMatchDelta;
        final long policyDropDelta;
        final boolean probeEpochFallbackCandidate;
        final String probeIdentity;

        S192CounterEvidence(boolean baselineKnown, long baselineMatchRecords,
                            long baselineNoMatchRecords, long baselineDropRecords,
                            long matchRecords, long noMatchRecords, long dropRecords,
                            boolean matchRecordsAdvanced, boolean noMatchRecordsAdvanced,
                            boolean dropRecordsAdvanced, long matchDelta, long noMatchDelta,
                            long dropDelta, boolean policyMatchRecordsAdvanced,
                            boolean policyDropRecordsAdvanced, long policyMatchDelta,
                            boolean policyNoMatchRecordsAdvanced, long policyNoMatchDelta,
                            long policyDropDelta, boolean probeEpochFallbackCandidate,
                            String probeIdentity) {
            this.baselineKnown = baselineKnown;
            this.baselineMatchRecords = baselineMatchRecords;
            this.baselineNoMatchRecords = baselineNoMatchRecords;
            this.baselineDropRecords = baselineDropRecords;
            this.matchRecords = matchRecords;
            this.noMatchRecords = noMatchRecords;
            this.dropRecords = dropRecords;
            this.matchRecordsAdvanced = matchRecordsAdvanced;
            this.noMatchRecordsAdvanced = noMatchRecordsAdvanced;
            this.dropRecordsAdvanced = dropRecordsAdvanced;
            this.matchDelta = matchDelta;
            this.noMatchDelta = noMatchDelta;
            this.dropDelta = dropDelta;
            this.policyMatchRecordsAdvanced = policyMatchRecordsAdvanced;
            this.policyNoMatchRecordsAdvanced = policyNoMatchRecordsAdvanced;
            this.policyDropRecordsAdvanced = policyDropRecordsAdvanced;
            this.policyMatchDelta = policyMatchDelta;
            this.policyNoMatchDelta = policyNoMatchDelta;
            this.policyDropDelta = policyDropDelta;
            this.probeEpochFallbackCandidate = probeEpochFallbackCandidate;
            this.probeIdentity = probeIdentity == null ? "" : probeIdentity;
        }
    }

    private static AuthoringPolicyBundle.L4Rule findS192Rule(
            AuthoringPolicyBundle bundle, long ruleId) {
        if (bundle == null || ruleId <= 0L) {
            return null;
        }
        for (AuthoringPolicyBundle.L4Rule candidate : bundle.l4Rules) {
            if (candidate.ruleId == ruleId) {
                return candidate;
            }
        }
        return null;
    }

    private static AuthoringPolicyBundle.L4Rule findS192RuleForProbe(
            AuthoringPolicyBundle bundle, S192ProbeFacts probe) {
        if (bundle == null || bundle.l4Rules.isEmpty()) {
            return null;
        }
        if (probe != null && probe.present) {
            for (AuthoringPolicyBundle.L4Rule candidate : bundle.l4Rules) {
                int family = candidate.family == AuthoringPolicyBundle.IpFamily.IPV4
                        ? PRODUCT_L4_IP_FAMILY_IPV4 : PRODUCT_L4_IP_FAMILY_IPV6;
                if (family == probe.ipFamily && candidate.ipProtocol == probe.ipProtocol) {
                    return candidate;
                }
            }
        }
        return bundle.l4Rules.get(0);
    }

    private static long wireS192IfIndex(int ifIndex) {
        return ifIndex == 0 ? PRODUCT_UINT32_MAX : Integer.toUnsignedLong(ifIndex);
    }

    private static String s192PolicyCase(int family, int protocol) {
        if (family == PRODUCT_L4_IP_FAMILY_IPV4 && protocol == PRODUCT_L4_IP_PROTOCOL_TCP) {
            return "ipv4-tcp";
        }
        if (family == PRODUCT_L4_IP_FAMILY_IPV4 && protocol == PRODUCT_L4_IP_PROTOCOL_UDP) {
            return "ipv4-udp";
        }
        if (family == PRODUCT_L4_IP_FAMILY_IPV6 && protocol == PRODUCT_L4_IP_PROTOCOL_TCP) {
            return "ipv6-tcp";
        }
        if (family == PRODUCT_L4_IP_FAMILY_IPV6 && protocol == PRODUCT_L4_IP_PROTOCOL_UDP) {
            return "ipv6-udp";
        }
        return "unknown";
    }

    private static String s192ActionName(int action) {
        if (action == PRODUCT_POLICY_VERDICT_DROP) {
            return "drop";
        }
        if (action == PRODUCT_POLICY_VERDICT_PASS_NEXT) {
            return "allow";
        }
        return "none";
    }

    private static String s192NoMatchReasonName(int reason) {
        switch (reason) {
            case 0:
                return "none";
            case 1:
                return "unknown_uid";
            case 2:
                return "unsupported_family";
            case 3:
                return "unsupported_protocol";
            case 4:
                return "l4_unavailable";
            case 5:
                return "unsupported_direction";
            case 6:
                return "no_subject";
            case 7:
                return "no_rule";
            default:
                return "unknown";
        }
    }

    private static String s192PropertyToken(String value) {
        return BoundedText.value(value, RuntimeSnapshot.MAX_TEXT_LENGTH)
                .replace('\n', '_').replace('\r', '_');
    }

    private S192ProbeFacts readLatestS192Probe() {
        File tcp = new File(getFilesDir(), DEBUG_TRAFFIC_PROBE_RESULT);
        File udp = new File(getFilesDir(), DEBUG_UDP_TRAFFIC_PROBE_RESULT);
        File selected = null;
        if (tcp.isFile()) {
            selected = tcp;
        }
        if (udp.isFile() && (selected == null
                || udp.lastModified() >= selected.lastModified())) {
            selected = udp;
        }
        if (selected == null) {
            return S192ProbeFacts.absent();
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(selected)) {
            values.load(input);
        } catch (IOException | IllegalArgumentException error) {
            return S192ProbeFacts.absent();
        }
        String host = values.getProperty("host", "");
        int family = host.indexOf(':') >= 0 ? PRODUCT_L4_IP_FAMILY_IPV6
                : host.isEmpty() ? 0 : PRODUCT_L4_IP_FAMILY_IPV4;
        int protocol = selected == udp ? PRODUCT_L4_IP_PROTOCOL_UDP
                : PRODUCT_L4_IP_PROTOCOL_TCP;
        int sourcePort = parseS192Port(values.getProperty("sourcePort"));
        int destinationPort = parseS192Port(values.getProperty("port"));
        int uid = parseFixedInt(values.getProperty("uid"), -1);
        boolean bindToVpn = "true".equalsIgnoreCase(
                values.getProperty("bindToVpn", "false"));
        String result = values.getProperty("result", "");
        String identity = selected.getName() + "|" + selected.lastModified() + "|"
                + selected.length() + "|" + values.getProperty("nonce", "") + "|"
                + host + "|" + sourcePort + "|" + destinationPort + "|" + uid + "|"
                + bindToVpn + "|" + result;
        return new S192ProbeFacts(true, family, protocol, sourcePort, destinationPort,
                uid, host, result, bindToVpn, s192PropertyToken(identity));
    }

    private static int parseS192Port(String value) {
        int port = parseFixedInt(value, -1);
        return port >= 0 && port <= 65535 ? port : -1;
    }

    private static final class S192ProbeFacts {
        final boolean present;
        final int ipFamily;
        final int ipProtocol;
        final int sourcePort;
        final int destinationPort;
        final int uid;
        final String host;
        final String result;
        final boolean bindToVpn;
        final String identity;

        S192ProbeFacts(boolean present, int ipFamily, int ipProtocol,
                       int sourcePort, int destinationPort, int uid,
                       String host, String result, boolean bindToVpn, String identity) {
            this.present = present;
            this.ipFamily = ipFamily;
            this.ipProtocol = ipProtocol;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.uid = uid;
            this.host = host;
            this.result = result;
            this.bindToVpn = bindToVpn;
            this.identity = identity == null ? "" : identity;
        }

        static S192ProbeFacts absent() {
            return new S192ProbeFacts(false, 0, 0, -1, -1, -1,
                    "", "", false, "");
        }
    }

    private void writeS190VpnNetworkGateStatus(RuntimeControlNative.Status status,
                                               String stage,
                                               String errorCode,
                                               String errorMessage) {
        RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        if (profile != RuntimeProfile.VPN) {
            return;
        }
        RuntimeControlFdClient.AttachResult nativeStatus = RuntimeControlFdClient.callJson(
                190, "VPN_TUN.STATUS", new JSONObject());
        JSONObject result = nativeStatus.ok ? nativeStatus.result : new JSONObject();
        long statusGeneration = status == null ? generation : status.generation;
        long requestedRevision = status == null ? 0L : status.policyRequestedRevision;
        long activeRevision = status == null ? 0L : status.policyActiveRevision;
        long policyGeneration = status == null ? 0L : status.policyGeneration;
        long worker0Revision = status == null ? 0L : status.policyWorker0Revision;
        long worker1Revision = status == null ? 0L : status.policyWorker1Revision;
        boolean revisionMatch = requestedRevision > 0L && requestedRevision == activeRevision;
        boolean generationMatch = status != null && status.policyGenerationMatch
                && policyGeneration == statusGeneration && statusGeneration > 0L;
        boolean workerRevisionMatch = activeRevision > 0L
                && worker0Revision == activeRevision
                && worker1Revision == activeRevision
                && status != null && !status.policyMixedRevision;
        boolean gateSnapshot = status != null
                && !status.policySnapshotEmpty
                && status.policyDefaultPass
                && status.policyL4RuleCount == 0
                && status.policyGateSubjectUid >= 0
                && status.policyGateNetworkContext
                == AuthoringPolicyBundle.NetworkContextId.VPN.wireId
                && status.policyGateReasonId > 0
                && status.policyGateRuleId > 0L
                && status.policyGateClaimCount == (status.policyGateBlocked ? 1 : 0);
        boolean dropRecorded = status != null
                && status.policyDropRecords > 0L
                && status.policyLastDropRevision == status.policyActiveRevision
                && status.policyLastDropRuleId == status.policyGateRuleId
                && status.policyLastDropCompletionAttempts == 1L
                && status.policyLastDropUid == status.policyGateSubjectUid
                && status.policyLastDropNetworkContext == status.policyGateNetworkContext
                && status.policyLastDropReasonId == status.policyGateReasonId
                && status.policyLastDropUidKnown
                && status.policyLastDropVerdict == PRODUCT_POLICY_VERDICT_DROP
                && status.policyLastDropWinner == PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE;
        int packetOriginCode = vpnPolicyDropPacketOriginCode(status, result);
        boolean vpnAdapterPolicyDropCompletion = dropRecorded
                && packetOriginCode == 1
                && status.vpnTunIngressPackets > 0L;
        String rustProductStore = policyStoreEvidencePath(status,
                "product-policy/network-gate-intent.properties");
        String code = errorCode == null ? "" : errorCode;
        String detail = errorMessage == null ? "" : errorMessage;
        String text = "schema=s190-vpn-network-gate/v1"
                + "\nstage=" + BoundedText.value(stage, RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\nprofile=vpn"
                + "\nstate=" + (code.isEmpty() ? "running" : "error")
                + "\nerrorCode=" + code
                + "\nerrorMessage=" + BoundedText.value(detail,
                RuntimeSnapshot.MAX_TEXT_LENGTH)
                + "\ngeneration=" + statusGeneration
                + "\nrequested_revision=" + requestedRevision
                + "\nactive_revision=" + activeRevision
                + "\nrevision_match=" + revisionMatch
                + "\npolicy_generation=" + policyGeneration
                + "\ngeneration_match=" + generationMatch
                + "\npolicy_snapshot_hash=" + (status == null ? "0"
                : Long.toUnsignedString(status.policySnapshotHash))
                + "\npolicy_snapshot_identity=" + (status == null ? ""
                : status.policySnapshotIdentity)
                + "\npolicy_snapshot_empty=" + (status != null
                && status.policySnapshotEmpty)
                + "\npolicy_default_pass=" + (status != null
                && status.policyDefaultPass)
                + "\ngate_snapshot=" + gateSnapshot
                + "\ngate_claim_count=" + (status == null ? 0
                : status.policyGateClaimCount)
                + "\nl4_rule_count=" + (status == null ? 0 : status.policyL4RuleCount)
                + "\ngate_subject_uid=" + (status == null ? 0
                : status.policyGateSubjectUid)
                + "\ngate_network_context=" + (status == null ? 0
                : status.policyGateNetworkContext)
                + "\ngate_blocked=" + (status != null && status.policyGateBlocked)
                + "\ngate_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyGateRuleId))
                + "\ngate_reason_id=" + (status == null ? 0
                : status.policyGateReasonId)
                + "\nworker0_revision=" + worker0Revision
                + "\nworker1_revision=" + worker1Revision
                + "\nworker_revision_match=" + workerRevisionMatch
                + "\npolicy_mixed_revision=" + (status != null
                && status.policyMixedRevision)
                + "\nsubmission_status_code=" + (status == null ? -1
                : status.policyLastApplyStatusCode)
                + "\noperation_status_code=" + (status == null ? -1 : status.code)
                + "\nartifact_match=" + (status != null && status.policyArtifactMatch)
                + "\npolicy_drop_records=" + (status == null ? 0L
                : status.policyDropRecords)
                + "\npolicy_last_drop_revision=" + (status == null ? 0L
                : status.policyLastDropRevision)
                + "\npolicy_last_drop_rule_id=" + (status == null ? "0"
                : Long.toUnsignedString(status.policyLastDropRuleId))
                + "\npolicy_last_drop_completion_attempts=" + (status == null ? 0L
                : status.policyLastDropCompletionAttempts)
                + "\npolicy_last_drop_uid=" + (status == null ? 0
                : status.policyLastDropUid)
                + "\npolicy_last_drop_network_context=" + (status == null ? 0
                : status.policyLastDropNetworkContext)
                + "\npolicy_last_drop_reason_id=" + (status == null ? 0
                : status.policyLastDropReasonId)
                + "\npolicy_last_drop_verdict=" + (status == null ? 0
                : status.policyLastDropVerdict)
                + "\npolicy_last_drop_winner=" + (status == null ? 0
                : status.policyLastDropWinner)
                + "\npolicy_last_drop_uid_known=" + (status != null
                && status.policyLastDropUidKnown)
                + "\npolicy_last_drop_packet_origin=" + (status == null ? ""
                : vpnPacketOriginName(packetOriginCode))
                + "\npolicy_last_drop_packet_origin_code=" + (status == null ? 0
                : packetOriginCode)
                + "\npolicy_drop_recorded=" + dropRecorded
                + "\nexpected_policy_last_drop_verdict=" + PRODUCT_POLICY_VERDICT_DROP
                + "\nexpected_policy_last_drop_winner="
                + PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE
                + "\nexpected_policy_last_drop_packet_origin=1"
                + "\npolicy_stage=network_gate"
                + "\npolicy_winner=network_gate"
                + "\npolicy_verdict=drop"
                + "\npolicy_drop_reason=policy_gate"
                + "\nvpn_policy_hint_subject_uid="
                + result.optLong("policySubjectUid", -1L)
                + "\nvpn_policy_hint_network_context="
                + result.optLong("policyNetworkContext", 0L)
                + "\nvpn_tun_status_available=" + (nativeStatus.ok ? "1" : "0")
                + "\nvpn_tun_fd_attached=" + result.optLong("vpnTunFdAttached", 0L)
                + "\nvpn_direct_tcp4_socket_attached="
                + result.optLong("vpnDirectTcp4SocketAttached", 0L)
                + "\nvpn_direct_tcp4_protect_succeeded="
                + result.optLong("vpnDirectTcp4ProtectSucceeded", 0L)
                + "\nvpn_direct_tcp4_bind_succeeded="
                + result.optLong("vpnDirectTcp4BindSucceeded", 0L)
                + "\nvpn_tun_ingress_packets=" + (status == null ? 0L
                : status.vpnTunIngressPackets)
                + "\nvpn_tun_tcp4_tun_origin_packets="
                + result.optLong("vpnTunTcp4TunOriginPackets", 0L)
                + "\nvpn_flow_stack_admissions=" + (status == null ? 0L
                : status.vpnFlowStackAdmissions)
                + "\nvpn_direct_tcp4_connect_attempts="
                + result.optLong("vpnDirectTcp4ConnectAttempts", 0L)
                + "\nvpn_direct_tcp4_connect_succeeded="
                + result.optLong("vpnDirectTcp4ConnectSucceeded", 0L)
                + "\nvpn_direct_tcp4_payload_bytes_from_tun="
                + result.optLong("vpnDirectTcp4PayloadBytesFromTun", 0L)
                + "\nvpn_direct_tcp4_socket_write_completions="
                + result.optLong("vpnDirectTcp4SocketWriteCompletions", 0L)
                + "\nvpn_direct_tcp4_socket_read_packets="
                + result.optLong("vpnDirectTcp4SocketReadPackets", 0L)
                + "\nvpn_direct_tcp4_return_packets="
                + result.optLong("vpnDirectTcp4ReturnPackets", 0L)
                + "\nvpn_direct_tcp4_tun_write_completions="
                + result.optLong("vpnDirectTcp4TunWriteCompletions", 0L)
                + "\nvpn_direct_tcp4_transport_failed="
                + result.optLong("vpnDirectTcp4TransportFailed", 0L)
                + "\nvpn_flow_stack_return_provenance_packets="
                + (status == null ? 0L : status.vpnFlowStackReturnProvenancePackets)
                + "\nvpn_tun_write_completions=" + (status == null ? 0L
                : status.vpnTunWriteCompletions)
                + "\nvpn_infrastructure_faults=" + (status == null ? 0L
                : status.vpnInfrastructureFaults)
                + "\nvpn_duplicate_or_stale_drops=" + (status == null ? 0L
                : status.vpnDuplicateOrStaleDrops)
                + "\nvpn_adapter_policy_drop_completion="
                + vpnAdapterPolicyDropCompletion
                + "\nadapter_completion_separate=vpn_tun_and_flow_stack_counters"
                + "\ntransport_outcome_separate=direct_socket_counters"
                + "\nphysical_nfqueue_completion=false"
                + "\nroot_vpn_shared_product_store=true"
                + "\nrust_product_store=" + rustProductStore
                + "\nrust_product_store_single_writer=true"
                + "\nui_policy_authority=false"
                + "\nvpp_policy_authority=false"
                + "\nartifact_id=" + (status == null ? "" : status.artifactId)
                + "\napi_identity=" + (status == null ? "" : status.apiIdentity)
                + "\nvpp_revision=" + (status == null ? "" : status.vppRevision)
                + "\n";
        writeBestEffortEvidenceFile(S190_VPN_NETWORK_GATE_STATUS, text);
    }

    private static boolean s187WorkerCoreConfigMatches(RuntimeControlNative.Status status) {
        if (status == null) {
            return false;
        }
        return status.productGraphWorkerCount == parseFixedInt(PRODUCT_CORE_WORKER_COUNT, -1)
                && status.productGraphVppWorkerCount == parseFixedInt(PRODUCT_CORE_WORKER_COUNT, -1)
                && status.productGraphVppMainCore == parseFixedInt(PRODUCT_CORE_MAIN_CORE, -1)
                && status.productGraphVppWorker0Core == parseFixedInt(
                        PRODUCT_CORE_WORKER0_CORE, -1)
                && status.productGraphVppWorker1Core == parseFixedInt(
                        PRODUCT_CORE_WORKER1_CORE, -1)
                && status.productGraphWorkerLayoutReady != 0;
    }

    private static int parseFixedInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private void writeS194PolicyMutationFaultStatus(String mode, boolean armed,
                                                     RuntimeControlNative.Status status,
                                                     String error) {
        String normalizedMode = s192PropertyToken(mode);
        String statusCode = status == null ? "-1" : Integer.toString(status.code);
        String detail = status == null ? "" : s192PropertyToken(status.errorDetail);
        String text = "schema=s194-product-mutation-fault/v1"
                + "\nmode=" + normalizedMode
                + "\narmed=" + armed
                + "\ngeneration=" + (status == null ? generation : status.generation)
                + "\noperation_status_code=" + statusCode
                + "\nerrorCode=" + s192PropertyToken(error)
                + "\nerrorMessage=" + detail
                + "\nconsumption=next_typed_bundle_apply_only"
                + "\n\n";
        writeBestEffortEvidenceFile(S194_POLICY_MUTATION_FAULT_STATUS, text);
    }

    private void writeBestEffortEvidenceFile(String relativePath, String text) {
        File file = new File(getFilesDir(), relativePath);
        File parent = file.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs()
                && !parent.isDirectory())) {
            appendLog("s176_evidence=unavailable path=" + relativePath);
            return;
        }
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(text.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (IOException error) {
            appendLog("s176_evidence=write_failed path=" + relativePath
                    + " error=" + messageOf(error));
        }
    }

    private void monitorProductCoreExit(Process process) {
        Thread monitor = new Thread(() -> {
            int exitCode;
            try {
                exitCode = process.waitFor();
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return;
            }
            enqueueLifecycle(() -> {
                if (process != vppProcess || stopRequested
                        || (snapshot != null
                        && RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state))) {
                    return;
                }
                failProductCoreGeneration("unexpected_exit",
                        "VPP sidecar exited with status " + exitCode);
            });
        }, "sakamoto-product-core-exit-monitor");
        monitor.start();
    }

    private void failProductCoreGeneration(String code, String message) {
        if (cleanupFaultInjected && (processAlive(vppProcess)
                || (productCoreSession != null && productCoreSession.isConnected()))) {
            publishError("cleanup_failed", code + ": " + message
                    + "; generation cleanup fault injected", true,
                    ProductCoreLifecycle.UNKNOWN_PID);
            return;
        }
        closeVpnDirectTcp4SessionQuietly();
        closeVpnDirectTcp6SessionQuietly();
        closeVpnDirectUdp6SessionQuietly();
        closeVpnDirectUdp4SessionQuietly();
        RuntimeControlNative.Status closeStatus = closeProductCoreSession();
        boolean closeFailed = closeStatus != null && closeStatus.code != 0;
        String closeCode = "";
        String closeDetail = "";
        if (closeFailed) {
            closeCode = ProductCoreLifecycle.failureCode(closeStatus);
            closeDetail = closeStatus.errorDetail.isEmpty()
                    ? closeCode : closeStatus.errorDetail;
        }
        boolean processStopped = terminateProductCoreProcess();
        boolean ownerStopped = terminateProductCoreOwnerProcess();
        if (closeFailed && "unexpected_exit".equals(code)
                && processStopped && ownerStopped) {
            appendLog("product_core_close=ignored_after_unexpected_exit code=" + closeCode);
            closeFailed = false;
        }
        if (closeFailed) {
            message = message + "; " + closeCode + ": " + closeDetail;
        }
        boolean clean = (activeProfile == RuntimeProfile.ROOT
                ? ownerStopped : processStopped && ownerStopped) && !closeFailed;
        if (clean && activeProfile == RuntimeProfile.ROOT) {
            clean = productRootNfqueueResidueClean();
        }
        if (clean && profileRoot != null && profileRoot.exists()) {
            clean = cleanProductCoreProfile(profileRoot);
        }
        if (clean) {
            productCoreSession = null;
            vppProcess = null;
            clearProfileHandles();
        }
        publishError(clean ? code : "cleanup_failed",
                clean ? message : code + ": " + message + "; generation cleanup failed",
                !clean, ProductCoreLifecycle.UNKNOWN_PID);
        stopIfInactive();
    }

    private RuntimeControlNative.Status closeProductCoreSession() {
        RuntimeControlNative.Session session = productCoreSession;
        if (session != null) {
            return session.closeAndGetStatus();
        }
        return null;
    }

    private boolean terminateProductCoreProcess() {
        if (cleanupFaultInjected) {
            return false;
        }
        Process process = vppProcess;
        if (process == null) {
            return true;
        }
        if (!process.isAlive()) {
            return true;
        }
        process.destroy();
        try {
            if (process.waitFor(STOP_TERM_MILLIS, TimeUnit.MILLISECONDS)
                    && !process.isAlive()) {
                return true;
            }
            // A graceful destroy is bounded.  Escalate only while the same
            // Process handle still reports a live child, then wait again
            // before any generation-owned profile is removed.
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            return process.waitFor(STOP_KILL_MILLIS, TimeUnit.MILLISECONDS)
                    && !process.isAlive();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private boolean terminateProductCoreOwnerProcess() {
        if (cleanupFaultInjected) {
            return false;
        }
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        try {
            File profile = profileDirectory(selected);
            ProductCoreOwner.OwnerRecord owner = readProductCoreOwner(profile);
            if (owner == null) {
                return true;
            }
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File vpp = new File(nativeDir, VPP_BINARY).getCanonicalFile();
            long pid = auditProductCoreProcessPid(owner, vpp);
            if (pid <= 0L) {
                return true;
            }
            appendLog("product_core_owner_terminate=TERM pid=" + pid);
            runPlatformCommandStatus(owner.profile, "kill -TERM " + pid, 2L);
            if (waitProductCoreOwnerGone(owner, vpp, STOP_TERM_MILLIS)) {
                return true;
            }
            long currentPid = auditProductCoreProcessPid(owner, vpp);
            if (currentPid <= 0L) {
                return true;
            }
            if (currentPid != pid) {
                appendLog("product_core_owner_terminate=pid_changed original="
                        + pid + " current=" + currentPid);
                return false;
            }
            appendLog("product_core_owner_terminate=KILL pid=" + pid);
            runPlatformCommandStatus(owner.profile, "kill -KILL " + pid, 2L);
            return waitProductCoreOwnerGone(owner, vpp, STOP_KILL_MILLIS);
        } catch (Exception error) {
            appendLog("product_core_owner_terminate=failed " + messageOf(error));
            return false;
        }
    }

    private boolean crashProductCoreOwnerProcess() {
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        try {
            File profile = profileDirectory(selected);
            ProductCoreOwner.OwnerRecord owner = readProductCoreOwner(profile);
            if (owner == null) {
                return false;
            }
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File vpp = new File(nativeDir, VPP_BINARY).getCanonicalFile();
            long pid = auditProductCoreProcessPid(owner, vpp);
            if (pid <= 0L) {
                return false;
            }
            appendLog("debug vpn native crash fault=owner_kill pid=" + pid);
            runPlatformCommandStatus(owner.profile, "kill -KILL " + pid, 2L);
            return waitProductCoreOwnerGone(owner, vpp, STOP_KILL_MILLIS);
        } catch (Exception error) {
            appendLog("debug vpn native crash owner_kill_failed=" + messageOf(error));
            return false;
        }
    }

    private boolean waitProductCoreOwnerGone(ProductCoreOwner.OwnerRecord owner, File vpp,
                                             long timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (true) {
            ProductCoreOwner.ProcessState state = auditProductCoreProcess(owner, vpp);
            if (state == ProductCoreOwner.ProcessState.GONE) {
                return true;
            }
            if (System.currentTimeMillis() >= deadline) {
                return false;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    private Properties readProductManifest() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = getAssets().open(PRODUCT_MANIFEST_ASSET)) {
            properties.load(input);
        }
        return properties;
    }

    /**
     * Audit the two fixed app-owned Product Core profiles before START/STOP
     * can replace or remove residue. A missing record or unreadable process
     * scan is unknown; only exact records plus zero-owner scans are cleanable.
     */
    private ProductCoreOwner.GlobalDecision auditProductCoreOwners(
            RuntimeProfile selected, String artifactId, String revision, File vpp,
            boolean processHandleLive) throws IOException {
        ProductCoreOwner.ProcessState globalProcessState = auditGlobalProductCoreProcess(vpp);
        ProductCoreOwner.ProfileFact root = auditProductCoreProfile(
                RuntimeProfile.ROOT, artifactId, revision, vpp);
        ProductCoreOwner.ProfileFact vpn = auditProductCoreProfile(
                RuntimeProfile.VPN, artifactId, revision, vpp);
        return ProductCoreOwner.decideGlobalForStart(
                selected, root, vpn, processHandleLive, globalProcessState);
    }

    private ProductCoreOwner.ProfileFact auditProductCoreProfile(
            RuntimeProfile profile, String artifactId, String revision, File vpp)
            throws IOException {
        File profileDirectory = profileDirectory(profile);
        if (!profileDirectory.exists()) {
            return ProductCoreOwner.ProfileFact.absent(profile);
        }
        // A candidate-only publication has no launchable startup/runtime
        // tree. Repair this interrupted fact before comparing artifact or
        // revision, so an upgrade cannot strand it as a permanent mismatch.
        if (ProductCoreOwner.isInterruptedPublicationOnly(profileDirectory)) {
            return ProductCoreOwner.ProfileFact.repairable(profile,
                    "interrupted Product Core publication has no launchable runtime");
        }
        ProductCoreOwner.OwnerRecord owner = readProductCoreOwner(profileDirectory);
        if (owner == null) {
            return ProductCoreOwner.ProfileFact.unknown(profile,
                    "Product Core owner record is missing or malformed");
        }
        ProductCoreOwner.OwnerRecord expected;
        try {
            File runtime = new File(profileDirectory, "runtime").getCanonicalFile();
            File socket = new File(runtime, "api.sock").getCanonicalFile();
            expected = ProductCoreOwner.OwnerRecord.create(owner.generation, owner.token,
                    profile, runtime.getPath(), socket.getPath(), artifactId, revision);
        } catch (RuntimeException error) {
            return ProductCoreOwner.ProfileFact.unknown(profile, owner,
                    "Product Core owner identity is malformed");
        }
        if (!owner.sameInstallation(expected)) {
            return ProductCoreOwner.ProfileFact.unknown(profile, owner,
                    "Product Core owner identity does not match this installation");
        }
        ProductCoreOwner.ProcessState processState = auditProductCoreProcess(owner, vpp);
        if (processState == ProductCoreOwner.ProcessState.LIVE) {
            return ProductCoreOwner.ProfileFact.live(profile, owner);
        }
        if (processState == ProductCoreOwner.ProcessState.GONE) {
            return ProductCoreOwner.ProfileFact.exactGone(profile, owner);
        }
        return ProductCoreOwner.ProfileFact.unknown(profile, owner,
                "Product Core owner process state could not be verified");
    }

    private boolean cleanProductCoreResidue(ProductCoreOwner.GlobalDecision ownerDecision) {
        if (ownerDecision.shouldClean(RuntimeProfile.ROOT)) {
            File root = profileDirectory(RuntimeProfile.ROOT);
            if (!productRootNfqueueResidueClean(RuntimeProfile.ROOT)
                    || !cleanProductCoreProfile(root)) {
                return false;
            }
        }
        if (ownerDecision.shouldClean(RuntimeProfile.VPN)) {
            File vpn = profileDirectory(RuntimeProfile.VPN);
            if (!cleanProductCoreProfile(vpn)) {
                return false;
            }
        }
        return true;
    }

    private boolean cleanProductCoreProfileResidue(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        if (selected == RuntimeProfile.ROOT
                && !productRootNfqueueResidueClean(RuntimeProfile.ROOT)) {
            return false;
        }
        return cleanProductCoreProfile(profileDirectory(selected));
    }

    /**
     * The Root adapter owns only this generation's fixed dual-stack
     * INPUT/OUTPUT chains. Remove them before deleting the durable profile,
     * then prove neither the jumps nor the chains remain. A missing
     * privileged runner is a cleanup failure, never permission to report a
     * stopped Root adapter.
     */
    private boolean productRootNfqueueResidueClean() {
        return productRootNfqueueResidueClean(activeProfile);
    }

    private boolean productRootNfqueueResidueClean(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        if (selected != RuntimeProfile.ROOT) {
            return true;
        }
        if (!rootCommandAvailable()) {
            appendLog("product_root_nfqueue_cleanup=root_authorization_required");
            writeS176RootNfqueueCleanupStatus(false);
            return false;
        }
        String outputChain = PRODUCT_ROOT_NFQUEUE_CHAIN;
        String inputChain = PRODUCT_ROOT_NFQUEUE_INPUT_CHAIN;
        String command = "set +e; "
                + "while iptables -w -t mangle -D OUTPUT -j " + outputChain
                + " >/dev/null 2>&1; do :; done; "
                + "while iptables -w -t mangle -D INPUT -j " + inputChain
                + " >/dev/null 2>&1; do :; done; "
                + "iptables -w -t mangle -F " + outputChain + " >/dev/null 2>&1; "
                + "iptables -w -t mangle -X " + outputChain + " >/dev/null 2>&1; "
                + "iptables -w -t mangle -F " + inputChain + " >/dev/null 2>&1; "
                + "iptables -w -t mangle -X " + inputChain + " >/dev/null 2>&1; "
                + "while ip6tables -w -t mangle -D OUTPUT -j " + outputChain
                + " >/dev/null 2>&1; do :; done; "
                + "while ip6tables -w -t mangle -D INPUT -j " + inputChain
                + " >/dev/null 2>&1; do :; done; "
                + "ip6tables -w -t mangle -F " + outputChain + " >/dev/null 2>&1; "
                + "ip6tables -w -t mangle -X " + outputChain + " >/dev/null 2>&1; "
                + "ip6tables -w -t mangle -F " + inputChain + " >/dev/null 2>&1; "
                + "ip6tables -w -t mangle -X " + inputChain + " >/dev/null 2>&1; "
                + "if iptables -w -t mangle -S OUTPUT 2>/dev/null | grep -F -- '-j "
                + outputChain + "' >/dev/null; then exit 1; fi; "
                + "if iptables -w -t mangle -S INPUT 2>/dev/null | grep -F -- '-j "
                + inputChain + "' >/dev/null; then exit 1; fi; "
                + "if iptables -w -t mangle -S " + outputChain
                + " >/dev/null 2>&1; then exit 1; fi; "
                + "if iptables -w -t mangle -S " + inputChain
                + " >/dev/null 2>&1; then exit 1; fi; "
                + "if ip6tables -w -t mangle -S OUTPUT 2>/dev/null | grep -F -- '-j "
                + outputChain + "' >/dev/null; then exit 1; fi; "
                + "if ip6tables -w -t mangle -S INPUT 2>/dev/null | grep -F -- '-j "
                + inputChain + "' >/dev/null; then exit 1; fi; "
                + "if ip6tables -w -t mangle -S " + outputChain
                + " >/dev/null 2>&1; then exit 1; fi; "
                + "if ip6tables -w -t mangle -S " + inputChain
                + " >/dev/null 2>&1; then exit 1; fi; "
                + "exit 0";
        boolean clean = runRootCommand(command, 5L);
        appendLog("product_root_nfqueue_cleanup=" + (clean ? "clean" : "failed"));
        writeS176RootNfqueueCleanupStatus(clean);
        return clean;
    }

    /**
     * Android owns the platform hook because it also owns root authorization
     * and APK UID identity. Product VPP owns only the NFQUEUE socket/listener
     * and packet graph completion path.
     */
    private boolean installProductRootNfqueueHook() {
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        if (selected != RuntimeProfile.ROOT) {
            return true;
        }
        // Android owns the platform hook because it owns root authorization
        // and this debug APK's UID. Product VPP owns the NFQUEUE listener.
        if (!rootCommandAvailable()) {
            appendLog("product_root_nfqueue_hook_install=root_authorization_required");
            return false;
        }
        String outputChain = PRODUCT_ROOT_NFQUEUE_CHAIN;
        String inputChain = PRODUCT_ROOT_NFQUEUE_INPUT_CHAIN;
        String queue = PRODUCT_ROOT_NFQUEUE_QUEUE;
        String queueLast = PRODUCT_ROOT_NFQUEUE_QUEUE_LAST;
        String uid = Integer.toString(getApplicationInfo().uid);
        String command = "set +e; "
                + "while iptables -w -t mangle -D OUTPUT -j " + outputChain
                + " >/dev/null 2>&1; do :; done; "
                + "while iptables -w -t mangle -D INPUT -j " + inputChain
                + " >/dev/null 2>&1; do :; done; "
                + "iptables -w -t mangle -F " + outputChain + " >/dev/null 2>&1; "
                + "iptables -w -t mangle -X " + outputChain + " >/dev/null 2>&1; "
                + "iptables -w -t mangle -F " + inputChain + " >/dev/null 2>&1; "
                + "iptables -w -t mangle -X " + inputChain + " >/dev/null 2>&1; "
                + "while ip6tables -w -t mangle -D OUTPUT -j " + outputChain
                + " >/dev/null 2>&1; do :; done; "
                + "while ip6tables -w -t mangle -D INPUT -j " + inputChain
                + " >/dev/null 2>&1; do :; done; "
                + "ip6tables -w -t mangle -F " + outputChain + " >/dev/null 2>&1; "
                + "ip6tables -w -t mangle -X " + outputChain + " >/dev/null 2>&1; "
                + "ip6tables -w -t mangle -F " + inputChain + " >/dev/null 2>&1; "
                + "ip6tables -w -t mangle -X " + inputChain + " >/dev/null 2>&1; "
                + "set -e; "
                + "iptables -w -t mangle -N " + outputChain + "; "
                + "iptables -w -t mangle -A " + outputChain
                + " -p udp -m owner --uid-owner " + uid
                + " -j NFQUEUE --queue-num " + queue + " --queue-bypass; "
                + "iptables -w -t mangle -I OUTPUT -j " + outputChain + "; "
                + "iptables -w -t mangle -S " + outputChain
                + " | grep -F -- '--queue-num " + queue + "' >/dev/null";
        for (int attempt = 1; attempt <= PRODUCT_ROOT_NFQUEUE_HOOK_INSTALL_ATTEMPTS;
                attempt++) {
            if (runRootCommand(command, 5L)) {
                appendLog("product_root_nfqueue_hook_install=installed attempt=" + attempt);
                return true;
            }
            appendLog("product_root_nfqueue_hook_install=failed attempt=" + attempt);
            if (attempt < PRODUCT_ROOT_NFQUEUE_HOOK_INSTALL_ATTEMPTS) {
                productRootNfqueueResidueClean(RuntimeProfile.ROOT);
                try {
                    Thread.sleep(PRODUCT_ROOT_NFQUEUE_HOOK_INSTALL_RETRY_MILLIS * attempt);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        appendLog("product_root_nfqueue_hook_install=failed");
        return false;
    }

    /** Delete generation contents first; owner.properties is the final authority removed. */
    private boolean cleanProductCoreProfile(File profile) {
        if (profile == null || !profile.exists()) {
            return true;
        }
        File owner = new File(profile, ProductCoreOwner.RECORD_FILE);
        File[] children = profile.listFiles();
        if (children == null) {
            return false;
        }
        for (File child : children) {
            if (!child.equals(owner) && !deleteTree(child)) {
                return false;
            }
        }
        byte[] ownerAuthority = null;
        if (owner.isFile()) {
            try {
                ownerAuthority = ProductCoreOwner.OwnerRecord.read(owner).encode()
                        .getBytes(StandardCharsets.US_ASCII);
            } catch (IOException error) {
                return false;
            }
        }
        if (owner.exists() && !owner.delete()) {
            return false;
        }
        if (!profile.exists() || profile.delete()) {
            return true;
        }
        // Directory removal can still fail after owner deletion. Restore the
        // complete authority before reporting cleanup failure so a later
        // explicit audit can retry without adopting a new owner.
        if (ownerAuthority != null) {
            try {
                ProductCoreOwner.writeAtomic(owner, ownerAuthority);
            } catch (IOException ignored) {
                // The failed cleanup remains visible; no replacement follows.
            }
        }
        return false;
    }

    private ProductCoreOwner.OwnerRecord readProductCoreOwner(File profile) {
        if (profile == null) {
            return null;
        }
        try {
            return ProductCoreOwner.OwnerRecord.readPending(
                    new File(profile, ProductCoreOwner.RECORD_FILE));
        } catch (IOException error) {
            return null;
        }
    }

    private long nextProductCoreGeneration(ProductCoreOwner.GlobalDecision ownerDecision)
            throws IOException {
        long highest = Math.max(generation,
                ownerDecision == null ? 0L : ownerDecision.highestGeneration());
        File state = new File(getFilesDir(), PRODUCT_CORE_GENERATION_STATE);
        if (state.isFile()) {
            Properties values = new Properties();
            try (InputStream input = new FileInputStream(state)) {
                values.load(input);
            }
            String persisted = values.getProperty("generation", "").trim();
            if (!persisted.isEmpty()) {
                try {
                    highest = Math.max(highest, Long.parseLong(persisted));
                } catch (NumberFormatException error) {
                    throw new IOException("Product Core generation state is invalid", error);
                }
            }
        }
        long next = highest + 1L;
        if (next <= 0L) {
            throw new IOException("Product Core generation overflow");
        }
        File parent = state.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs()
                && !parent.isDirectory())) {
            throw new IOException("Product Core generation state directory is unavailable");
        }
        ProductCoreOwner.writeAtomic(state, ("generation=" + next + "\n")
                .getBytes(StandardCharsets.US_ASCII));
        return next;
    }

    private ProductCoreOwner.ProcessState auditProductCoreProcess(
            ProductCoreOwner.OwnerRecord owner, File vpp) {
        try {
            RuntimeOwnershipReconciliation.CommandResult result = runProductCoreCommandResult(
                    ProductCoreOwner.buildProcessAuditCommand(owner, vpp.getPath(),
                            owner.profile == RuntimeProfile.ROOT ? "0"
                                    : Integer.toString(android.os.Process.myUid())),
                    owner.profile);
            return ProductCoreOwner.processState(result.status, result.output);
        } catch (RuntimeException error) {
            appendLog("product_core_owner_audit=unknown " + messageOf(error));
            return ProductCoreOwner.ProcessState.UNKNOWN;
        }
    }

    private long auditProductCoreProcessPid(ProductCoreOwner.OwnerRecord owner, File vpp) {
        try {
            RuntimeOwnershipReconciliation.CommandResult result = runProductCoreCommandResult(
                    ProductCoreOwner.buildProcessAuditCommand(owner, vpp.getPath(),
                            owner.profile == RuntimeProfile.ROOT ? "0"
                                    : Integer.toString(android.os.Process.myUid())),
                    owner.profile);
            return ProductCoreOwner.processPid(result.status, result.output);
        } catch (RuntimeException error) {
            appendLog("product_core_owner_pid_audit=unknown " + messageOf(error));
            return ProductCoreOwner.UNKNOWN_PID;
        }
    }

    /** Catch an unregistered VPP in either mutually-exclusive runtime identity. */
    private ProductCoreOwner.ProcessState auditGlobalProductCoreProcess(File vpp) {
        try {
            RuntimeOwnershipReconciliation.CommandResult rootResult = runProductCoreCommandResult(
                    ProductCoreOwner.buildGlobalProcessAuditCommand(vpp.getPath(),
                            "0"), RuntimeProfile.ROOT);
            ProductCoreOwner.ProcessState root = ProductCoreOwner.processState(
                    rootResult.status, rootResult.output);
            if (root != ProductCoreOwner.ProcessState.GONE) {
                return root;
            }
            RuntimeOwnershipReconciliation.CommandResult vpnResult = runProductCoreCommandResult(
                    ProductCoreOwner.buildGlobalProcessAuditCommand(vpp.getPath(),
                            Integer.toString(android.os.Process.myUid())), RuntimeProfile.VPN);
            return ProductCoreOwner.processState(vpnResult.status, vpnResult.output);
        } catch (RuntimeException error) {
            appendLog("product_core_global_owner_audit=unknown " + messageOf(error));
            return ProductCoreOwner.ProcessState.UNKNOWN;
        }
    }

    /** Root owner inspection uses the same bounded privileged runner as launch/cleanup. */
    private RuntimeOwnershipReconciliation.CommandResult runProductCoreCommandResult(
            String command, RuntimeProfile profile) {
        Process process = null;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            if (profile == RuntimeProfile.ROOT) {
                if (!rootCommandAvailable()) {
                    return new RuntimeOwnershipReconciliation.CommandResult(
                            ROOT_COMMAND_UNAVAILABLE, "PRODUCT_OWNER_AUDIT_ERROR=root");
                }
                process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command)
                        .redirectErrorStream(true).start();
            } else {
                process = new ProcessBuilder("/system/bin/sh", "-c", command)
                        .redirectErrorStream(true).start();
            }
            if (!process.waitFor(3L, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new RuntimeOwnershipReconciliation.CommandResult(124,
                        "PRODUCT_OWNER_AUDIT_ERROR=timeout");
            }
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[256];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count > 0 && output.size() < 4096) {
                        output.write(buffer, 0, Math.min(count, 4096 - output.size()));
                    }
                }
            }
            return new RuntimeOwnershipReconciliation.CommandResult(process.exitValue(),
                    output.toString(StandardCharsets.UTF_8.name()));
        } catch (Exception error) {
            if (process != null) {
                process.destroyForcibly();
            }
            return new RuntimeOwnershipReconciliation.CommandResult(125,
                    "PRODUCT_OWNER_AUDIT_ERROR=runner");
        }
    }

    private static String requiredProductProperty(Properties properties, String name)
            throws IOException {
        String value = properties.getProperty(name, "").trim();
        if (value.isEmpty()) {
            throw new IOException("product stage property is missing: " + name);
        }
        return value;
    }

    private static int requiredProductIntProperty(Properties properties, String name)
            throws IOException {
        String value = requiredProductProperty(properties, name);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException error) {
            throw new IOException("product manifest property is not an integer: " + name,
                    error);
        }
    }

    private void prepareProductCoreProfile(File profile, File nativeDir,
                                           ProductCoreOwner.OwnerRecord owner)
            throws IOException {
        File runtime = new File(profile, "runtime");
        File logs = new File(profile, "logs");
        File svm = new File(profile, "shm");
        String nativeLibraryPath = safeVppConfigPath(nativeDir);
        if (!profile.isDirectory() && !profile.mkdirs()) {
            throw new IOException("unable to create generation-owned Product Core profile");
        }
        // Publish owner.properties first. If startup publication is
        // interrupted, the complete owner fact remains auditable and the
        // next explicit START can prove it gone, remove this exact profile,
        // and perform a fresh restart. VPP is launched only after both files.
        owner.write(new File(profile, ProductCoreOwner.RECORD_FILE));
        if ((!runtime.isDirectory() && !runtime.mkdirs())
                || (!logs.isDirectory() && !logs.mkdirs())
                || (!svm.isDirectory() && !svm.mkdirs())) {
            throw new IOException("unable to create generation-owned profile directories");
        }
        String config = "plugin_path " + nativeLibraryPath + "\n\n"
                + "cpu {\n  main-core " + PRODUCT_CORE_MAIN_CORE
                + "\n  corelist-workers " + PRODUCT_CORE_WORKER_CORES
                + "\n}\n\n"
                + "unix {\n  nodaemon\n  nobanner\n  runtime-dir "
                + runtime.getPath() + "\n  log " + new File(logs, "vpp.log").getPath()
                + "\n  cli-listen " + new File(runtime, "cli.sock").getPath()
                + "\n  cli-no-pager\n}\n\n"
                + "socksvr {\n  socket-name " + new File(runtime, "api.sock").getPath()
                + "\n}\n\napi-segment {\n  prefix sakamoto-product-" + generation
                + "\n}\n\nstatseg {\n  socket-name "
                + new File(runtime, "statseg.sock").getPath() + "\n}\n\n"
                + "plugins {\n  path " + nativeLibraryPath
                + "\n  plugin default { disable }\n  plugin "
                + PRODUCT_PLUGIN_BINARY + " { enable }\n}\n";
        ProductCoreOwner.writeAtomic(new File(profile, "startup.conf"),
                config.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Render one trusted native-library directory as a VPP config token.
     * VPP's {@code %s} parser accepts a brace-delimited token and removes
     * backslash escapes, so paths remain a single value even if a platform
     * ever supplies whitespace or a config delimiter. Control characters
     * and colons are rejected because they cannot safely occur in a
     * line-oriented startup configuration or VPP's colon-separated plugin
     * path list.
     */
    private static String safeVppConfigPath(File path) throws IOException {
        if (path == null) {
            throw new IOException("nativeLibraryDir is absent");
        }
        String value = path.getPath();
        if (value.isEmpty() || value.charAt(0) != '/') {
            throw new IOException("nativeLibraryDir is not absolute");
        }
        StringBuilder escaped = new StringBuilder(value.length() + 2);
        escaped.append('{');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isISOControl(character) || character == '#' || character == ':') {
                throw new IOException(
                        "nativeLibraryDir contains an unsafe startup-config character");
            }
            if (character == '\\' || character == '{' || character == '}') {
                escaped.append('\\');
            }
            escaped.append(character);
        }
        return escaped.append('}').toString();
    }

    private void reconcileDurableRuntime() {
        reconcileDurableRuntime(false);
    }

    private void reconcileDurableRuntime(boolean forceHealthQuery) {
        reconcileDurableRuntime(forceHealthQuery, 0L);
    }

    private void reconcileDurableRuntime(boolean forceHealthQuery, long queryRevision) {
        reconcileProductCoreRuntime(forceHealthQuery, queryRevision);
    }

    /**
     * Product Core has no cross-service adoption. A service recreation first
     * audits both fixed durable owner records and app-UID process identities;
     * it leaves exact gone profiles for visible START to clean, while
     * live/unknown ownership remains an explicit blocking error.
     */
    private void reconcileProductCoreRuntime(boolean forceHealthQuery, long queryRevision) {
        Process process = vppProcess;
        if (processAlive(process) && productCoreSession != null
                && productCoreSession.isConnected()) {
            if (forceHealthQuery) {
                queryProductCoreRuntime();
            }
            return;
        }
        if (processAlive(process) || (productCoreSession != null
                && productCoreSession.isConnected())) {
            publishError("product_core_owner_live",
                    "Product Core handles are inconsistent; replacement is blocked", true,
                    ProductCoreLifecycle.UNKNOWN_PID);
            return;
        }
        RuntimeProfile selected = snapshot == null || snapshot.profile == null
                ? (activeProfile == null ? RuntimeProfile.ROOT : activeProfile)
                : snapshot.profile;
        activeProfile = selected;
        initializeProfilePaths(selected);
        ProductCoreOwner.GlobalDecision ownerDecision;
        try {
            Properties manifest = readProductManifest();
            String artifactId = requiredProductProperty(manifest, "artifactId");
            String revision = requiredProductProperty(manifest, "vppRevision");
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File vpp = new File(nativeDir, VPP_BINARY).getCanonicalFile();
            ownerDecision = auditProductCoreOwners(selected, artifactId, revision, vpp, false);
        } catch (Exception error) {
            ProductCoreOwner.ProfileFact root = ProductCoreOwner.ProfileFact.unknown(
                    RuntimeProfile.ROOT,
                    "Product Core owner identity could not be audited: " + messageOf(error));
            ProductCoreOwner.ProfileFact vpn = ProductCoreOwner.ProfileFact.unknown(
                    RuntimeProfile.VPN,
                    "Product Core owner identity could not be audited: " + messageOf(error));
            ownerDecision = ProductCoreOwner.decideGlobalForStart(
                    selected, root, vpn, false, ProductCoreOwner.ProcessState.UNKNOWN);
        }
        if (ownerDecision.action == ProductCoreOwner.Action.BLOCK_LIVE
                || ownerDecision.action == ProductCoreOwner.Action.BLOCK_UNKNOWN) {
            publishError(ownerDecision.errorCode, ownerDecision.detail, true,
                    ProductCoreLifecycle.UNKNOWN_PID);
            return;
        }
        if (snapshot != null && snapshot.isActive()) {
            publishError("runtime_recovered", "previous Product Core owner is not active",
                    false, ProductCoreLifecycle.UNKNOWN_PID);
            stopProductCoreResidue(false);
        }
    }

    private File profileDirectory(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        return new File(getFilesDir(), "profiles/" + selected.wireName + "/vpp");
    }

    private boolean stopRuntime() {
        return stopRuntime(true);
    }

    private boolean stopRuntime(boolean stopService) {
        if (isSupersededServiceInstance()) {
            appendLog("lifecycle_teardown=skipped_superseded_service");
            stopRequested = false;
            return false;
        }
        if (!(productCoreSession != null && productCoreSession.isConnected())
                && !processAlive(vppProcess)) {
            RuntimeProfile selected = snapshot == null || snapshot.profile == null
                    ? (activeProfile == null ? RuntimeProfile.ROOT : activeProfile)
                    : snapshot.profile;
            activeProfile = selected;
            initializeProfilePaths(selected);
            if (snapshot == null || !snapshot.isActive()) {
                boolean productProfileResidue = profileDirectory(RuntimeProfile.ROOT).exists()
                        || profileDirectory(RuntimeProfile.VPN).exists();
                if (productProfileResidue
                        || (selected == RuntimeProfile.ROOT && rootCommandAvailable())) {
                    return stopProductCoreResidue(stopService);
                }
                if (stopService && foregroundStarted
                        && !persistenceGate.isPersistenceUnavailable()) {
                    stopForeground(true);
                    foregroundStarted = false;
                }
                if (stopService && !destroying
                        && !persistenceGate.isPersistenceUnavailable()) {
                    stopSelf();
                }
                return !persistenceGate.isPersistenceUnavailable();
            }
            return stopProductCoreResidue(stopService);
        }
        if ((productCoreSession != null && productCoreSession.isConnected())
                || processAlive(vppProcess)) {
            RuntimeSnapshot current = snapshot == null
                    ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot;
            publish(RuntimeSnapshot.stopping(current));
            if (cleanupFaultInjected) {
                stopRequested = false;
                publishError("cleanup_failed", "generation-owned Product Core cleanup failed",
                        true, ProductCoreLifecycle.UNKNOWN_PID);
                return false;
            }
            RuntimeControlNative.Status closeStatus = closeProductCoreSession();
            boolean closeFailed = closeStatus != null && closeStatus.code != 0;
            boolean clean = terminateProductCoreProcess();
            boolean ownerStopped = terminateProductCoreOwnerProcess();
            clean = (activeProfile == RuntimeProfile.ROOT
                    ? ownerStopped : clean && ownerStopped) && !closeFailed;
            if (clean) {
                ProductCoreOwner.GlobalDecision postKill = auditProductCoreOwnerForStop();
                if (postKill.action == ProductCoreOwner.Action.BLOCK_LIVE
                        || postKill.action == ProductCoreOwner.Action.BLOCK_UNKNOWN) {
                    stopRequested = false;
                    publishError(postKill.errorCode, postKill.detail, true,
                            ProductCoreLifecycle.UNKNOWN_PID);
                    return false;
                }
                clean = !cleanupFaultInjected && cleanProductCoreResidue(postKill);
                if (clean) {
                    // A final global executable/profile audit is the barrier
                    // immediately before publishing STOPPED; it catches an
                    // opposite-profile owner without killing it again.
                    ProductCoreOwner.GlobalDecision finalAudit = auditProductCoreOwnerForStop();
                    if (finalAudit.action == ProductCoreOwner.Action.BLOCK_LIVE
                            || finalAudit.action == ProductCoreOwner.Action.BLOCK_UNKNOWN) {
                        stopRequested = false;
                        publishError(finalAudit.errorCode, finalAudit.detail, true,
                                ProductCoreLifecycle.UNKNOWN_PID);
                        return false;
                    }
                    clean = !cleanupFaultInjected && cleanProductCoreResidue(finalAudit);
                }
            }
            if (!clean) {
                stopRequested = false;
                String detail = closeFailed
                        ? "Product Core control disconnect or generation cleanup failed"
                        : "generation-owned profile cleanup failed";
                publishError("cleanup_failed", detail, true,
                        ProductCoreLifecycle.UNKNOWN_PID);
                return false;
            }
            productCoreSession = null;
            vppProcess = null;
            clearProfileHandles();
            boolean published = publish(RuntimeSnapshot.stopped(
                    current.profile, current.generation));
            writeS192L4MatrixStatus(null, "stopped", "", "");
            stopRequested = false;
            if (stopService && foregroundStarted) {
                stopForeground(true);
                foregroundStarted = false;
            }
            if (stopService && !destroying) {
                stopSelf();
            }
            return published;
        }
        return false;
    }

    /** Product Core STOP never falls through the retired Root/VPN cleanup path. */
    private boolean stopProductCoreResidue(boolean stopService) {
        if (isSupersededServiceInstance()) {
            appendLog("product_core_cleanup=skipped_superseded_service");
            stopRequested = false;
            return false;
        }
        initializeProfilePaths(activeProfile);
        if (!productRootNfqueueResidueClean()) {
            publishError("cleanup_failed",
                    "Root NFQUEUE hook/queue residue could not be removed", true,
                    ProductCoreLifecycle.UNKNOWN_PID);
            stopRequested = false;
            return false;
        }
        ProductCoreOwner.GlobalDecision ownerDecision = auditProductCoreOwnerForStop();
        if (ownerDecision.action == ProductCoreOwner.Action.BLOCK_LIVE) {
            if (isSupersededServiceInstance()) {
                appendLog("product_core_global_cleanup=skipped_superseded_service");
                stopRequested = false;
                return false;
            }
            if (cleanupFaultInjected || !terminateGlobalProductCoreProcessesForStop()) {
                publishError(ownerDecision.errorCode, ownerDecision.detail, true,
                        ProductCoreLifecycle.UNKNOWN_PID);
                stopRequested = false;
                return false;
            }
            ownerDecision = auditProductCoreOwnerForStop();
        }
        if (ownerDecision.action == ProductCoreOwner.Action.BLOCK_LIVE
                || ownerDecision.action == ProductCoreOwner.Action.BLOCK_UNKNOWN) {
            publishError(ownerDecision.errorCode, ownerDecision.detail, true,
                    ProductCoreLifecycle.UNKNOWN_PID);
            stopRequested = false;
            return false;
        }
        if (ownerDecision.action == ProductCoreOwner.Action.CLEAN_THEN_START) {
            if (cleanupFaultInjected) {
                publishError("cleanup_failed",
                        "generation-owned Product Core cleanup failed", true,
                        ProductCoreLifecycle.UNKNOWN_PID);
                stopRequested = false;
                return false;
            }
            if (!cleanProductCoreResidue(ownerDecision)) {
                publishError("cleanup_failed",
                        "exact Product Core owner profile cleanup failed", true,
                        ProductCoreLifecycle.UNKNOWN_PID);
                stopRequested = false;
                return false;
            }
        }
        productCoreSession = null;
        vppProcess = null;
        clearProfileHandles();
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        boolean published = publish(destroying
                ? RuntimeSnapshot.stoppedAfter(snapshot)
                : RuntimeSnapshot.stopped(selected, generation));
        writeS192L4MatrixStatus(null, "stopped", "", "");
        stopRequested = false;
        if (stopService && foregroundStarted && !persistenceGate.isPersistenceUnavailable()) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (stopService && !destroying && !persistenceGate.isPersistenceUnavailable()) {
            stopSelf();
        }
        return published && !persistenceGate.isPersistenceUnavailable();
    }

    private ProductCoreOwner.GlobalDecision auditProductCoreOwnerForStop() {
        try {
            Properties manifest = readProductManifest();
            String artifactId = requiredProductProperty(manifest, "artifactId");
            String revision = requiredProductProperty(manifest, "vppRevision");
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File vpp = new File(nativeDir, VPP_BINARY).getCanonicalFile();
            return auditProductCoreOwners(activeProfile, artifactId, revision, vpp, false);
        } catch (Exception error) {
            String detail = "Product Core owner identity could not be audited: "
                    + messageOf(error);
            return ProductCoreOwner.decideGlobalForStart(activeProfile,
                    ProductCoreOwner.ProfileFact.unknown(RuntimeProfile.ROOT, detail),
                    ProductCoreOwner.ProfileFact.unknown(RuntimeProfile.VPN, detail), false,
                    ProductCoreOwner.ProcessState.UNKNOWN);
        }
    }

    private boolean terminateGlobalProductCoreProcessesForStop() {
        if (isSupersededServiceInstance()) {
            appendLog("product_core_global_cleanup=skipped_superseded_service");
            return false;
        }
        if (cleanupFaultInjected) {
            return false;
        }
        try {
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir).getCanonicalFile();
            File vpp = new File(nativeDir, VPP_BINARY).getCanonicalFile();
            return terminateGlobalProductCoreProcess(vpp, RuntimeProfile.ROOT)
                    && terminateGlobalProductCoreProcess(vpp, RuntimeProfile.VPN);
        } catch (Exception error) {
            appendLog("product_core_global_terminate=failed " + messageOf(error));
            return false;
        }
    }

    private boolean terminateGlobalProductCoreProcess(File vpp, RuntimeProfile profile) {
        long pid = auditGlobalProductCoreProcessPid(vpp, profile);
        if (pid == ProductCoreOwner.UNKNOWN_PID) {
            ProductCoreOwner.ProcessState state = auditGlobalProductCoreProcess(vpp, profile);
            if (state == ProductCoreOwner.ProcessState.GONE) {
                return true;
            }
            appendLog("product_core_global_terminate=unknown profile=" + profile.wireName);
            return false;
        }
        appendLog("product_core_global_terminate=TERM profile=" + profile.wireName
                + " pid=" + pid);
        runPlatformCommandStatus(profile, "kill -TERM " + pid, 2L);
        if (waitGlobalProductCoreProcessGone(vpp, profile, STOP_TERM_MILLIS)) {
            return true;
        }
        long currentPid = auditGlobalProductCoreProcessPid(vpp, profile);
        if (currentPid == ProductCoreOwner.UNKNOWN_PID) {
            return waitGlobalProductCoreProcessGone(vpp, profile, STOP_KILL_MILLIS);
        }
        if (currentPid != pid) {
            appendLog("product_core_global_terminate=pid_changed profile="
                    + profile.wireName + " original=" + pid + " current=" + currentPid);
            return false;
        }
        appendLog("product_core_global_terminate=KILL profile=" + profile.wireName
                + " pid=" + currentPid);
        runPlatformCommandStatus(profile, "kill -KILL " + currentPid, 2L);
        return waitGlobalProductCoreProcessGone(vpp, profile, STOP_KILL_MILLIS);
    }

    private boolean waitGlobalProductCoreProcessGone(File vpp, RuntimeProfile profile,
                                                     long timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (true) {
            ProductCoreOwner.ProcessState state = auditGlobalProductCoreProcess(vpp, profile);
            if (state == ProductCoreOwner.ProcessState.GONE) {
                return true;
            }
            if (System.currentTimeMillis() >= deadline) {
                return false;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    private ProductCoreOwner.ProcessState auditGlobalProductCoreProcess(
            File vpp, RuntimeProfile profile) {
        try {
            RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
            String expectedUid = selected == RuntimeProfile.ROOT ? "0"
                    : Integer.toString(android.os.Process.myUid());
            RuntimeOwnershipReconciliation.CommandResult result = runProductCoreCommandResult(
                    ProductCoreOwner.buildGlobalProcessAuditCommand(vpp.getPath(), expectedUid),
                    selected);
            return ProductCoreOwner.processState(result.status, result.output);
        } catch (RuntimeException error) {
            appendLog("product_core_global_owner_audit=unknown profile="
                    + (profile == null ? "root" : profile.wireName) + " " + messageOf(error));
            return ProductCoreOwner.ProcessState.UNKNOWN;
        }
    }

    private long auditGlobalProductCoreProcessPid(File vpp, RuntimeProfile profile) {
        try {
            RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
            String expectedUid = selected == RuntimeProfile.ROOT ? "0"
                    : Integer.toString(android.os.Process.myUid());
            RuntimeOwnershipReconciliation.CommandResult result = runProductCoreCommandResult(
                    ProductCoreOwner.buildGlobalProcessAuditCommand(vpp.getPath(), expectedUid),
                    selected);
            return ProductCoreOwner.processPid(result.status, result.output);
        } catch (RuntimeException error) {
            appendLog("product_core_global_owner_pid_audit=unknown profile="
                    + (profile == null ? "root" : profile.wireName) + " " + messageOf(error));
            return ProductCoreOwner.UNKNOWN_PID;
        }
    }

    private void pauseProtection() {
        RuntimeProfile pausedProfile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        boolean stopped = stopRuntime(false);
        if (!stopped && persistenceGate.isPersistenceUnavailable()) {
            return;
        }
        stopRequested = true;
        publish(RuntimeSnapshot.paused(pausedProfile, generation));
        if (foregroundStarted && !persistenceGate.isPersistenceUnavailable()) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying && !persistenceGate.isPersistenceUnavailable()) {
            stopSelf();
        }
    }

    private int runPlatformCommandStatus(RuntimeProfile selected, String command,
                                         long timeoutSeconds) {
        RuntimeProfile profileType = selected == null ? RuntimeProfile.ROOT : selected;
        return profileType == RuntimeProfile.ROOT
                ? runRootCommandStatus(command, timeoutSeconds)
                : runAppCommandStatus(command, timeoutSeconds);
    }

    private void failWithoutRuntime(String code, String message) {
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void failSelectedProfileWithoutRuntime(String code, String message) {
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        publish(RuntimeSnapshot.error(selected, VppHealthHandshake.PROTOCOL, "", "", "",
                code, message, false, -1L, generation));
        stopIfInactive();
    }

    private VpnTunPlatformSession establishPacketAdapterSession(
            ProductPacketAdapterContract adapter) {
        if (adapter == null || !adapter.requiresVpnPlatformSession) {
            return null;
        }
        if (VpnService.prepare(this) != null) {
            failSelectedProfileWithoutRuntime("vpn_authorization_required",
                    "VpnService authorization is required before establishing the TUN");
            return null;
        }
        if (vpnFaultModeIs("establish_null")) {
            failSelectedProfileWithoutRuntime("vpn_establish_returned_null",
                    "S185 fault mode simulated VpnService.Builder.establish returning null");
            return null;
        }
        VpnTunPlatformSession.EstablishResult result =
                VpnTunPlatformSession.establish(this, adapter.enableIpv6);
        if (!result.ok) {
            failSelectedProfileWithoutRuntime(result.errorCode, result.errorMessage);
            return null;
        }
        return result.session;
    }

    private boolean attachVpnTunSessionAfterHealth(RuntimeProfile profile,
                                                   VpnTunPlatformSession session) {
        if (profile != RuntimeProfile.VPN) {
            return true;
        }
        if (session == null || !session.isOpen()) {
            appendLog("vpn_tun_control_attach=missing_session");
            return false;
        }
        RuntimeControlFdClient.AttachResult readiness =
                RuntimeControlFdClient.waitForVpnTunHandoffReady();
        if (!readiness.ok) {
            appendLog("vpn_tun_control_ready=failed code=" + readiness.errorCode
                    + " message=" + readiness.errorMessage);
            return false;
        }
        appendLog("vpn_tun_control_ready=ok");
        int rawFd = session.releaseFd();
        VpnPolicyHints policyHints = currentVpnPolicyHints();
        RuntimeControlFdClient.AttachResult result =
                RuntimeControlFdClient.attachVpnTun(rawFd, session.ipv6Enabled,
                        policyHints.subjectUid, policyHints.networkContext);
        if (!result.ok) {
            appendLog("vpn_tun_control_attach=failed code=" + result.errorCode
                    + " message=" + result.errorMessage);
            return false;
        }
        if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(result.adapter)
                || !result.fdAttached || result.ipv6Enabled != session.ipv6Enabled) {
            appendLog("vpn_tun_control_attach=invalid_result adapter=" + result.adapter
                    + " fdAttached=" + result.fdAttached
                    + " ipv6Enabled=" + result.ipv6Enabled);
            return false;
        }
        appendLog("vpn_tun_control_attach=ok adapter=" + result.adapter
                + " ipv6Enabled=" + result.ipv6Enabled
                + " policySubjectUid=" + policyHints.subjectUid
                + " networkContext=" + policyHints.networkContext);
        return true;
    }

    private VpnPolicyHints currentVpnPolicyHints() {
        if (productBackend == null) {
            return VpnPolicyHints.none();
        }
        ProductStateSnapshot state = productBackend.productState();
        if (state == null || state.authoringPolicyBundle == null) {
            return VpnPolicyHints.none();
        }
        for (AuthoringPolicyBundle.NetworkGateRule rule
                : state.authoringPolicyBundle.gateMatrix) {
            if (rule.networkContext == AuthoringPolicyBundle.NetworkContextId.VPN) {
                return new VpnPolicyHints(rule.subjectId.uid,
                        rule.networkContext.wireId);
            }
        }
        // A complete L4 bundle is also authoritative for the TUN handoff
        // when no VPN Gate exists. Prefer an explicitly VPN-scoped rule, then
        // retain the bundle's first deterministic UID/context for policies
        // intentionally evaluated in wifi or mobile context on VPN traffic.
        for (AuthoringPolicyBundle.L4Rule rule : state.authoringPolicyBundle.l4Rules) {
            if (rule.networkContext == AuthoringPolicyBundle.NetworkContextId.VPN) {
                return new VpnPolicyHints(rule.subjectId.uid,
                        rule.networkContext.wireId);
            }
        }
        if (!state.authoringPolicyBundle.l4Rules.isEmpty()) {
            AuthoringPolicyBundle.L4Rule rule = state.authoringPolicyBundle.l4Rules.get(0);
            if (rule.networkContext != null) {
                return new VpnPolicyHints(rule.subjectId.uid,
                        rule.networkContext.wireId);
            }
        }
        return VpnPolicyHints.none();
    }

    private static final class VpnPolicyHints {
        final int subjectUid;
        final int networkContext;

        private VpnPolicyHints(int subjectUid, int networkContext) {
            this.subjectUid = subjectUid;
            this.networkContext = networkContext;
        }

        static VpnPolicyHints none() {
            return new VpnPolicyHints(-1, 0);
        }
    }

    private boolean attachVpnTunSessionForProductCore(VpnTunPlatformSession session) {
        if (activeProfile != RuntimeProfile.VPN) {
            return true;
        }
        return attachVpnTunSessionAfterHealth(RuntimeProfile.VPN, session);
    }

    private RuntimeControlNative.Status waitForVpnAdapterReadyAfterHandoff(
            RuntimeControlNative.Session session, ProductPacketAdapterContract adapter)
            throws InterruptedException {
        productCoreConnectFailureCode = "";
        productCoreConnectFailureMessage = "";
        if (session == null || !session.isConnected()) {
            productCoreConnectFailureCode = "product_core_session_missing";
            productCoreConnectFailureMessage =
                    "Product Core session is unavailable after VPN fd handoff";
            return null;
        }
        for (int attempt = 0; attempt < HEALTH_ATTEMPTS; ++attempt) {
            if (stopRequested || !processAlive(vppProcess)) {
                productCoreConnectFailureCode = "product_core_not_ready";
                productCoreConnectFailureMessage =
                        "Product Core stopped while waiting for VPN adapter readiness";
                return null;
            }
            RuntimeControlNative.Status status = session.query();
            String validation;
            if (status != null && status.code != 0) {
                validation = ProductCoreLifecycle.failureCode(status);
            } else {
                validation = ProductCoreLifecycle.validate(generation, productArtifactId,
                        productApiIdentity, productVppRevision, productAbiVersion,
                        productApiVersion, status, adapter.adapterReadyAfterHandoff);
            }
            if (validation.isEmpty()) {
                return status;
            }
            if (!ProductCoreLifecycle.isRetryableConnectionFailure(validation)) {
                productCoreConnectFailureCode = validation;
                productCoreConnectFailureMessage = status == null
                        ? validation : status.errorDetail;
                return null;
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
        }
        productCoreConnectFailureCode = "product_core_not_ready";
        productCoreConnectFailureMessage =
                "VPN ProductCore adapter readiness did not converge after fd handoff";
        return null;
    }

    private boolean startVpnHevTransportAfterTun(RuntimeProfile profile, File nativeDir,
                                                 File currentProfile) {
        if (profile != RuntimeProfile.VPN) {
            return true;
        }
        VpnHevTransportSession.StartResult result =
                VpnHevTransportSession.start(this, nativeDir.getPath(),
                        new File(currentProfile, "logs"));
        if (!result.ok) {
            appendLog("vpn_hev_transport=failed code=" + result.errorCode
                    + " message=" + result.errorMessage);
            return false;
        }
        vpnHevSession = result.session;
        appendLog("vpn_hev_transport=ok name=" + VpnHevTransportSession.TRANSPORT_NAME
                + " socksPort=" + VpnHevTransportSession.DEFAULT_SOCKS_PORT);
        return true;
    }

    private void closeVpnTunSessionAfterNativeHandoff() {
        VpnTunPlatformSession session = vpnTunSession;
        vpnTunSession = null;
        closeVpnTunSessionQuietly(session);
    }

    private void closeVpnTunSessionQuietly(VpnTunPlatformSession session) {
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (IOException error) {
            appendLog("vpn_tun_cleanup_failed=" + messageOf(error));
        }
    }

    private void closeVpnHevSessionQuietly() {
        VpnHevTransportSession session = vpnHevSession;
        vpnHevSession = null;
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (RuntimeException error) {
            appendLog("vpn_hev_cleanup_failed=" + messageOf(error));
        }
    }

    private void closeVpnDirectUdp4SessionQuietly() {
        VpnDirectUdp4TransportSession session = vpnDirectUdp4Session;
        vpnDirectUdp4Session = null;
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (RuntimeException error) {
            appendLog("vpn_direct_udp4_cleanup_failed=" + messageOf(error));
        }
    }

    private void closeVpnDirectUdp6SessionQuietly() {
        VpnDirectUdp6TransportSession session = vpnDirectUdp6Session;
        vpnDirectUdp6Session = null;
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (RuntimeException error) {
            appendLog("vpn_direct_udp6_cleanup_failed=" + messageOf(error));
        }
    }

    private void closeVpnDirectTcp4SessionQuietly() {
        VpnDirectTcp4TransportSession session = vpnDirectTcp4Session;
        vpnDirectTcp4Session = null;
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (RuntimeException error) {
            appendLog("vpn_direct_tcp4_cleanup_failed=" + messageOf(error));
        }
    }

    private void closeVpnDirectTcp6SessionQuietly() {
        VpnDirectTcp6TransportSession session = vpnDirectTcp6Session;
        vpnDirectTcp6Session = null;
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (RuntimeException error) {
            appendLog("vpn_direct_tcp6_cleanup_failed=" + messageOf(error));
        }
    }

    private void resetVpnDirectUnderlaySnapshot() {
        vpnDirectUnderlayEpoch = -1L;
        vpnDirectUnderlayTransport = "";
        vpnDirectUnderlayNetworkHandle = -1L;
        vpnDirectUdp4NetworkHandle = -1L;
        vpnDirectUdp6NetworkHandle = -1L;
        vpnDirectTcp4NetworkHandle = -1L;
        vpnDirectTcp6NetworkHandle = -1L;
    }

    private void publishError(String code, String message, boolean mayBeActive, long pid) {
        RuntimeSnapshot current = snapshot == null
                ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot;
        publish(RuntimeSnapshot.error(current.profile, current.protocol, current.version,
                current.artifact, current.abi, code, message, mayBeActive, pid,
                current.generation));
    }

    private void publishHealthError(VppHealthHandshake.Result health, String message,
                                    boolean mayBeActive, long pid) {
        RuntimeSnapshot current = snapshot == null
                ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot;
        String version = health == null || health.version.isEmpty()
                ? current.version : health.version;
        String code = health == null || health.errorCode.isEmpty()
                ? "health_handshake_failed" : health.errorCode;
        publish(RuntimeSnapshot.error(current.profile, current.protocol, version, current.artifact,
                current.abi, code, message, mayBeActive, pid, current.generation));
    }

    private boolean publish(RuntimeSnapshot next) {
        synchronized (stateLock) {
            RuntimeStateStore.PersistenceGate.Result result = persistenceGate.publish(
                    getFilesDir(), next, processAlive(vppProcess));
            snapshot = result.snapshot;
            if (!result.persisted) {
                exposePersistenceFailure(result, "publish");
                return false;
            }
            if (!result.launchAllowed) {
                exposePersistenceFailure(result, "launch_blocked");
                return false;
            }
            if (foregroundStarted) {
                NotificationManager manager = getSystemService(NotificationManager.class);
                if (manager != null) {
                    manager.notify(NOTIFICATION_ID, buildNotification(next));
                }
            }
            if (next.profile == RuntimeProfile.VPN
                    && RuntimeSnapshot.STATE_ERROR.equals(next.state)) {
                writeS185VpnFaultRecoveryErrorStatus(next);
            }
            writeS186ProfileSwitchBarrierStatus(next);
        }
        appendLog("runtime_state=" + next.state + " profile=" + next.profile.wireName
                + " health=" + next.health + (next.errorCode.isEmpty() ? ""
                : " error=" + next.errorCode));
        return true;
    }

    private boolean persistSelectedProductProfile(RuntimeProfile profile) {
        if (productBackend == null) {
            return true;
        }
        ProductStore.MutationResult result = productBackend.selectRuntimeProfile(profile);
        if (result.persisted) {
            appendLog("product_state=profile_selected profile=" + profile.wireName);
            return true;
        }
        publishError(result.errorCode.isEmpty() ? "product_state_persistence_failed"
                        : result.errorCode,
                result.errorMessage.isEmpty()
                        ? "selected runtime profile could not be persisted"
                        : result.errorMessage,
                currentMayBeActive(), currentPid());
        return false;
    }

    private void selectProductProfile(RuntimeProfile profile) {
        if (persistSelectedProductProfile(profile)) {
            appendLog("product_control=profile_select profile=" + profile.wireName);
        }
        refreshProductCatalogProjection("profile_select");
        stopIfInactive();
    }

    private void bindProductApplication(ApplicationSubjectId subjectId) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result = productBackend.bindApplication(subjectId);
        if (result.persisted) {
            appendLog("product_control=bind_app subject=" + subjectId.encode());
        } else {
            publishProductMutationFailure("product_bind_failed", result,
                    "application binding could not be persisted");
        }
        refreshProductCatalogProjection("bind_app");
        stopIfInactive();
    }

    private void unbindProductApplication(ApplicationSubjectId subjectId) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result = productBackend.unbindApplication(subjectId);
        if (result.persisted) {
            appendLog("product_control=unbind_app subject=" + subjectId.encode());
        } else {
            publishProductMutationFailure("product_unbind_failed", result,
                    "application unbinding could not be persisted");
        }
        refreshProductCatalogProjection("unbind_app");
        stopIfInactive();
    }

    private void setProductNetworkGate(ApplicationSubjectId subjectId,
                                       AuthoringPolicyBundle.NetworkContextId context,
                                       boolean blocked) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result =
                productBackend.setNetworkGate(subjectId, context, blocked);
        if (result.persisted) {
            appendLog("product_control=network_gate subject=" + subjectId.encode()
                    + " context=" + context.wireName
                    + " blocked=" + blocked);
        } else {
            publishProductMutationFailure("product_network_gate_failed", result,
                    "Network Gate mutation could not be applied");
        }
        refreshProductCatalogProjection("network_gate");
        refreshProductActivityProjection("network_gate", subjectId);
        stopIfInactive();
    }

    private void setProductL4Rule(AuthoringPolicyBundle.L4Rule rule) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result = productBackend.setL4Rule(rule);
        if (result.persisted) {
            appendLog("product_control=l4_rule subject=" + rule.subjectId.encode()
                    + " family=" + rule.family.wireName
                    + " direction=" + rule.direction.wireName
                    + " ipProtocol=" + rule.ipProtocol
                    + " action=" + rule.action.wireName
                    + " ruleId=" + Long.toUnsignedString(rule.ruleId));
        } else {
            publishProductMutationFailure("product_l4_rule_failed", result,
                    "L4 rule mutation could not be applied");
        }
        refreshProductCatalogProjection("l4_rule");
        refreshProductActivityProjection("l4_rule", rule.subjectId);
        stopIfInactive();
    }

    private void refreshProductCatalogProjection(String reason) {
        if (productBackend == null) {
            return;
        }
        ProductCatalogFormatter.Projection projection =
                productBackend.refreshProductCatalogProjection();
        appendLog("product_catalog_projection=" + projection.catalogStatus
                + " reason=" + reason
                + " entries=" + projection.catalogEntryCount
                + (projection.errorCode.isEmpty() ? "" : " error=" + projection.errorCode)
                + ("valid".equals(projection.productStateStatus)
                        || "missing".equals(projection.productStateStatus) ? ""
                        : " product_state=" + projection.productStateStatus
                                + " product_error=" + projection.productStateErrorCode));
    }

    private void refreshProductActivityProjection(String reason,
                                                  ApplicationSubjectId preferredSubject) {
        if (productBackend == null) {
            return;
        }
        ingestLatestNativeActivity(reason);
        ApplicationSubjectId subject = preferredSubject;
        if (subject == null) {
            ProductStateSnapshot state = productBackend.productState();
            subject = state.boundApplications.isEmpty()
                    ? null : state.boundApplications.iterator().next();
        }
        RuntimeSummary runtime = RuntimeSummary.fromSnapshot(
                snapshot == null ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot,
                CapabilitySet.androidL4(true, true));
        AppDetail detail = productBackend.refreshProductActivityProjection(subject, runtime, 32);
        appendLog("product_activity_projection=published reason=" + reason
                + " subject=" + (subject == null ? "(none)" : subject.encode())
                + " activity=" + detail.activity.size()
                + " rules=" + detail.rules.size()
                + " state=" + detail.state);
    }

    private void ingestLatestNativeActivity(String reason) {
        RuntimeSnapshot current = snapshot;
        if (current == null || !current.isActive()) {
            return;
        }
        RuntimeProfile profile = current.profile == null ? RuntimeProfile.ROOT : current.profile;
        RuntimeControlFdClient.AttachResult status = RuntimeControlFdClient.callJson(58,
                profile == RuntimeProfile.VPN ? "VPN_TUN.STATUS" : "NFQUEUE.STATUS",
                new JSONObject());
        if (!status.ok) {
            appendLog("product_activity_native_status=unavailable reason=" + reason
                    + " profile=" + profile.wireName
                    + " code=" + status.errorCode);
            return;
        }
        JSONObject activity = status.result.optJSONObject("policyDropActivity");
        ProductNativeActivityIngestor.NativePolicyDropRecord record =
                nativePolicyDropRecord(activity);
        if (!ProductNativeActivityIngestor.shouldIngest(record, profile,
                lastNativePolicyDropActivityProfile, lastNativePolicyDropActivityGeneration,
                current.generation, lastNativePolicyDropActivityTotalRecords)) {
            record = null;
        }
        ActivityItem item = ProductNativeActivityIngestor.toActivityItem(record, profile,
                System.currentTimeMillis());
        if (item != null) {
            productBackend.ingestActivity(item);
            lastNativePolicyDropActivityProfile = profile;
            lastNativePolicyDropActivityGeneration = current.generation;
            lastNativePolicyDropActivityTotalRecords = record.totalRecords;
            appendLog("product_activity_native_ingest=ok reason=" + reason
                    + " profile=" + profile.wireName
                    + " kind=policy_drop"
                    + " totalRecords=" + record.totalRecords
                    + " subject=" + item.subjectId.encode()
                    + " winner=" + item.winner
                    + " revision=" + item.policyRevision);
        }

        JSONObject allowedActivity = status.result.optJSONObject("allowedFlowActivity");
        ProductNativeActivityIngestor.NativeAllowedFlowRecord allowedRecord =
                nativeAllowedFlowRecord(allowedActivity);
        if (!ProductNativeActivityIngestor.shouldIngest(allowedRecord, profile,
                lastNativeAllowedFlowActivityProfile, lastNativeAllowedFlowActivityGeneration,
                current.generation, lastNativeAllowedFlowActivityTotalRecords)) {
            return;
        }
        ActivityItem allowed = ProductNativeActivityIngestor.toActivityItem(
                allowedRecord, profile, System.currentTimeMillis());
        if (allowed == null) {
            return;
        }
        productBackend.ingestActivity(allowed);
        lastNativeAllowedFlowActivityProfile = profile;
        lastNativeAllowedFlowActivityGeneration = current.generation;
        lastNativeAllowedFlowActivityTotalRecords = allowedRecord.totalRecords;
        appendLog("product_activity_native_ingest=ok reason=" + reason
                + " profile=" + profile.wireName
                + " kind=allowed_flow"
                + " totalRecords=" + allowedRecord.totalRecords
                + " subject=" + allowed.subjectId.encode()
                + " remote=" + allowed.remoteIp + ":" + allowed.remotePort
                + " revision=" + allowed.policyRevision);
    }

    private static ProductNativeActivityIngestor.NativePolicyDropRecord nativePolicyDropRecord(
            JSONObject activity) {
        if (activity == null) {
            return null;
        }
        return new ProductNativeActivityIngestor.NativePolicyDropRecord(
                activity.optLong("totalRecords", 0L),
                activity.optBoolean("hasLastRecord", false),
                (int) activity.optLong("lastLinuxUid", 0L),
                activity.optBoolean("lastUidKnown", false),
                (int) activity.optLong("lastNetworkContext", 0L),
                activity.optString("lastSourceAddress", ""),
                activity.optString("lastDestinationAddress", ""),
                (int) activity.optLong("lastIpProtocol", 0L),
                (int) activity.optLong("lastSourcePort", 0L),
                (int) activity.optLong("lastDestinationPort", 0L),
                activity.optBoolean("lastPortsAvailable", false),
                activity.optString("lastDeviceDirection", ""),
                activity.optString("lastStage", ""),
                (int) activity.optLong("lastReasonId", 0L),
                activity.optLong("lastRuleId", 0L),
                activity.optLong("lastRevision", 0L));
    }

    private static ProductNativeActivityIngestor.NativeAllowedFlowRecord nativeAllowedFlowRecord(
            JSONObject activity) {
        if (activity == null) {
            return null;
        }
        return new ProductNativeActivityIngestor.NativeAllowedFlowRecord(
                activity.optLong("totalRecords", 0L),
                activity.optBoolean("hasLastRecord", false),
                (int) activity.optLong("lastLinuxUid", 0L),
                activity.optBoolean("lastUidKnown", false),
                (int) activity.optLong("lastNetworkContext", 0L),
                activity.optString("lastSourceAddress", ""),
                activity.optString("lastDestinationAddress", ""),
                (int) activity.optLong("lastIpProtocol", 0L),
                (int) activity.optLong("lastSourcePort", 0L),
                (int) activity.optLong("lastDestinationPort", 0L),
                activity.optBoolean("lastPortsAvailable", false),
                activity.optString("lastDeviceDirection", ""),
                activity.optString("lastFlowDirection", ""),
                activity.optLong("lastPolicyRevision", 0L),
                activity.optLong("lastPackets", 0L),
                activity.optLong("lastBytes", 0L),
                activity.optString("lastProtocolRecognitionState", ""),
                activity.optString("lastApplicationProtocolKey", ""),
                activity.optString("lastApplicationProtocolCategory", ""),
                activity.optString("lastProtocolRecognitionSequence", ""),
                (int) activity.optLong("lastProtocolPayloadPackets", 0L));
    }

    private void publishProductMutationFailure(String fallbackCode,
                                               ProductStore.MutationResult result,
                                               String fallbackMessage) {
        publishError(result == null || result.errorCode.isEmpty()
                        ? fallbackCode : result.errorCode,
                result == null || result.errorMessage.isEmpty()
                        ? fallbackMessage : result.errorMessage,
                currentMayBeActive(), currentPid());
    }

    /**
     * Keep a bounded local error projection when the durable write itself is
     * unavailable. This deliberately does not call publish again: doing so
     * would recurse through the same failing writer and hide the original
     * lifecycle transition. The latch is cleared only by the explicit
     * ownership-audited recovery probe above.
     */
    private void exposePersistenceFailure(RuntimeStateStore.PersistenceGate.Result result,
                                          String phase) {
        synchronized (stateLock) {
            RuntimeSnapshot local = result == null || result.snapshot == null
                    ? (snapshot == null
                            ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot)
                    : result.snapshot;
            snapshot = local;
            Log.e(TAG, "failed to persist runtime state: "
                    + (result == null ? "missing persistence result" : result.detail));
            if (foregroundStarted) {
                NotificationManager manager = getSystemService(NotificationManager.class);
                if (manager != null) {
                    manager.notify(NOTIFICATION_ID, buildNotification(local));
                }
            }
            appendLog("runtime_state_persistence=unavailable phase=" + phase
                    + " state=" + local.state + " mayBeActive=" + local.mayBeActive
                    + (local.pid > 0L ? " pid=" + local.pid : ""));
        }
    }

    private Notification buildNotification(RuntimeSnapshot value) {
        String text = "Protection " + value.state;
        if (!value.errorCode.isEmpty()) {
            text += ": " + value.errorCode;
        }
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID) : new Notification.Builder(this);
        return builder.setContentTitle("Sakamoto protection").setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(value.isActive()).setCategory(Notification.CATEGORY_SERVICE).build();
    }

    private void stopIfInactive() {
        stopIfInactive(latestStartId);
    }

    private void stopIfInactive(int startId) {
        if (persistenceGate.isPersistenceUnavailable()) {
            appendLog("runtime_state_persistence=service_retained pending_recovery");
            return;
        }
        if (snapshot != null && snapshot.mayBeActive) {
            return;
        }
        if (startId <= 0) {
            // onCreate's durable reconciliation has no startId. Do not stop
            // the service here: a START intent may be queued immediately
            // afterward and must not race an onDestroy/stopRequested flag.
            return;
        }
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying) {
            stopSelf(startId);
        }
    }

    private void setCleanupFault(boolean enabled) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            appendLog("ignored cleanup fault seam in non-debug build");
            return;
        }
        cleanupFaultInjected = enabled;
        appendLog("debug cleanup fault=" + enabled);
    }

    private void setRootNfqueueFaultMode(String mode) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            appendLog("ignored Root NFQUEUE fault seam in non-debug build");
            return;
        }
        String normalized = normalizeRootNfqueueFaultMode(mode);
        rootNfqueueFaultMode = normalized;
        appendLog("debug root nfqueue fault mode=" + normalized);
    }

    private void setVpnFaultMode(String mode) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            appendLog("ignored VPN fault seam in non-debug build");
            return;
        }
        String normalized = normalizeVpnFaultMode(mode);
        vpnFaultMode = normalized;
        appendLog("debug vpn fault mode=" + normalized);
    }

    private void setPolicyMutationFaultMode(String mode) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            appendLog("ignored Product policy mutation fault seam in non-debug build");
            return;
        }
        String requested = mode == null ? "" : mode.trim();
        String normalized = normalizePolicyMutationFaultMode(requested);
        if (!requested.isEmpty() && !"none".equals(requested) && normalized.isEmpty()) {
            appendLog("ignored Product policy mutation fault mode=" + requested);
            writeS194PolicyMutationFaultStatus(requested, false, null,
                    "unsupported debug policy mutation fault mode");
            return;
        }
        RuntimeControlNative.Session session = productCoreSession;
        if (session == null || session.generation() != generation || !session.isConnected()) {
            appendLog("Product policy mutation fault has no active session mode=" + normalized);
            writeS194PolicyMutationFaultStatus(normalized, false, null,
                    "Product Core session is unavailable for fault arming");
            return;
        }
        RuntimeControlNative.Status status = session.setPolicyMutationFaultMode(normalized);
        boolean armed = !normalized.isEmpty() && status != null && status.code == 0;
        String error = status == null || status.code == 0 ? ""
                : ProductCoreLifecycle.failureCode(status);
        writeS194PolicyMutationFaultStatus(normalized, armed, status, error);
        appendLog("debug Product policy mutation fault mode=" + normalized
                + " armed=" + armed + " code=" + (status == null ? -1 : status.code)
                + " generation=" + generation);
    }

    private boolean vpnFaultModeIs(String mode) {
        return mode != null && mode.equals(vpnFaultMode);
    }

    private void handleVpnFaultEvent(String event) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            appendLog("ignored VPN fault event seam in non-debug build");
            return;
        }
        String normalized = normalizeVpnFaultEvent(event);
        if (normalized.isEmpty()) {
            appendLog("ignored VPN fault event=" + event);
            return;
        }
        if (snapshot != null
                && RuntimeSnapshot.STATE_ERROR.equals(snapshot.state)
                && !snapshot.mayBeActive) {
            appendLog("ignored VPN fault event=" + normalized
                    + " after terminal error=" + snapshot.errorCode);
            return;
        }
        if ("revoke".equals(normalized)) {
            handleVpnAuthorizationRevoked("debug");
            return;
        }
        if (activeProfile != RuntimeProfile.VPN) {
            appendLog("ignored stale VPN fault event=" + normalized
                    + " activeProfile="
                    + (activeProfile == null ? "none" : activeProfile.wireName));
            return;
        }
        if ("close_tun".equals(normalized)) {
            RuntimeControlFdClient.AttachResult result = RuntimeControlFdClient.callJson(
                    185, RuntimeControlFdClient.VPN_FAULT_CLOSE_TUN, new JSONObject());
            writeS185VpnFaultEventStatus("tun_abnormal_close", result);
            if (!result.ok) {
                publishError(result.errorCode.isEmpty()
                                ? "vpn_tun_abnormal_close_failed" : result.errorCode,
                        result.errorMessage.isEmpty()
                                ? "VPN TUN fd abnormal-close fault did not reach Product Core"
                                : result.errorMessage,
                        currentMayBeActive(), ProductCoreLifecycle.UNKNOWN_PID);
                return;
            }
            failProductCoreGeneration("vpn_tun_abnormal_close",
                    "VPN TUN fd was closed by the S185 fault event");
            return;
        }
        if ("native_crash".equals(normalized)) {
            Process process = vppProcess;
            boolean crashIssued = false;
            if (process != null && process.isAlive()) {
                appendLog("debug vpn native crash fault=process_destroy_forcibly");
                process.destroyForcibly();
                crashIssued = true;
            } else {
                crashIssued = crashProductCoreOwnerProcess();
            }
            if (crashIssued || (snapshot != null && snapshot.isActive())) {
                failProductCoreGeneration("unexpected_exit",
                        "VPN Product Core process was destroyed by the S185 native crash fault");
            } else {
                publishError("vpn_native_process_not_running",
                        "VPN Product Core process is unavailable for native crash fault",
                        currentMayBeActive(), ProductCoreLifecycle.UNKNOWN_PID);
            }
            return;
        }
    }

    private static String normalizeRootNfqueueFaultMode(String mode) {
        String value = mode == null ? "" : mode.trim();
        if (value.isEmpty() || "none".equals(value)) {
            return "";
        }
        switch (value) {
            case "missing_identity":
            case "graph_submit_fail_open":
            case "verdict_failed_definite":
            case "verdict_outcome_unknown":
            case "duplicate_completion":
            case "stale_completion":
                return value;
            default:
                return "";
        }
    }

    private static String normalizeVpnFaultMode(String mode) {
        String value = mode == null ? "" : mode.trim();
        if (value.isEmpty() || "none".equals(value)) {
            return "";
        }
        switch (value) {
            case "establish_null":
            case "protect_false":
            case "bind_failed":
                return value;
            default:
                return "";
        }
    }

    private static String normalizePolicyMutationFaultMode(String mode) {
        String value = mode == null ? "" : mode.trim();
        if (value.isEmpty() || "none".equals(value)) {
            return "";
        }
        if ("bundle_callback_omission".equals(value)
                || "bundle_pre_submit_not_sent".equals(value)) {
            return value;
        }
        return "";
    }

    private static String normalizeVpnFaultEvent(String event) {
        String value = event == null ? "" : event.trim();
        switch (value) {
            case "close_tun":
            case "revoke":
            case "native_crash":
                return value;
            default:
                return "";
        }
    }

    private String productRootNfqueueFaultExport() {
        String mode = rootNfqueueFaultMode;
        if (mode == null || mode.isEmpty()) {
            return "";
        }
        return "; export SAKAMOTO_PRODUCT_ROOT_NFQUEUE_FAULT_MODE="
                + shellQuote(mode);
    }

    private void initializeProfilePaths(RuntimeProfile profile) {
        if (profile == null) {
            profile = RuntimeProfile.ROOT;
        }
        File expectedRoot = new File(getFilesDir(), "profiles/" + profile.wireName + "/vpp");
        if (activeProfile != profile || profileRoot == null
                || !expectedRoot.equals(profileRoot)) {
            activeProfile = profile;
            profileRoot = expectedRoot;
            pidFile = new File(profileRoot, "runtime/vpp.pid");
        }
    }

    private void ensureOwnerToken(File runtime) throws IOException {
        File token = new File(runtime, "owner.token");
        if (token.isFile() && !readOwnerToken().isEmpty()) {
            return;
        }
        String value = UUID.randomUUID().toString();
        try (FileOutputStream output = new FileOutputStream(token)) {
            output.write((value + "\n").getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        }
    }

    private String readOwnerToken() {
        initializeProfilePaths(activeProfile);
        return readOwnerToken(profileRoot);
    }

    private String readOwnerToken(File profile) {
        File token = new File(new File(profile, "runtime"), "owner.token");
        try (FileInputStream input = new FileInputStream(token)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[64];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    bytes.write(buffer, 0, count);
                }
            }
            String value = bytes.toString(StandardCharsets.US_ASCII.name()).trim();
            return value.matches("[0-9a-fA-F-]{36}") ? value : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private void clearProfileHandles() {
        closeVpnDirectTcp4SessionQuietly();
        closeVpnDirectTcp6SessionQuietly();
        closeVpnDirectUdp6SessionQuietly();
        closeVpnDirectUdp4SessionQuietly();
        closeVpnHevSessionQuietly();
        closeVpnTunSessionAfterNativeHandoff();
        resetVpnDirectUnderlaySnapshot();
        profileRoot = null;
        pidFile = null;
    }

    private static final class VpnDirectUdp4TransportSession implements AutoCloseable {
        static final String TRANSPORT_NAME = "direct-udp4-protected-socket";

        private final RuntimeService service;
        private final long networkHandle;
        private boolean closed;

        private VpnDirectUdp4TransportSession(RuntimeService service, long networkHandle) {
            this.service = service;
            this.networkHandle = networkHandle;
        }

        static StartResult start(RuntimeService service) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct UDP4 protect");
            }
            UnderlayNetwork underlay = UnderlayNetwork.select(service);
            return start(service, underlay);
        }

        static StartResult start(RuntimeService service, UnderlayNetwork underlay) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct UDP4 protect");
            }
            if (underlay == null) {
                return StartResult.error("vpn_underlay_unavailable",
                        "No underlay Network snapshot is available for Direct UDP4");
            }
            if (!underlay.available) {
                return StartResult.error(underlay.errorCode, underlay.errorMessage);
            }

            DatagramSocket socket = null;
            ParcelFileDescriptor descriptor = null;
            int rawFd = -1;
            try {
                socket = new DatagramSocket(null);
                socket.setReuseAddress(true);
                if (service.vpnFaultModeIs("protect_false")) {
                    return StartResult.error("vpn_direct_udp4_protect_failed",
                            "S185 fault mode simulated VpnService.protect false for Direct UDP4");
                }
                if (!service.protect(socket)) {
                    return StartResult.error("vpn_direct_udp4_protect_failed",
                            "VpnService.protect returned false for Direct UDP4 socket");
                }
                if (service.vpnFaultModeIs("bind_failed")) {
                    return StartResult.error("vpn_direct_udp4_bind_failed",
                            "S185 fault mode simulated Network.bindSocket failure for Direct UDP4");
                }
                underlay.network.bindSocket(socket);
                socket.bind(new InetSocketAddress(0));
                service.setUnderlyingNetworks(new Network[]{underlay.network});

                // Keep the documented ParcelFileDescriptor.fromDatagramSocket(socket).dup()
                // pattern explicit: Android returns a dup on modern devices, and the dup
                // is the descriptor transferred to the ProductCore VPP process.
                ParcelFileDescriptor sourceDescriptor =
                        ParcelFileDescriptor.fromDatagramSocket(socket);
                try {
                    descriptor = sourceDescriptor.dup();
                } finally {
                    sourceDescriptor.close();
                }
                rawFd = descriptor.detachFd();
                RuntimeControlFdClient.AttachResult attach =
                        RuntimeControlFdClient.attachVpnTransport(rawFd);
                rawFd = -1;
                if (!attach.ok) {
                    return StartResult.error(attach.errorCode.isEmpty()
                                    ? "vpn_direct_udp4_attach_failed" : attach.errorCode,
                            attach.errorMessage.isEmpty()
                                    ? "Direct UDP4 fd attach failed" : attach.errorMessage);
                }
                if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(attach.adapter)
                        || !attach.transportFdAttached) {
                    return StartResult.error("vpn_direct_udp4_attach_invalid_result",
                            "Direct UDP4 attach did not prove the ProductCore handoff");
                }
                socket.close();
                socket = null;
                return StartResult.ready(new VpnDirectUdp4TransportSession(
                        service, underlay.networkHandle));
            } catch (Exception error) {
                return StartResult.error("vpn_direct_udp4_start_failed", messageOf(error));
            } finally {
                if (rawFd >= 0) {
                    closeRawFdQuietly(rawFd);
                }
                if (descriptor != null) {
                    try {
                        descriptor.close();
                    } catch (IOException ignored) {
                        // The attach result already records the actionable failure.
                    }
                }
                if (socket != null) {
                    socket.close();
                }
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            service.setUnderlyingNetworks(null);
        }

        private static void closeRawFdQuietly(int rawFd) {
            try {
                ParcelFileDescriptor.adoptFd(rawFd).close();
            } catch (IOException ignored) {
                // Best-effort cleanup of a not-yet-transferred descriptor.
            }
        }

        static final class StartResult {
            final boolean ok;
            final VpnDirectUdp4TransportSession session;
            final String errorCode;
            final String errorMessage;
            final long networkHandle;

            private StartResult(boolean ok, VpnDirectUdp4TransportSession session,
                                String errorCode, String errorMessage, long networkHandle) {
                this.ok = ok;
                this.session = session;
                this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.errorMessage =
                        BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.networkHandle = networkHandle;
            }

            static StartResult ready(VpnDirectUdp4TransportSession session) {
                return new StartResult(true, session, "", "", session.networkHandle);
            }

            static StartResult error(String code, String message) {
                return new StartResult(false, null, code, message, -1L);
            }
        }
    }

    private static final class VpnDirectUdp6TransportSession implements AutoCloseable {
        static final String TRANSPORT_NAME = "direct-udp6-protected-socket";

        private final RuntimeService service;
        private final long networkHandle;
        private boolean closed;

        private VpnDirectUdp6TransportSession(RuntimeService service, long networkHandle) {
            this.service = service;
            this.networkHandle = networkHandle;
        }

        static StartResult start(RuntimeService service) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct UDP6 protect");
            }
            UnderlayNetwork underlay = UnderlayNetwork.select(service);
            return start(service, underlay);
        }

        static StartResult start(RuntimeService service, UnderlayNetwork underlay) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct UDP6 protect");
            }
            if (underlay == null) {
                return StartResult.error("vpn_underlay_unavailable",
                        "No underlay Network snapshot is available for Direct UDP6");
            }
            if (!underlay.available) {
                return StartResult.error(underlay.errorCode, underlay.errorMessage);
            }

            DatagramSocket socket = null;
            ParcelFileDescriptor descriptor = null;
            int rawFd = -1;
            try {
                socket = new DatagramSocket(null);
                socket.setReuseAddress(true);
                if (service.vpnFaultModeIs("protect_false")) {
                    return StartResult.error("vpn_direct_udp6_protect_failed",
                            "S185 fault mode simulated VpnService.protect false for Direct UDP6");
                }
                if (!service.protect(socket)) {
                    return StartResult.error("vpn_direct_udp6_protect_failed",
                            "VpnService.protect returned false for Direct UDP6 socket");
                }
                if (service.vpnFaultModeIs("bind_failed")) {
                    return StartResult.error("vpn_direct_udp6_bind_failed",
                            "S185 fault mode simulated Network.bindSocket failure for Direct UDP6");
                }
                underlay.network.bindSocket(socket);
                socket.bind(new InetSocketAddress(InetAddress.getByName("::"), 0));
                service.setUnderlyingNetworks(new Network[]{underlay.network});

                // Keep the documented ParcelFileDescriptor.fromDatagramSocket(socket).dup()
                // pattern explicit: the dup is consumed by ProductCore.
                ParcelFileDescriptor sourceDescriptor =
                        ParcelFileDescriptor.fromDatagramSocket(socket);
                try {
                    descriptor = sourceDescriptor.dup();
                } finally {
                    sourceDescriptor.close();
                }
                rawFd = descriptor.detachFd();
                RuntimeControlFdClient.AttachResult attach =
                        RuntimeControlFdClient.attachVpnUdp6Transport(rawFd);
                rawFd = -1;
                if (!attach.ok) {
                    return StartResult.error(attach.errorCode.isEmpty()
                                    ? "vpn_direct_udp6_attach_failed" : attach.errorCode,
                            attach.errorMessage.isEmpty()
                                    ? "Direct UDP6 fd attach failed" : attach.errorMessage);
                }
                if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(attach.adapter)
                        || !attach.transportFdAttached) {
                    return StartResult.error("vpn_direct_udp6_attach_invalid_result",
                            "Direct UDP6 attach did not prove the ProductCore handoff");
                }
                socket.close();
                socket = null;
                return StartResult.ready(new VpnDirectUdp6TransportSession(
                        service, underlay.networkHandle));
            } catch (Exception error) {
                return StartResult.error("vpn_direct_udp6_start_failed", messageOf(error));
            } finally {
                if (rawFd >= 0) {
                    closeRawFdQuietly(rawFd);
                }
                if (descriptor != null) {
                    try {
                        descriptor.close();
                    } catch (IOException ignored) {
                        // The attach result already records the actionable failure.
                    }
                }
                if (socket != null) {
                    socket.close();
                }
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            service.setUnderlyingNetworks(null);
        }

        private static void closeRawFdQuietly(int rawFd) {
            try {
                ParcelFileDescriptor.adoptFd(rawFd).close();
            } catch (IOException ignored) {
                // Best-effort cleanup of a not-yet-transferred descriptor.
            }
        }

        static final class StartResult {
            final boolean ok;
            final VpnDirectUdp6TransportSession session;
            final String errorCode;
            final String errorMessage;
            final long networkHandle;

            private StartResult(boolean ok, VpnDirectUdp6TransportSession session,
                                String errorCode, String errorMessage, long networkHandle) {
                this.ok = ok;
                this.session = session;
                this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.errorMessage =
                        BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.networkHandle = networkHandle;
            }

            static StartResult ready(VpnDirectUdp6TransportSession session) {
                return new StartResult(true, session, "", "", session.networkHandle);
            }

            static StartResult error(String code, String message) {
                return new StartResult(false, null, code, message, -1L);
            }
        }
    }

    private static final class VpnDirectTcp4TransportSession implements AutoCloseable {
        static final String TRANSPORT_NAME = "direct-tcp4-protected-socket-pool";
        private static final int SOCKET_POOL_SIZE = 16;

        private final RuntimeService service;
        private final long networkHandle;
        private final int socketCount;
        private boolean closed;

        private VpnDirectTcp4TransportSession(RuntimeService service, long networkHandle,
                                              int socketCount) {
            this.service = service;
            this.networkHandle = networkHandle;
            this.socketCount = socketCount;
        }

        static StartResult start(RuntimeService service) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct TCP4 protect");
            }
            UnderlayNetwork underlay = UnderlayNetwork.select(service);
            return start(service, underlay);
        }

        static StartResult start(RuntimeService service, UnderlayNetwork underlay) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct TCP4 protect");
            }
            if (underlay == null) {
                return StartResult.error("vpn_underlay_unavailable",
                        "No underlay Network snapshot is available for Direct TCP4");
            }
            if (!underlay.available) {
                return StartResult.error(underlay.errorCode, underlay.errorMessage);
            }
            int attached = 0;
            for (int index = 0; index < SOCKET_POOL_SIZE; ++index) {
                StartResult single = attachOne(service, underlay);
                if (!single.ok) {
                    return single;
                }
                attached++;
            }
            service.setUnderlyingNetworks(new Network[]{underlay.network});
            return StartResult.ready(new VpnDirectTcp4TransportSession(
                    service, underlay.networkHandle, attached));
        }

        private static StartResult attachOne(RuntimeService service, UnderlayNetwork underlay) {
            Socket socket = null;
            ParcelFileDescriptor descriptor = null;
            int rawFd = -1;
            try {
                socket = new Socket();
                socket.setReuseAddress(true);
                socket.setTcpNoDelay(true);
                if (service.vpnFaultModeIs("protect_false")) {
                    return StartResult.error("vpn_direct_tcp4_protect_failed",
                            "S185 fault mode simulated VpnService.protect false for Direct TCP4");
                }
                if (!service.protect(socket)) {
                    return StartResult.error("vpn_direct_tcp4_protect_failed",
                            "VpnService.protect returned false for Direct TCP4 socket");
                }
                if (service.vpnFaultModeIs("bind_failed")) {
                    return StartResult.error("vpn_direct_tcp4_bind_failed",
                            "S185 fault mode simulated Network.bindSocket failure for Direct TCP4");
                }
                underlay.network.bindSocket(socket);
                socket.bind(new InetSocketAddress(
                        InetAddress.getByName("0.0.0.0"), 0));

                // Keep the TCP counterpart of the documented UDP
                // ParcelFileDescriptor.fromSocket(socket).dup() handoff
                // pattern explicit: the dup is consumed by ProductCore.
                ParcelFileDescriptor sourceDescriptor =
                        ParcelFileDescriptor.fromSocket(socket);
                try {
                    descriptor = sourceDescriptor.dup();
                } finally {
                    sourceDescriptor.close();
                }
                rawFd = descriptor.detachFd();
                RuntimeControlFdClient.AttachResult attach =
                        RuntimeControlFdClient.attachVpnTcpTransport(rawFd);
                rawFd = -1;
                if (!attach.ok) {
                    return StartResult.error(attach.errorCode.isEmpty()
                                    ? "vpn_direct_tcp4_attach_failed" : attach.errorCode,
                            attach.errorMessage.isEmpty()
                                    ? "Direct TCP4 fd attach failed" : attach.errorMessage);
                }
                if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(attach.adapter)
                        || !attach.transportFdAttached) {
                    return StartResult.error("vpn_direct_tcp4_attach_invalid_result",
                            "Direct TCP4 attach did not prove the ProductCore handoff");
                }
                socket.close();
                socket = null;
                return StartResult.ready(new VpnDirectTcp4TransportSession(
                        service, underlay.networkHandle, 1));
            } catch (Exception error) {
                return StartResult.error("vpn_direct_tcp4_start_failed", messageOf(error));
            } finally {
                if (rawFd >= 0) {
                    closeRawFdQuietly(rawFd);
                }
                if (descriptor != null) {
                    try {
                        descriptor.close();
                    } catch (IOException ignored) {
                        // The attach result already records the actionable failure.
                    }
                }
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException ignored) {
                        // The attach result already records the actionable failure.
                    }
                }
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            service.setUnderlyingNetworks(null);
        }

        private static void closeRawFdQuietly(int rawFd) {
            try {
                ParcelFileDescriptor.adoptFd(rawFd).close();
            } catch (IOException ignored) {
                // Best-effort cleanup of a not-yet-transferred descriptor.
            }
        }

        static final class StartResult {
            final boolean ok;
            final VpnDirectTcp4TransportSession session;
            final String errorCode;
            final String errorMessage;
            final long networkHandle;
            final int socketCount;

            private StartResult(boolean ok, VpnDirectTcp4TransportSession session,
                                String errorCode, String errorMessage, long networkHandle,
                                int socketCount) {
                this.ok = ok;
                this.session = session;
                this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.errorMessage =
                        BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.networkHandle = networkHandle;
                this.socketCount = socketCount;
            }

            static StartResult ready(VpnDirectTcp4TransportSession session) {
                return new StartResult(true, session, "", "", session.networkHandle,
                        session.socketCount);
            }

            static StartResult error(String code, String message) {
                return new StartResult(false, null, code, message, -1L, 0);
            }
        }
    }

    private static final class VpnDirectTcp6TransportSession implements AutoCloseable {
        static final String TRANSPORT_NAME = "direct-tcp6-protected-socket-pool";
        private static final int SOCKET_POOL_SIZE = 16;

        private final RuntimeService service;
        private final long networkHandle;
        private final int socketCount;
        private boolean closed;

        private VpnDirectTcp6TransportSession(RuntimeService service, long networkHandle,
                                              int socketCount) {
            this.service = service;
            this.networkHandle = networkHandle;
            this.socketCount = socketCount;
        }

        static StartResult start(RuntimeService service) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct TCP6 protect");
            }
            UnderlayNetwork underlay = UnderlayNetwork.select(service);
            return start(service, underlay);
        }

        static StartResult start(RuntimeService service, UnderlayNetwork underlay) {
            if (service == null) {
                return StartResult.error("vpn_service_missing",
                        "VpnService instance is unavailable for Direct TCP6 protect");
            }
            if (underlay == null) {
                return StartResult.error("vpn_underlay_unavailable",
                        "No underlay Network snapshot is available for Direct TCP6");
            }
            if (!underlay.available) {
                return StartResult.error(underlay.errorCode, underlay.errorMessage);
            }
            int attached = 0;
            for (int index = 0; index < SOCKET_POOL_SIZE; ++index) {
                StartResult single = attachOne(service, underlay);
                if (!single.ok) {
                    return single;
                }
                attached++;
            }
            service.setUnderlyingNetworks(new Network[]{underlay.network});
            return StartResult.ready(new VpnDirectTcp6TransportSession(
                    service, underlay.networkHandle, attached));
        }

        private static StartResult attachOne(RuntimeService service, UnderlayNetwork underlay) {
            Socket socket = null;
            ParcelFileDescriptor descriptor = null;
            int rawFd = -1;
            try {
                socket = new Socket();
                socket.setReuseAddress(true);
                socket.setTcpNoDelay(true);
                if (service.vpnFaultModeIs("protect_false")) {
                    return StartResult.error("vpn_direct_tcp6_protect_failed",
                            "S185 fault mode simulated VpnService.protect false for Direct TCP6");
                }
                if (!service.protect(socket)) {
                    return StartResult.error("vpn_direct_tcp6_protect_failed",
                            "VpnService.protect returned false for Direct TCP6 socket");
                }
                if (service.vpnFaultModeIs("bind_failed")) {
                    return StartResult.error("vpn_direct_tcp6_bind_failed",
                            "S185 fault mode simulated Network.bindSocket failure for Direct TCP6");
                }
                underlay.network.bindSocket(socket);
                socket.bind(new InetSocketAddress(
                        InetAddress.getByName("::"), 0));

                // Keep the TCP6 counterpart of the documented UDP/TCP4
                // ParcelFileDescriptor.fromSocket(socket).dup() handoff
                // pattern explicit: the dup is consumed by ProductCore.
                ParcelFileDescriptor sourceDescriptor =
                        ParcelFileDescriptor.fromSocket(socket);
                try {
                    descriptor = sourceDescriptor.dup();
                } finally {
                    sourceDescriptor.close();
                }
                rawFd = descriptor.detachFd();
                RuntimeControlFdClient.AttachResult attach =
                        RuntimeControlFdClient.attachVpnTcp6Transport(rawFd);
                rawFd = -1;
                if (!attach.ok) {
                    return StartResult.error(attach.errorCode.isEmpty()
                                    ? "vpn_direct_tcp6_attach_failed" : attach.errorCode,
                            attach.errorMessage.isEmpty()
                                    ? "Direct TCP6 fd attach failed" : attach.errorMessage);
                }
                if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(attach.adapter)
                        || !attach.transportFdAttached) {
                    return StartResult.error("vpn_direct_tcp6_attach_invalid_result",
                            "Direct TCP6 attach did not prove the ProductCore handoff");
                }
                socket.close();
                socket = null;
                return StartResult.ready(new VpnDirectTcp6TransportSession(
                        service, underlay.networkHandle, 1));
            } catch (Exception error) {
                return StartResult.error("vpn_direct_tcp6_start_failed", messageOf(error));
            } finally {
                if (rawFd >= 0) {
                    closeRawFdQuietly(rawFd);
                }
                if (descriptor != null) {
                    try {
                        descriptor.close();
                    } catch (IOException ignored) {
                        // The attach result already records the actionable failure.
                    }
                }
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException ignored) {
                        // The attach result already records the actionable failure.
                    }
                }
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            service.setUnderlyingNetworks(null);
        }

        private static void closeRawFdQuietly(int rawFd) {
            try {
                ParcelFileDescriptor.adoptFd(rawFd).close();
            } catch (IOException ignored) {
                // Best-effort cleanup of a not-yet-transferred descriptor.
            }
        }

        static final class StartResult {
            final boolean ok;
            final VpnDirectTcp6TransportSession session;
            final String errorCode;
            final String errorMessage;
            final long networkHandle;
            final int socketCount;

            private StartResult(boolean ok, VpnDirectTcp6TransportSession session,
                                String errorCode, String errorMessage, long networkHandle,
                                int socketCount) {
                this.ok = ok;
                this.session = session;
                this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.errorMessage =
                        BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
                this.networkHandle = networkHandle;
                this.socketCount = socketCount;
            }

            static StartResult ready(VpnDirectTcp6TransportSession session) {
                return new StartResult(true, session, "", "", session.networkHandle,
                        session.socketCount);
            }

            static StartResult error(String code, String message) {
                return new StartResult(false, null, code, message, -1L, 0);
            }
        }
    }

    private static final class UnderlayNetwork {
        final boolean available;
        final Network network;
        final long networkHandle;
        final String transport;
        final String errorCode;
        final String errorMessage;

        private UnderlayNetwork(boolean available, Network network, long networkHandle,
                                String transport, String errorCode, String errorMessage) {
            this.available = available;
            this.network = network;
            this.networkHandle = networkHandle;
            this.transport = BoundedText.value(transport, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.errorMessage = BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
        }

        static UnderlayNetwork select(RuntimeService service) {
            ConnectivityManager connectivity =
                    service.getSystemService(ConnectivityManager.class);
            if (connectivity == null) {
                return unavailable("vpn_underlay_unavailable",
                        "ConnectivityManager is unavailable");
            }
            Network[] networks;
            try {
                networks = connectivity.getAllNetworks();
            } catch (RuntimeException error) {
                return unavailable("vpn_underlay_lookup_failed", messageOf(error));
            }
            if (networks == null) {
                return unavailable("vpn_underlay_unavailable",
                        "ConnectivityManager returned no networks");
            }
            UnderlayNetwork fallback = null;
            int fallbackRank = Integer.MAX_VALUE;
            for (Network network : networks) {
                if (network == null) {
                    continue;
                }
                NetworkCapabilities capabilities;
                try {
                    capabilities = connectivity.getNetworkCapabilities(network);
                } catch (RuntimeException ignored) {
                    continue;
                }
                if (capabilities == null
                        || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    continue;
                }
                int rank = transportRank(capabilities);
                if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                        && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                        && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    continue;
                }
                long handle;
                try {
                    handle = network.getNetworkHandle();
                } catch (RuntimeException error) {
                    return unavailable("vpn_underlay_handle_failed", messageOf(error));
                }
                UnderlayNetwork candidate = new UnderlayNetwork(true, network, handle,
                        transportName(capabilities), "", "");
                if (rank == 0) {
                    return candidate;
                }
                if (rank < fallbackRank) {
                    fallback = candidate;
                    fallbackRank = rank;
                }
            }
            if (fallback != null) {
                return fallback;
            }
            return unavailable("vpn_underlay_unavailable",
                    "No non-VPN underlay Network is available for Direct VPN handoff");
        }

        private static int transportRank(NetworkCapabilities capabilities) {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return 0;
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return 1;
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return 2;
            }
            return 3;
        }

        private static String transportName(NetworkCapabilities capabilities) {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return "wifi";
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return "ethernet";
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return "cellular";
            }
            return "unknown";
        }

        private static UnderlayNetwork unavailable(String code, String message) {
            return new UnderlayNetwork(false, null, -1L, "", code, message);
        }
    }

    private long currentPid() {
        if (snapshot != null && snapshot.pid > 0L) {
            return snapshot.pid;
        }
        initializeProfilePaths(activeProfile);
        return readPid(pidFile);
    }

    private boolean currentMayBeActive() {
        return snapshot != null && snapshot.mayBeActive;
    }

    private static boolean processAlive(Process process) {
        return process != null && process.isAlive();
    }

    private static long readPid(File file) {
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[32];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    bytes.write(buffer, 0, count);
                }
            }
            return Long.parseLong(bytes.toString(StandardCharsets.US_ASCII.name()).trim());
        } catch (Exception ignored) {
            return -1L;
        }
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[32 * 1024];
        try (InputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    digest.update(buffer, 0, count);
                }
            }
        }
        StringBuilder value = new StringBuilder(64);
        for (byte item : digest.digest()) {
            value.append(String.format(Locale.US, "%02x", item & 0xff));
        }
        return value.toString();
    }

    private boolean rootCommandAvailable() {
        File su = new File(SU_PATH);
        if (!su.isFile() || !su.canExecute()) {
            return false;
        }
        Process process = null;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", "id -u")
                    .redirectErrorStream(true).start();
            if (!process.waitFor(5L, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return false;
            }
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[32];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count > 0 && output.size() < 64) {
                        output.write(buffer, 0, Math.min(count, 64 - output.size()));
                    }
                }
            }
            return process.exitValue() == 0
                    && "0".equals(output.toString(StandardCharsets.UTF_8.name()).trim());
        } catch (Exception error) {
            if (process != null) {
                process.destroyForcibly();
            }
            Log.w(TAG, "root authorization probe failed", error);
            return false;
        }
    }

    private boolean runRootCommand(String command, long timeoutSeconds) {
        return runRootCommandStatus(command, timeoutSeconds) == 0;
    }

    private int runRootCommandStatus(String command, long timeoutSeconds) {
        try {
            Process process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return 124;
            }
            return process.exitValue();
        } catch (Exception error) {
            Log.w(TAG, "root command failed", error);
            return ROOT_COMMAND_UNAVAILABLE;
        }
    }

    private boolean runAppCommand(String command, long timeoutSeconds) {
        return runAppCommandStatus(command, timeoutSeconds) == 0;
    }

    private int runAppCommandStatus(String command, long timeoutSeconds) {
        try {
            Process process = new ProcessBuilder("/system/bin/sh", "-c", command).start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return 124;
            }
            return process.exitValue();
        } catch (Exception error) {
            Log.w(TAG, "app command failed", error);
            return 125;
        }
    }

    private static boolean deleteTree(File file) {
        if (!file.exists()) {
            return true;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                if (!deleteTree(child)) {
                    return false;
                }
            }
        }
        return file.delete();
    }

    private static String deviceAbi() {
        return Build.SUPPORTED_ABIS.length == 0 ? "" : Build.SUPPORTED_ABIS[0];
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String messageOf(Exception error) {
        String message = error.getMessage();
        return error.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }

    @Override
    public void onRevoke() {
        enqueueLifecycle(() -> handleVpnAuthorizationRevoked("system"));
        super.onRevoke();
    }

    private void handleVpnAuthorizationRevoked(String source) {
        appendLog("vpn_authorization=revoked source=" + source);
        if (activeProfile != RuntimeProfile.VPN
                || snapshot == null
                || snapshot.profile != RuntimeProfile.VPN
                || !snapshot.isActive()) {
            appendLog("ignored stale vpn_authorization_revoked source=" + source
                    + " activeProfile="
                    + (activeProfile == null ? "none" : activeProfile.wireName));
            return;
        }
        if (activeProfile == RuntimeProfile.VPN
                && (processAlive(vppProcess)
                || (productCoreSession != null && productCoreSession.isConnected()))) {
            failProductCoreGeneration("vpn_authorization_revoked",
                    "Android revoked VpnService authorization");
            return;
        }
        clearProfileHandles();
        publishError("vpn_authorization_revoked",
                "Android revoked VpnService authorization", false,
                ProductCoreLifecycle.UNKNOWN_PID);
    }

    @Override
    public void onDestroy() {
        final boolean ownsServiceInstance = isCurrentServiceInstance();
        destroying = true;
        stopRequested = true;
        if (ownsServiceInstance && isCurrentServiceInstance()
                && snapshot != null && snapshot.isActive()
                && !RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state)) {
            publish(RuntimeSnapshot.stopping(snapshot));
        }
        // Main-thread destruction never waits. The serial worker drains an
        // in-flight start and performs bounded stop/cleanup before shutdown.
        Runnable teardown = () -> {
            try {
                if (ownsServiceInstance && isCurrentServiceInstance()) {
                    stopRuntime();
                } else {
                    appendLog("lifecycle_teardown=skipped_superseded_service");
                }
            } finally {
                synchronized (SERVICE_INSTANCE_LOCK) {
                    if (activeServiceInstance == this) {
                        activeServiceInstance = null;
                    }
                }
                lifecycle.shutdown();
            }
        };
        // Destruction supersedes queued queries/starts. Drop those stale
        // requests so a bounded lifecycle queue always retains room for the
        // teardown barrier; an in-flight task remains serialized ahead of it.
        if (lifecycle instanceof ThreadPoolExecutor) {
            ((ThreadPoolExecutor) lifecycle).getQueue().clear();
        }
        if (!enqueueLifecycle(teardown)) {
            appendLog("lifecycle_teardown_rejected");
        }
        super.onDestroy();
    }

    private boolean isCurrentServiceInstance() {
        return activeServiceInstance == this && !serviceInstanceSuperseded;
    }

    private boolean isSupersededServiceInstance() {
        RuntimeService current = activeServiceInstance;
        return serviceInstanceSuperseded || (current != null && current != this);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void appendLog(String line) {
        File log = runtimeLog;
        if (log == null) {
            File logs = new File(getFilesDir(), "logs");
            if (!logs.isDirectory()) {
                logs.mkdirs();
            }
            log = new File(logs, "runtime-service.log");
            runtimeLog = log;
        }
        try (FileOutputStream output = new FileOutputStream(log, true)) {
            output.write((System.currentTimeMillis() + " " + line + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            if (log.length() > 256L * 1024L) {
                // Keep diagnostics bounded; the durable snapshot remains the
                // source of truth for current state and error identity.
                log.delete();
            }
        } catch (IOException error) {
            Log.e(TAG, "runtime log write failed", error);
        }
    }

}
