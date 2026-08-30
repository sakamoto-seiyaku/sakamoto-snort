package com.sakamoto.snort.androidruntime;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Small Android-free seam for the durable Product Core owner fact.
 *
 * <p>The record is evidence for one generation, not a process adoption
 * protocol. A service recreation may use it to decide whether a profile can
 * be cleaned. PID is retained only as optional diagnostic text; it is never
 * needed to authorize a replacement.</p>
 */
public final class ProductCoreOwner {
    public static final int SCHEMA_VERSION = 1;
    public static final long UNKNOWN_PID = -1L;
    public static final String RECORD_FILE = "owner.properties";

    private static final String KEY_SCHEMA = "schemaVersion";
    private static final String KEY_GENERATION = "generation";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_PROFILE = "profile";
    private static final String KEY_RUNTIME = "runtimePath";
    private static final String KEY_SOCKET = "apiSocket";
    private static final String KEY_ARTIFACT = "artifactId";
    private static final String KEY_REVISION = "revision";
    private static final String KEY_DIAGNOSTIC_PID = "diagnosticPid";

    private ProductCoreOwner() {}

    public enum ProcessState {
        LIVE,
        GONE,
        UNKNOWN
    }

    public enum Action {
        FRESH_START,
        CLEAN_THEN_START,
        BLOCK_LIVE,
        BLOCK_UNKNOWN
    }

    public enum CleanupAction {
        CLEAR_OWNER,
        RETAIN_OWNER
    }

    /** One result type keeps the start and cleanup decisions easy to inspect. */
    public static final class Decision {
        public final Action action;
        public final CleanupAction cleanupAction;
        public final String errorCode;
        public final String detail;

        private Decision(Action action, CleanupAction cleanupAction,
                         String errorCode, String detail) {
            this.action = action;
            this.cleanupAction = cleanupAction;
            this.errorCode = value(errorCode);
            this.detail = value(detail);
        }

        private static Decision start(Action action, String detail) {
            return new Decision(action, null, action == Action.BLOCK_LIVE
                    ? "product_core_owner_live"
                    : action == Action.BLOCK_UNKNOWN ? "product_core_owner_unverified" : "",
                    detail);
        }

        private static Decision cleanup(CleanupAction action, String errorCode, String detail) {
            return new Decision(null, action, errorCode, detail);
        }

        public static Decision unknown(String detail) {
            return start(Action.BLOCK_UNKNOWN, detail);
        }
    }

    /** Strict, durable identity facts written before the VPP process starts. */
    public static final class OwnerRecord {
        public final long generation;
        public final String token;
        public final RuntimeProfile profile;
        public final String runtimePath;
        public final String apiSocket;
        public final String artifactId;
        public final String revision;
        /** Diagnostic only. Android's supported Process API does not supply it. */
        public final long diagnosticPid;

        private OwnerRecord(long generation, String token, RuntimeProfile profile,
                            String runtimePath, String apiSocket, String artifactId,
                            String revision, long diagnosticPid) {
            if (generation <= 0L) {
                throw new IllegalArgumentException("owner generation must be positive");
            }
            if (token == null || !token.matches("[0-9a-fA-F-]{36}")) {
                throw new IllegalArgumentException("owner token must be a UUID");
            }
            if (profile == null) {
                throw new IllegalArgumentException("owner profile is required");
            }
            this.generation = generation;
            this.token = safeScalar(token, "owner token");
            this.profile = profile;
            this.runtimePath = absolutePath(runtimePath, "owner runtime path");
            if (!this.runtimePath.endsWith("/runtime")) {
                throw new IllegalArgumentException("owner runtime path must end in /runtime");
            }
            this.apiSocket = absolutePath(apiSocket, "owner API socket");
            if (!this.apiSocket.startsWith(this.runtimePath + "/")) {
                throw new IllegalArgumentException("owner API socket is outside runtime path");
            }
            this.artifactId = safeScalar(artifactId, "owner artifact identity");
            this.revision = safeScalar(revision, "owner VPP revision");
            if (diagnosticPid < UNKNOWN_PID) {
                throw new IllegalArgumentException("owner diagnostic PID is invalid");
            }
            this.diagnosticPid = diagnosticPid;
        }

        public static OwnerRecord create(long generation, String token, RuntimeProfile profile,
                                         String runtimePath, String apiSocket,
                                         String artifactId, String revision) {
            return new OwnerRecord(generation, token, profile, runtimePath, apiSocket,
                    artifactId, revision, UNKNOWN_PID);
        }

        /** Encode a deterministic record; the parser deliberately accepts no duplicate keys. */
        public String encode() {
            return KEY_SCHEMA + "=" + SCHEMA_VERSION + "\n"
                    + KEY_GENERATION + "=" + generation + "\n"
                    + KEY_TOKEN + "=" + token + "\n"
                    + KEY_PROFILE + "=" + profile.wireName + "\n"
                    + KEY_RUNTIME + "=" + runtimePath + "\n"
                    + KEY_SOCKET + "=" + apiSocket + "\n"
                    + KEY_ARTIFACT + "=" + artifactId + "\n"
                    + KEY_REVISION + "=" + revision + "\n"
                    + KEY_DIAGNOSTIC_PID + "=" + diagnosticPid + "\n";
        }

        /** Parse one strict record from text. */
        public static OwnerRecord parse(String encoded) {
            if (encoded == null) {
                throw new IllegalArgumentException("owner record is missing");
            }
            try {
                Map<String, String> values = parseLines(new StringReader(encoded));
                requireKeys(values);
                int schema = parseInt(values.get(KEY_SCHEMA), KEY_SCHEMA);
                if (schema != SCHEMA_VERSION) {
                    throw new IllegalArgumentException("unsupported owner record schema");
                }
                long generation = parseLong(values.get(KEY_GENERATION), KEY_GENERATION);
                RuntimeProfile profile;
                try {
                    profile = RuntimeProfile.parse(values.get(KEY_PROFILE));
                } catch (IllegalArgumentException error) {
                    throw new IllegalArgumentException("invalid owner profile", error);
                }
                long diagnosticPid = parseLong(values.get(KEY_DIAGNOSTIC_PID),
                        KEY_DIAGNOSTIC_PID);
                return new OwnerRecord(generation, values.get(KEY_TOKEN), profile,
                        values.get(KEY_RUNTIME), values.get(KEY_SOCKET),
                        values.get(KEY_ARTIFACT), values.get(KEY_REVISION), diagnosticPid);
            } catch (IOException error) {
                throw new IllegalArgumentException("owner record could not be read", error);
            }
        }

        /** Read and parse the record without the Android lifecycle. */
        public static OwnerRecord read(File file) throws IOException {
            if (file == null || !file.isFile()) {
                throw new IOException("owner record is missing");
            }
            StringBuilder encoded = new StringBuilder();
            try (Reader reader = new InputStreamReader(new FileInputStream(file),
                    StandardCharsets.US_ASCII)) {
                char[] buffer = new char[256];
                int count;
                while ((count = reader.read(buffer)) >= 0) {
                    if (count > 0) {
                        encoded.append(buffer, 0, count);
                    }
                }
            }
            try {
                return parse(encoded.toString());
            } catch (IllegalArgumentException error) {
                throw new IOException(error.getMessage(), error);
            }
        }

        /** Publish the durable fact before starting the process. */
        public void write(File file) throws IOException {
            if (file == null) {
                throw new IOException("owner record path is missing");
            }
            File parent = file.getParentFile();
            if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
                throw new IOException("owner record directory could not be created");
            }
            try (FileOutputStream output = new FileOutputStream(file);
                 OutputStreamWriter writer = new OutputStreamWriter(output,
                         StandardCharsets.US_ASCII);
                 BufferedWriter buffered = new BufferedWriter(writer)) {
                buffered.write(encode());
                buffered.flush();
                output.getFD().sync();
            }
        }

        /** Compare installation identity; generation/token remain generation-specific. */
        public boolean sameInstallation(OwnerRecord other) {
            return other != null
                    && profile == other.profile
                    && runtimePath.equals(other.runtimePath)
                    && apiSocket.equals(other.apiSocket)
                    && artifactId.equals(other.artifactId)
                    && revision.equals(other.revision);
        }

        private static Map<String, String> parseLines(Reader source) throws IOException {
            Map<String, String> values = new HashMap<>();
            BufferedReader reader = new BufferedReader(source);
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                if (line.charAt(0) == '#' || line.charAt(0) == ';') {
                    throw new IllegalArgumentException("owner record comments are not allowed");
                }
                int separator = line.indexOf('=');
                if (separator <= 0 || separator != line.lastIndexOf('=')) {
                    throw new IllegalArgumentException("owner record line is not key=value");
                }
                String key = line.substring(0, separator);
                String item = line.substring(separator + 1);
                if (!isKnownKey(key) || values.containsKey(key)) {
                    throw new IllegalArgumentException("owner record key is duplicate or unknown: "
                            + key);
                }
                if (key.trim().length() != key.length() || item.trim().length() != item.length()) {
                    throw new IllegalArgumentException("owner record values must be exact");
                }
                values.put(key, item);
            }
            return values;
        }

        private static void requireKeys(Map<String, String> values) {
            String[] keys = {KEY_SCHEMA, KEY_GENERATION, KEY_TOKEN, KEY_PROFILE,
                    KEY_RUNTIME, KEY_SOCKET, KEY_ARTIFACT, KEY_REVISION, KEY_DIAGNOSTIC_PID};
            for (String key : keys) {
                if (!values.containsKey(key)) {
                    throw new IllegalArgumentException("owner record key is missing: " + key);
                }
            }
            if (values.size() != keys.length) {
                throw new IllegalArgumentException("owner record has unexpected keys");
            }
        }

        private static boolean isKnownKey(String key) {
            return KEY_SCHEMA.equals(key) || KEY_GENERATION.equals(key)
                    || KEY_TOKEN.equals(key) || KEY_PROFILE.equals(key)
                    || KEY_RUNTIME.equals(key) || KEY_SOCKET.equals(key)
                    || KEY_ARTIFACT.equals(key) || KEY_REVISION.equals(key)
                    || KEY_DIAGNOSTIC_PID.equals(key);
        }

        private static int parseInt(String value, String key) {
            try {
                return Integer.parseInt(value);
            } catch (Exception error) {
                throw new IllegalArgumentException("owner record integer is invalid: " + key,
                        error);
            }
        }

        private static long parseLong(String value, String key) {
            try {
                return Long.parseLong(value);
            } catch (Exception error) {
                throw new IllegalArgumentException("owner record integer is invalid: " + key,
                        error);
            }
        }
    }

    /** Decide the only allowed START transition after an ownership audit. */
    public static Decision decideForStart(boolean profilePresent, OwnerRecord record,
                                          boolean identityMatches, ProcessState processState,
                                          boolean processHandleLive) {
        if (processHandleLive || processState == ProcessState.LIVE) {
            return Decision.start(Action.BLOCK_LIVE,
                    "a Product Core owner is still live; replacement is blocked");
        }
        if (processState == null || processState == ProcessState.UNKNOWN) {
            return Decision.start(Action.BLOCK_UNKNOWN,
                    "Product Core owner state could not be verified");
        }
        if (!profilePresent) {
            return Decision.start(Action.FRESH_START, "no Product Core owner profile exists");
        }
        if (record == null || !identityMatches) {
            return Decision.start(Action.BLOCK_UNKNOWN,
                    "Product Core owner record is missing or does not match this installation");
        }
        return Decision.start(Action.CLEAN_THEN_START,
                "the exact Product Core owner is proven gone");
    }

    /** Clear handles/tree only after the process is gone and cleanup succeeded. */
    public static Decision decideCleanup(boolean processHandleLive, boolean profileRemoved) {
        if (processHandleLive || !profileRemoved) {
            return Decision.cleanup(CleanupAction.RETAIN_OWNER, "cleanup_failed",
                    "Product Core owner remains authoritative until cleanup succeeds");
        }
        return Decision.cleanup(CleanupAction.CLEAR_OWNER, "",
                "Product Core owner cleanup completed");
    }

    /** Convert the bounded shell audit output into a conservative process state. */
    public static ProcessState processState(int status, String output) {
        if (status != 0 || output == null) {
            return ProcessState.UNKNOWN;
        }
        String marker = "PRODUCT_OWNER_COUNT=";
        int start = output.indexOf(marker);
        if (start < 0) {
            return ProcessState.UNKNOWN;
        }
        int valueStart = start + marker.length();
        int valueEnd = valueStart;
        while (valueEnd < output.length() && Character.isDigit(output.charAt(valueEnd))) {
            valueEnd++;
        }
        if (valueEnd == valueStart) {
            return ProcessState.UNKNOWN;
        }
        try {
            int count = Integer.parseInt(output.substring(valueStart, valueEnd));
            return count == 0 ? ProcessState.GONE : count == 1
                    ? ProcessState.LIVE : ProcessState.UNKNOWN;
        } catch (NumberFormatException error) {
            return ProcessState.UNKNOWN;
        }
    }

    /** Build a bounded app-UID shell probe for the exact executable/profile/token identity. */
    public static String buildProcessAuditCommand(OwnerRecord record, String executablePath) {
        return buildProcessAuditCommand(record, executablePath, "*");
    }

    /**
     * Build the same probe with an explicit UID filter. The UID filter is
     * deliberately before any /proc reads: an app must not inspect arbitrary
     * other-UID processes, while an unreadable candidate in its own UID stays
     * unknown and therefore blocks replacement.
     */
    public static String buildProcessAuditCommand(OwnerRecord record, String executablePath,
                                                   String expectedUid) {
        if (record == null) {
            throw new IllegalArgumentException("owner record is missing");
        }
        String executable = absolutePath(executablePath, "Product Core executable path");
        String uid = safeScalar(expectedUid, "Product Core owner UID");
        String startup = record.runtimePath.substring(0,
                record.runtimePath.length() - "/runtime".length()) + "/startup.conf";
        String ownerEnv = "SAKAMOTO_VPP_OWNER_TOKEN=" + record.token;
        String generationEnv = "SAKAMOTO_PRODUCT_GENERATION=" + record.generation;
        String runtimeEnv = "SAKAMOTO_VPP_RUNTIME_DIR=" + record.runtimePath;
        String profileEnv = "SAKAMOTO_RUNTIME_PROFILE=" + record.profile.wireName;
        String socket = shellQuote(record.apiSocket);
        return "set +e; "
                + "ps_output=$(ps -A -o PID,UID,args 2>/dev/null); ps_status=$?; "
                + "if [ \"$ps_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=ps; exit 125; fi; "
                + "count=0; "
                + "for pid in $(printf '%s\\n' \"$ps_output\" | awk -v expected_uid="
                + shellQuote(uid)
                + " '$1 ~ /^[0-9]+$/ && (expected_uid == \"*\" || $2 == expected_uid) {print $1}'); do "
                + "proc=/proc/$pid; "
                + "exe=$(readlink \"$proc/exe\" 2>/dev/null); exe_status=$?; "
                + "if [ \"$exe_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=exe; exit 125; fi; "
                + "[ \"$exe\" = " + shellQuote(executable) + " ] || continue; "
                + "cmd=$(tr '\\0' ' ' <\"$proc/cmdline\" 2>/dev/null); cmd_status=$?; "
                + "if [ \"$cmd_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=cmdline; exit 125; fi; "
                + "case \"$cmd\" in *" + shellQuote(startup) + "*) ;; *) continue ;; esac; "
                + "env=$(tr '\\0' '\\n' <\"$proc/environ\" 2>/dev/null); env_status=$?; "
                + "if [ \"$env_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=environ; exit 125; fi; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(ownerEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=token; exit 125; }; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(generationEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=generation; exit 125; }; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(runtimeEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=runtime; exit 125; }; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(profileEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=profile; exit 125; }; "
                + "count=$((count + 1)); done; "
                + "if [ -e " + socket + " ]; then echo PRODUCT_OWNER_SOCKET=present; "
                + "else echo PRODUCT_OWNER_SOCKET=absent; fi; "
                + "echo PRODUCT_OWNER_COUNT=$count; exit 0";
    }

    private static String absolutePath(String value, String label) {
        String safe = safeScalar(value, label);
        if (!safe.startsWith("/")) {
            throw new IllegalArgumentException(label + " must be absolute");
        }
        return safe;
    }

    private static String safeScalar(String value, String label) {
        if (value == null || value.isEmpty() || !value.equals(value.trim())
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0
                || value.indexOf('=') >= 0) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        return value;
    }

    private static String value(String input) {
        return input == null ? "" : input;
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
