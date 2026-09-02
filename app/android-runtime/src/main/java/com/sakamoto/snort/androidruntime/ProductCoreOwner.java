package com.sakamoto.snort.androidruntime;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
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

    /** Durable facts for the two fixed Product Core profiles. */
    public static final class ProfileFact {
        public final RuntimeProfile profile;
        public final boolean present;
        public final OwnerRecord owner;
        public final boolean identityMatches;
        public final ProcessState processState;
        public final String detail;

        private ProfileFact(RuntimeProfile profile, boolean present, OwnerRecord owner,
                            boolean identityMatches, ProcessState processState, String detail) {
            if (profile == null) {
                throw new IllegalArgumentException("Product Core profile is required");
            }
            this.profile = profile;
            this.present = present;
            this.owner = owner;
            this.identityMatches = identityMatches;
            this.processState = processState;
            this.detail = value(detail);
        }

        public static ProfileFact absent(RuntimeProfile profile) {
            return new ProfileFact(profile, false, null, false, ProcessState.GONE,
                    "profile is absent");
        }

        public static ProfileFact exactGone(RuntimeProfile profile, OwnerRecord owner) {
            if (owner == null) {
                throw new IllegalArgumentException("exact gone owner is required");
            }
            return new ProfileFact(profile, true, owner, true, ProcessState.GONE,
                    "exact owner is proven gone");
        }

        public static ProfileFact live(RuntimeProfile profile, OwnerRecord owner) {
            if (owner == null) {
                throw new IllegalArgumentException("live owner is required");
            }
            return new ProfileFact(profile, true, owner, true, ProcessState.LIVE,
                    "exact owner is live");
        }

        public static ProfileFact repairable(RuntimeProfile profile, String detail) {
            return new ProfileFact(profile, true, null, true, ProcessState.GONE, detail);
        }

        public static ProfileFact unknown(RuntimeProfile profile, String detail) {
            return new ProfileFact(profile, true, null, false, ProcessState.UNKNOWN, detail);
        }

        public static ProfileFact unknown(RuntimeProfile profile, OwnerRecord owner,
                                          String detail) {
            return new ProfileFact(profile, true, owner, false, ProcessState.UNKNOWN, detail);
        }

        public boolean isLive() {
            return present && identityMatches && processState == ProcessState.LIVE;
        }

        public boolean isGone() {
            return present && identityMatches
                    && processState == ProcessState.GONE;
        }

        public boolean isUnknown() {
            return present && !isGone() && !isLive();
        }
    }

    /** Fixed ROOT+VPN global decision; deliberately not a generic profile framework. */
    public static final class GlobalDecision {
        public final Action action;
        public final RuntimeProfile selectedProfile;
        public final ProfileFact root;
        public final ProfileFact vpn;
        public final String errorCode;
        public final String detail;
        private final boolean cleanRoot;
        private final boolean cleanVpn;

        private GlobalDecision(Action action, RuntimeProfile selectedProfile,
                               ProfileFact root, ProfileFact vpn,
                               boolean cleanRoot, boolean cleanVpn, String detail) {
            this.action = action;
            this.selectedProfile = selectedProfile;
            this.root = root;
            this.vpn = vpn;
            this.cleanRoot = cleanRoot;
            this.cleanVpn = cleanVpn;
            this.errorCode = action == Action.BLOCK_LIVE
                    ? "product_core_owner_live"
                    : action == Action.BLOCK_UNKNOWN ? "product_core_owner_unverified" : "";
            this.detail = value(detail);
        }

        public boolean shouldClean(RuntimeProfile profile) {
            return profile == RuntimeProfile.ROOT ? cleanRoot
                    : profile == RuntimeProfile.VPN && cleanVpn;
        }

        /** Highest durable generation observed across the fixed profiles. */
        public long highestGeneration() {
            long highest = root.owner == null ? 0L : root.owner.generation;
            if (vpn.owner != null && vpn.owner.generation > highest) {
                highest = vpn.owner.generation;
            }
            return highest;
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

        /**
         * Read the complete target, or one complete owner candidate left by a
         * crash before rename. A malformed/duplicate candidate remains an
         * audit error; callers may only repair the candidate-only profile.
         */
        public static OwnerRecord readPending(File file) throws IOException {
            if (file == null) {
                throw new IOException("owner record is missing");
            }
            File target = file.getAbsoluteFile();
            if (target.isFile()) {
                return read(target);
            }
            File parent = target.getParentFile();
            File[] children = parent == null ? null : parent.listFiles();
            OwnerRecord pending = null;
            if (children != null) {
                String prefix = "." + target.getName() + ".";
                for (File child : children) {
                    String name = child.getName();
                    if (!name.startsWith(prefix) || !name.endsWith(".tmp")) {
                        continue;
                    }
                    OwnerRecord candidate = read(child);
                    if (pending != null) {
                        throw new IOException("owner record has duplicate candidates");
                    }
                    pending = candidate;
                }
            }
            if (pending == null) {
                throw new IOException("owner record is missing");
            }
            return pending;
        }

        /** Publish the durable fact before starting the process. */
        public void write(File file) throws IOException {
            if (file == null) {
                throw new IOException("owner record path is missing");
            }
            writeAtomic(file, encode().getBytes(StandardCharsets.US_ASCII));
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
                if (separator <= 0) {
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

    /**
     * Publish one small durable file through a same-directory synced candidate
     * and rename. A failed publication leaves the previous complete target in
     * place and removes the candidate; callers publish owner.properties first,
     * startup.conf second, and launch only after both files are complete.
     */
    public static void writeAtomic(File file, byte[] content) throws IOException {
        if (file == null || content == null) {
            throw new IOException("atomic publication path/content is missing");
        }
        File target = file.getAbsoluteFile();
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("atomic publication directory could not be created");
        }
        File candidate = File.createTempFile("." + target.getName() + ".", ".tmp", parent);
        boolean published = false;
        try {
            try (FileOutputStream output = new FileOutputStream(candidate)) {
                output.write(content);
                output.flush();
                output.getFD().sync();
            }
            if (!candidate.renameTo(target)) {
                throw new IOException("atomic publication rename failed: " + target);
            }
            published = true;
        } finally {
            if (!published) {
                candidate.delete();
            }
        }
    }

    /**
     * A profile containing only our same-directory publication candidates and
     * no launchable runtime/startup tree is safe to repair on the next START.
     * Empty or otherwise populated profiles stay unknown and fail closed.
     */
    public static boolean isInterruptedPublicationOnly(File profile) {
        if (profile == null || !profile.isDirectory()
                || new File(profile, RECORD_FILE).exists()
                || new File(profile, "startup.conf").exists()
                || new File(profile, "runtime").exists()
                || new File(profile, "logs").exists()
                || new File(profile, "shm").exists()) {
            return false;
        }
        File[] children = profile.listFiles();
        if (children == null || children.length == 0) {
            return false;
        }
        boolean candidateFound = false;
        String ownerPrefix = "." + RECORD_FILE + ".";
        String startupPrefix = ".startup.conf.";
        for (File child : children) {
            String name = child.getName();
            boolean ownerCandidate = name.startsWith(ownerPrefix) && name.endsWith(".tmp");
            boolean startupCandidate = name.startsWith(startupPrefix) && name.endsWith(".tmp");
            if (!ownerCandidate && !startupCandidate) {
                return false;
            }
            candidateFound = true;
        }
        return candidateFound;
    }

    /** Audit both existing profiles before any replacement or exact cleanup. */
    public static GlobalDecision decideGlobalForStart(RuntimeProfile selected,
                                                       ProfileFact root,
                                                       ProfileFact vpn,
                                                       boolean processHandleLive,
                                                       ProcessState globalProcessState) {
        RuntimeProfile chosen = selected == null ? RuntimeProfile.ROOT : selected;
        ProfileFact safeRoot = root == null
                ? ProfileFact.unknown(RuntimeProfile.ROOT, "ROOT audit is missing") : root;
        ProfileFact safeVpn = vpn == null
                ? ProfileFact.unknown(RuntimeProfile.VPN, "VPN audit is missing") : vpn;
        if (processHandleLive || globalProcessState == ProcessState.LIVE
                || safeRoot.isLive() || safeVpn.isLive()) {
            return new GlobalDecision(Action.BLOCK_LIVE, chosen, safeRoot, safeVpn,
                    false, false, "a Product Core owner is live in ROOT, VPN, or unregistered VPP");
        }
        if (globalProcessState == null || globalProcessState == ProcessState.UNKNOWN
                || safeRoot.isUnknown() || safeVpn.isUnknown()) {
            return new GlobalDecision(Action.BLOCK_UNKNOWN, chosen, safeRoot, safeVpn,
                    false, false, "Product Core global executable or profile ownership could not be verified");
        }
        ProfileFact selectedFact = chosen == RuntimeProfile.VPN ? safeVpn : safeRoot;
        boolean cleanRoot = safeRoot.isGone();
        boolean cleanVpn = safeVpn.isGone();
        if (cleanRoot || cleanVpn) {
            return new GlobalDecision(Action.CLEAN_THEN_START, chosen, safeRoot, safeVpn,
                    cleanRoot, cleanVpn,
                    "all existing Product Core owners are proven gone; exact profiles may be cleaned");
        }
        if (!selectedFact.present) {
            return new GlobalDecision(Action.FRESH_START, chosen, safeRoot, safeVpn,
                    false, false, "selected Product Core profile is absent");
        }
        return new GlobalDecision(Action.BLOCK_UNKNOWN, chosen, safeRoot, safeVpn,
                false, false, "selected Product Core profile has no clean decision");
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

    public static long processPid(int status, String output) {
        if (processState(status, output) != ProcessState.LIVE) {
            return UNKNOWN_PID;
        }
        String marker = "PRODUCT_OWNER_PID=";
        int start = output.indexOf(marker);
        if (start < 0) {
            return UNKNOWN_PID;
        }
        int valueStart = start + marker.length();
        int valueEnd = valueStart;
        while (valueEnd < output.length() && Character.isDigit(output.charAt(valueEnd))) {
            valueEnd++;
        }
        if (valueEnd == valueStart) {
            return UNKNOWN_PID;
        }
        try {
            long pid = Long.parseLong(output.substring(valueStart, valueEnd));
            return pid > 0L ? pid : UNKNOWN_PID;
        } catch (NumberFormatException error) {
            return UNKNOWN_PID;
        }
    }

    /** Build a bounded app-UID scan for an unregistered exact VPP executable. */
    public static String buildGlobalProcessAuditCommand(String executablePath,
                                                        String expectedUid) {
        String executable = absolutePath(executablePath, "Product Core executable path");
        String uid = safeScalar(expectedUid, "Product Core owner UID");
        String executableName = new File(executable).getName();
        return "set +e; "
                + "ps_output=$(ps -A -o PID,UID,args 2>/dev/null); ps_status=$?; "
                + "if [ \"$ps_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=ps; exit 125; fi; "
                + "count=0; owner_pid=; "
                + "for pid in $(printf '%s\\n' \"$ps_output\" | awk -v expected_uid="
                + shellQuote(uid)
                + " -v executable=" + shellQuote(executable)
                + " -v executable_name=" + shellQuote(executableName)
                + " -v audit_pid=\"$$\" '$1 ~ /^[0-9]+$/ && $1 != audit_pid "
                + "&& $3 != \"ps\" && (expected_uid == \"*\" || $2 == expected_uid) "
                + "{args=$0; sub(/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+/, \"\", args); "
                + "if (index(args, executable) > 0 || index(args, executable_name) > 0) print $1}'); do "
                + "proc=/proc/$pid; "
                + "exe=$(readlink \"$proc/exe\" 2>/dev/null); exe_status=$?; "
                + "if [ \"$exe_status\" -ne 0 ]; then "
                + "if [ ! -e \"$proc\" ]; then continue; fi; "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=exe; exit 125; fi; "
                + "case \"$exe\" in " + shellQuote(executable) + "|*/"
                + shellQuote(executableName) + "|*/"
                + shellQuote(executableName + " (deleted)")
                + ") ;; *) continue ;; esac; "
                + "count=$((count + 1)); owner_pid=$pid; done; "
                + "echo PRODUCT_OWNER_COUNT=$count; "
                + "if [ \"$count\" -eq 1 ]; then echo PRODUCT_OWNER_PID=$owner_pid; fi; "
                + "exit 0";
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
        String executableName = new File(executable).getName();
        String startup = record.runtimePath.substring(0,
                record.runtimePath.length() - "/runtime".length()) + "/startup.conf";
        String startupAlias = androidDataPathAlias(startup);
        String ownerEnv = "SAKAMOTO_VPP_OWNER_TOKEN=" + record.token;
        String generationEnv = "SAKAMOTO_PRODUCT_GENERATION=" + record.generation;
        String runtimeEnv = "SAKAMOTO_VPP_RUNTIME_DIR=" + record.runtimePath;
        String runtimeAliasEnv = "SAKAMOTO_VPP_RUNTIME_DIR="
                + androidDataPathAlias(record.runtimePath);
        String profileEnv = "SAKAMOTO_RUNTIME_PROFILE=" + record.profile.wireName;
        String socket = shellQuote(record.apiSocket);
        return "set +e; "
                + "ps_output=$(ps -A -o PID,UID,args 2>/dev/null); ps_status=$?; "
                + "if [ \"$ps_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=ps; exit 125; fi; "
                + "count=0; owner_pid=; "
                + "for pid in $(printf '%s\\n' \"$ps_output\" | awk -v expected_uid="
                + shellQuote(uid)
                + " -v executable=" + shellQuote(executable)
                + " -v executable_name=" + shellQuote(executableName)
                + " -v startup=" + shellQuote(startup)
                + " -v startup_alias=" + shellQuote(startupAlias)
                + " -v audit_pid=\"$$\" '$1 ~ /^[0-9]+$/ && $1 != audit_pid "
                + "&& $3 != \"ps\" && (expected_uid == \"*\" || $2 == expected_uid) "
                + "{args=$0; sub(/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+/, \"\", args); "
                + "if (index(args, executable) > 0 || index(args, startup) > 0 "
                + "|| index(args, startup_alias) > 0 || index(args, executable_name) > 0) print $1}'); do "
                + "proc=/proc/$pid; "
                + "exe=$(readlink \"$proc/exe\" 2>/dev/null); exe_status=$?; "
                + "if [ \"$exe_status\" -ne 0 ]; then "
                + "if [ ! -e \"$proc\" ]; then continue; fi; "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=exe; exit 125; fi; "
                + "case \"$exe\" in " + shellQuote(executable) + "|*/"
                + shellQuote(executableName) + "|*/"
                + shellQuote(executableName + " (deleted)")
                + ") ;; *) continue ;; esac; "
                + "cmd=$(tr '\\0' ' ' <\"$proc/cmdline\" 2>/dev/null); cmd_status=$?; "
                + "if [ \"$cmd_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=cmdline; exit 125; fi; "
                + "case \"$cmd\" in *" + shellQuote(startup) + "*|*"
                + shellQuote(startupAlias) + "*) ;; *) continue ;; esac; "
                + "env=$(tr '\\0' '\\n' <\"$proc/environ\" 2>/dev/null); env_status=$?; "
                + "if [ \"$env_status\" -ne 0 ]; then "
                + "echo PRODUCT_OWNER_AUDIT_ERROR=environ; exit 125; fi; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(ownerEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=token; exit 125; }; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(generationEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=generation; exit 125; }; "
                + "{ printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(runtimeEnv)
                + " >/dev/null || printf '%s\\n' \"$env\" | grep -F -x -- "
                + shellQuote(runtimeAliasEnv)
                + " >/dev/null; } || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=runtime; exit 125; }; "
                + "printf '%s\\n' \"$env\" | grep -F -x -- " + shellQuote(profileEnv)
                + " >/dev/null || { echo PRODUCT_OWNER_IDENTITY_MISMATCH=profile; exit 125; }; "
                + "count=$((count + 1)); owner_pid=$pid; done; "
                + "if [ -e " + socket + " ]; then echo PRODUCT_OWNER_SOCKET=present; "
                + "else echo PRODUCT_OWNER_SOCKET=absent; fi; "
                + "echo PRODUCT_OWNER_COUNT=$count; "
                + "if [ \"$count\" -eq 1 ]; then echo PRODUCT_OWNER_PID=$owner_pid; fi; "
                + "exit 0";
    }

    private static String absolutePath(String value, String label) {
        if (value == null || value.isEmpty() || !value.equals(value.trim())
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        String safe = value;
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

    private static String androidDataPathAlias(String value) {
        if (value.startsWith("/data/data/")) {
            return "/data/user/0/" + value.substring("/data/data/".length());
        }
        if (value.startsWith("/data/user/0/")) {
            return "/data/data/" + value.substring("/data/user/0/".length());
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
