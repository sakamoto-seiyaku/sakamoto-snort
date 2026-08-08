package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/** Atomic durable projection consumed after Activity close/recreate. */
public final class RuntimeStateStore {
    private static final String DIRECTORY = "runtime-state";
    private static final String FILE = "snapshot.properties";
    private static final String TEMP_FILE = "snapshot.properties.tmp";

    private RuntimeStateStore() {}

    /**
     * Durable projection write boundary. RuntimeService injects this seam so
     * a failed persistence operation can be exercised without replacing the
     * Android filesystem.
     */
    @FunctionalInterface
    public interface Writer {
        void write(File filesDir, RuntimeSnapshot snapshot) throws IOException;
    }

    /** Return the production writer used by RuntimeService's default constructor. */
    public static Writer defaultWriter() {
        return RuntimeStateStore::write;
    }

    /**
     * Read the durable projection while retaining whether it was present and
     * parseable. Supervisors must not infer that an invalid/missing
     * projection means the default ROOT profile is inactive.
     */
    public static ReadResult readResult(File filesDir) {
        File target = stateFile(filesDir);
        if (!target.isFile()) {
            return ReadResult.absent(RuntimeSnapshot.stopped());
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(target)) {
            values.load(input);
            int schema = Integer.parseInt(values.getProperty("schemaVersion", "0"));
            if (schema != 1 && schema != RuntimeSnapshot.SCHEMA_VERSION) {
                throw new IOException("unsupported runtime snapshot schema: " + schema);
            }
            RuntimeProfile profile = RuntimeProfile.parse(values.getProperty("profile", "root"));
            String state = values.getProperty("state", RuntimeSnapshot.STATE_STOPPED);
            RuntimeSnapshot snapshot = new RuntimeSnapshot(
                    state, profile, values.getProperty("protocol", ""),
                    values.getProperty("version", ""), values.getProperty("artifact",
                            values.getProperty("abiEvidence", "")),
                    values.getProperty("abi", ""),
                    values.getProperty("coreHealth", values.getProperty("health", "unknown")),
                    values.getProperty("errorCode", ""), values.getProperty("errorMessage", ""),
                    Boolean.parseBoolean(values.getProperty("mayBeActive", "false")),
                    parseLong(values, "pid", -1L),
                    parseLong(values, "generation", 0L),
                    parseLong(values, "updatedAtMillis", 0L));
            return ReadResult.valid(snapshot);
        } catch (Exception error) {
            return ReadResult.invalid(RuntimeSnapshot.error(RuntimeProfile.ROOT,
                    RuntimeControlProtocol.NAME, "", "", "", "state_projection_corrupt",
                    "runtime state could not be read", false, -1L));
        }
    }

    /** Compatibility reader for existing product callers. */
    public static RuntimeSnapshot read(File filesDir) {
        return readResult(filesDir).snapshot;
    }

    public static void write(File filesDir, RuntimeSnapshot snapshot) throws IOException {
        File directory = new File(filesDir, DIRECTORY);
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) {
            throw new IOException("unable to create runtime state directory: " + directory);
        }
        Properties values = new Properties();
        for (java.util.Map.Entry<String, String> entry : snapshot.encode().entrySet()) {
            values.setProperty(entry.getKey(), entry.getValue());
        }
        File temporary = new File(directory, TEMP_FILE);
        File target = new File(directory, FILE);
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            values.store(output, "Sakamoto Android RuntimeService product projection");
            output.getFD().sync();
        }
        if (!temporary.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw new IOException("unable to replace runtime state: " + target);
            }
            if (!temporary.renameTo(target)) {
                throw new IOException("unable to publish runtime state: " + target);
            }
        }
    }

    public static File stateFile(File filesDir) {
        return new File(new File(filesDir, DIRECTORY), FILE);
    }

    private static long parseLong(Properties values, String key, long fallback) throws IOException {
        String value = values.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException error) {
            throw new IOException("invalid runtime snapshot " + key, error);
        }
    }

    /** Public persistence seam exposing projection health without Android APIs. */
    public static final class ReadResult {
        public final RuntimeSnapshot snapshot;
        public final boolean present;
        public final boolean valid;

        private ReadResult(RuntimeSnapshot snapshot, boolean present, boolean valid) {
            this.snapshot = snapshot;
            this.present = present;
            this.valid = valid;
        }

        private static ReadResult absent(RuntimeSnapshot snapshot) {
            return new ReadResult(snapshot, false, true);
        }

        private static ReadResult valid(RuntimeSnapshot snapshot) {
            return new ReadResult(snapshot, true, true);
        }

        private static ReadResult invalid(RuntimeSnapshot snapshot) {
            return new ReadResult(snapshot, true, false);
        }
    }

    /**
     * Android-free lifecycle policy around the durable projection boundary.
     * RuntimeService uses the same gate as host tests so persistence faults
     * cannot silently turn into an ordinary lifecycle transition.
     */
    public static final class PersistenceGate {
        public static final class Result {
            public final boolean persisted;
            public final boolean recovered;
            public final boolean launchAllowed;
            public final boolean cleanupAllowed;
            public final boolean cleanupRequired;
            public final RuntimeSnapshot snapshot;
            public final String detail;

            private Result(boolean persisted, boolean recovered, boolean launchAllowed,
                           boolean cleanupAllowed, boolean cleanupRequired,
                           RuntimeSnapshot snapshot, String detail) {
                this.persisted = persisted;
                this.recovered = recovered;
                this.launchAllowed = launchAllowed;
                this.cleanupAllowed = cleanupAllowed;
                this.cleanupRequired = cleanupRequired;
                this.snapshot = snapshot;
                this.detail = detail == null ? "" : detail;
            }
        }

        private final Writer writer;
        private RuntimeSnapshot snapshot;
        private boolean persistenceUnavailable;

        public PersistenceGate(Writer writer, RuntimeSnapshot initial) {
            this.writer = writer == null ? RuntimeStateStore.defaultWriter() : writer;
            this.snapshot = initial == null ? RuntimeSnapshot.stopped() : initial;
        }

        public synchronized boolean isPersistenceUnavailable() {
            return persistenceUnavailable;
        }

        public synchronized RuntimeSnapshot snapshot() {
            return snapshot;
        }

        /** Seed the gate from the projection read during service creation. */
        public synchronized void setSnapshot(RuntimeSnapshot initial) {
            if (!persistenceUnavailable && initial != null) {
                snapshot = initial;
            }
        }

        /**
         * Attempt one lifecycle projection. A failed STARTING write never
         * permits launch; a failed RUNNING write asks the caller to clean the
         * already-launched owner; STOPPING/STOPPED failures still allow the
         * caller to finish bounded cleanup.
         */
        public synchronized Result publish(File filesDir, RuntimeSnapshot next,
                                           boolean processMayBeActive) {
            if (next == null) {
                throw new IllegalArgumentException("runtime snapshot is required");
            }
            if (persistenceUnavailable && RuntimeSnapshot.STATE_STARTING.equals(next.state)) {
                RuntimeSnapshot local = failureSnapshot(next, "start blocked until durable recovery",
                        processMayBeActive);
                snapshot = local;
                return result(false, false, false, false, false, local, "start blocked");
            }
            try {
                writer.write(filesDir, next);
                snapshot = next;
                boolean launchAllowed = !RuntimeSnapshot.STATE_STARTING.equals(next.state)
                        || !persistenceUnavailable;
                return result(true, false, launchAllowed,
                        cleanupState(next), false, snapshot, "");
            } catch (IOException error) {
                RuntimeSnapshot local = failureSnapshot(next,
                        "durable runtime projection unavailable"
                                + (error.getMessage() == null ? "" : ": " + error.getMessage()),
                        processMayBeActive);
                persistenceUnavailable = true;
                snapshot = local;
                boolean cleanupRequired = RuntimeSnapshot.STATE_RUNNING.equals(next.state)
                        && (processMayBeActive || next.mayBeActive);
                return result(false, false, false,
                        cleanupRequired || cleanupState(next), cleanupRequired, local,
                        local.errorMessage);
            }
        }

        /**
         * Clear the unavailable latch only after the caller has completed a
         * global ownership audit and reports that no live owner is ambiguous.
         */
        public synchronized Result recover(File filesDir, boolean ownershipSafe) {
            if (!persistenceUnavailable || !ownershipSafe) {
                return result(false, false, false, false, false, snapshot,
                        ownershipSafe ? "durable projection is already available"
                                : "ownership audit is not safe");
            }
            try {
                writer.write(filesDir, snapshot);
                persistenceUnavailable = false;
                return result(true, true, true, false, false, snapshot,
                        "durable projection recovered");
            } catch (IOException error) {
                RuntimeSnapshot local = failureSnapshot(snapshot,
                        "durable runtime projection unavailable during recovery"
                                + (error.getMessage() == null ? "" : ": " + error.getMessage()),
                        snapshot != null && snapshot.mayBeActive);
                persistenceUnavailable = true;
                snapshot = local;
                return result(false, false, false, false, false, local, local.errorMessage);
            }
        }

        private static boolean cleanupState(RuntimeSnapshot value) {
            return RuntimeSnapshot.STATE_STOPPING.equals(value.state)
                    || RuntimeSnapshot.STATE_STOPPED.equals(value.state);
        }

        private static RuntimeSnapshot failureSnapshot(RuntimeSnapshot attempted, String detail,
                                                       boolean processMayBeActive) {
            boolean mayBeActive = attempted != null && !RuntimeSnapshot.STATE_STOPPED.equals(
                    attempted.state) && (RuntimeSnapshot.STATE_STARTING.equals(attempted.state)
                    ? processMayBeActive : attempted.mayBeActive);
            long pid = mayBeActive && attempted != null && attempted.pid > 0L
                    ? attempted.pid : -1L;
            RuntimeSnapshot basis = attempted == null ? RuntimeSnapshot.stopped() : attempted;
            return RuntimeSnapshot.error(basis.profile, basis.protocol, basis.version,
                    basis.artifact, basis.abi, "runtime_state_persistence_unavailable", detail,
                    mayBeActive, pid, basis.generation);
        }

        private static Result result(boolean persisted, boolean recovered, boolean launchAllowed,
                                     boolean cleanupAllowed, boolean cleanupRequired,
                                     RuntimeSnapshot snapshot, String detail) {
            return new Result(persisted, recovered, launchAllowed, cleanupAllowed,
                    cleanupRequired, snapshot, detail);
        }
    }
}
