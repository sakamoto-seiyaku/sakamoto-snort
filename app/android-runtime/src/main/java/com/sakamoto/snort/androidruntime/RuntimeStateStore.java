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
}
