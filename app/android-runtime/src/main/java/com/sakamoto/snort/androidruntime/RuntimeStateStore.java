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

    public static RuntimeSnapshot read(File filesDir) {
        File target = stateFile(filesDir);
        if (!target.isFile()) {
            return RuntimeSnapshot.stopped();
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
            return new RuntimeSnapshot(
                    state, profile, values.getProperty("protocol", ""),
                    values.getProperty("version", ""), values.getProperty("artifact",
                            values.getProperty("abiEvidence", "")),
                    values.getProperty("abi", ""),
                    values.getProperty("coreHealth", values.getProperty("health", "unknown")),
                    values.getProperty("errorCode", ""), values.getProperty("errorMessage", ""),
                    Boolean.parseBoolean(values.getProperty("mayBeActive", "false")),
                    parseLong(values.getProperty("pid", "-1"), -1L),
                    parseLong(values.getProperty("generation", "0"), 0L),
                    parseLong(values.getProperty("updatedAtMillis", "0"), 0L));
        } catch (Exception error) {
            return RuntimeSnapshot.error(RuntimeProfile.ROOT, RuntimeControlProtocol.NAME, "", "", "",
                    "state_projection_corrupt",
                    "runtime state could not be read", false, -1L);
        }
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

    private static long parseLong(String value, long fallback) {
        try {
            return Long.parseLong(value);
        } catch (Exception ignored) {
            return fallback;
        }
    }
}
