package com.sakamoto.snort.vpnlite;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

/** Owns the durable, low-cardinality runtime projection used by Product UI. */
public final class RuntimeStateStore {
    private static final String DIRECTORY = "runtime-state";
    private static final String FILE = "snapshot.properties";
    private static final String TEMP_FILE = "snapshot.properties.tmp";

    private RuntimeStateStore() {}

    public static RuntimeSnapshot read(File filesDir) {
        File stateFile = stateFile(filesDir);
        if (!stateFile.isFile()) {
            return RuntimeSnapshot.stopped();
        }

        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(stateFile)) {
            properties.load(input);
            int schemaVersion = Integer.parseInt(properties.getProperty("schemaVersion", "0"));
            if (schemaVersion != RuntimeSnapshot.SCHEMA_VERSION) {
                throw new IOException("unsupported runtime snapshot schema: " + schemaVersion);
            }
            return new RuntimeSnapshot(
                    properties.getProperty("state", RuntimeSnapshot.STATE_STOPPED),
                    properties.getProperty("profile", RuntimeSnapshot.PROFILE_ROOT),
                    properties.getProperty("version", ""),
                    properties.getProperty("abi", ""),
                    properties.getProperty("health", "unknown"),
                    properties.getProperty("errorCode", ""),
                    properties.getProperty("errorMessage", ""),
                    parseLong(properties.getProperty("pid", "-1"), -1L),
                    parseLong(properties.getProperty("updatedAtMillis", "0"), 0L));
        } catch (Exception ignored) {
            return RuntimeSnapshot.startupError(RuntimeSnapshot.PROFILE_ROOT, "", "",
                    "state_projection_corrupt", "runtime state could not be read");
        }
    }

    public static void write(File filesDir, RuntimeSnapshot snapshot) throws IOException {
        File directory = new File(filesDir, DIRECTORY);
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) {
            throw new IOException("unable to create runtime state directory: " + directory);
        }

        Properties properties = new Properties();
        properties.setProperty("schemaVersion", Integer.toString(RuntimeSnapshot.SCHEMA_VERSION));
        properties.setProperty("state", snapshot.state);
        properties.setProperty("profile", snapshot.profile);
        properties.setProperty("version", snapshot.version);
        properties.setProperty("abi", snapshot.abi);
        properties.setProperty("health", snapshot.health);
        properties.setProperty("errorCode", snapshot.errorCode);
        properties.setProperty("errorMessage", snapshot.errorMessage);
        properties.setProperty("pid", Long.toString(snapshot.pid));
        properties.setProperty("updatedAtMillis", Long.toString(snapshot.updatedAtMillis));

        File temporary = new File(directory, TEMP_FILE);
        File target = new File(directory, FILE);
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            properties.store(output, "Sakamoto RuntimeService product projection");
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
