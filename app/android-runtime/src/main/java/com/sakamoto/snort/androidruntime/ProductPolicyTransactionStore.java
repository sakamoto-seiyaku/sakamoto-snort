package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

/** Durable Draft/Commit/Apply/Checkpoint transaction repository. */
public final class ProductPolicyTransactionStore {
    public static final int SCHEMA_VERSION = 1;
    private static final String DIRECTORY = "product-transactions";
    private static final String FILE = "transactions.properties";
    private static final String TEMP_FILE = "transactions.properties.tmp";

    private ProductPolicyTransactionStore() {}

    @FunctionalInterface
    public interface Writer {
        void write(File filesDir, ProductPolicyTransactions transactions) throws IOException;
    }

    public static Writer defaultWriter() {
        return ProductPolicyTransactionStore::write;
    }

    public static ReadResult readResult(File filesDir) {
        File target = stateFile(filesDir);
        if (!target.isFile()) {
            return ReadResult.absent(new ProductPolicyTransactions(AuthoringPolicyBundle.empty()));
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(target)) {
            values.load(input);
            int schema = Integer.parseInt(values.getProperty("schemaVersion", "0"));
            if (schema != SCHEMA_VERSION) {
                return ReadResult.invalid(true, "policy_transactions_unsupported_schema",
                        "policy transaction store schema " + schema
                                + " is unsupported; upgrade the app or reset policy state");
            }

            AuthoringPolicyBundle draft = readBundle(values, "draftBundle");
            AuthoringPolicyBundle committed = readBundle(values, "committedBundle");
            boolean draftDirty = Boolean.parseBoolean(values.getProperty("draftDirty", "false"));
            long runtimeRevision = Long.parseLong(values.getProperty("runtimeRevision", "0"));
            long selectedCheckpointRevision = Long.parseLong(
                    values.getProperty("selectedCheckpointRevision", "0"));
            String runtimeSnapshotState = values.getProperty("runtimeSnapshotState", "empty");
            int checkpointCount = Integer.parseInt(values.getProperty("checkpointCount", "0"));
            if (checkpointCount < 0
                    || checkpointCount > ProductPolicyTransactions.MAX_CHECKPOINTS) {
                return ReadResult.invalid(true, "policy_transactions_corrupt",
                        "policy transaction checkpoint count is outside the retained ring");
            }
            List<ProductPolicyTransactions.Checkpoint> checkpoints = new ArrayList<>();
            for (int i = 0; i < checkpointCount; i++) {
                AuthoringPolicyBundle bundle = readBundle(values, "checkpoint." + i + ".bundle");
                String applyPayload = decode(values.getProperty(
                        "checkpoint." + i + ".applyPayload", ""));
                checkpoints.add(new ProductPolicyTransactions.Checkpoint(
                        bundle.revision, bundle, applyPayload));
            }

            return ReadResult.valid(ProductPolicyTransactions.restore(draft, committed,
                    draftDirty, runtimeRevision, selectedCheckpointRevision,
                    runtimeSnapshotState, checkpoints));
        } catch (Exception error) {
            return ReadResult.invalid(true, "policy_transactions_corrupt",
                    "policy transaction state could not be read; export diagnostics and reset policy state");
        }
    }

    public static void write(File filesDir, ProductPolicyTransactions transactions)
            throws IOException {
        File directory = new File(filesDir, DIRECTORY);
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) {
            throw new IOException("unable to create policy transaction directory: " + directory);
        }
        ProductPolicyTransactions value = transactions == null
                ? new ProductPolicyTransactions(AuthoringPolicyBundle.empty()) : transactions;
        ProductPolicyTransactions.Status status = value.status();
        Properties values = new Properties();
        values.setProperty("schemaVersion", Integer.toString(SCHEMA_VERSION));
        values.setProperty("draftBundle", encode(ProductPolicyTransactions.exportBundle(
                value.draft())));
        values.setProperty("committedBundle", encode(ProductPolicyTransactions.exportBundle(
                value.committed())));
        values.setProperty("draftDirty", Boolean.toString(status.draftDirty));
        values.setProperty("runtimeRevision", Long.toString(status.runtimeRevision));
        values.setProperty("selectedCheckpointRevision",
                Long.toString(status.selectedCheckpointRevision));
        values.setProperty("runtimeSnapshotState", status.runtimeSnapshotState);
        List<ProductPolicyTransactions.Checkpoint> checkpoints = value.checkpoints();
        values.setProperty("checkpointCount", Integer.toString(checkpoints.size()));
        for (int i = 0; i < checkpoints.size(); i++) {
            ProductPolicyTransactions.Checkpoint checkpoint = checkpoints.get(i);
            values.setProperty("checkpoint." + i + ".bundle",
                    encode(ProductPolicyTransactions.exportBundle(checkpoint.bundle)));
            values.setProperty("checkpoint." + i + ".applyPayload",
                    encode(checkpoint.applyPayload));
        }

        File temporary = new File(directory, TEMP_FILE);
        File target = new File(directory, FILE);
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            values.store(output, "Sakamoto Android policy transaction state");
            output.getFD().sync();
        }
        if (!temporary.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw new IOException("unable to replace policy transaction state: " + target);
            }
            if (!temporary.renameTo(target)) {
                throw new IOException("unable to publish policy transaction state: " + target);
            }
        }
    }

    public static File stateFile(File filesDir) {
        return new File(new File(filesDir, DIRECTORY), FILE);
    }

    private static AuthoringPolicyBundle readBundle(Properties values, String key) {
        ProductPolicyTransactions.ImportResult imported =
                ProductPolicyTransactions.importBundle(decode(values.getProperty(key, "")));
        if (!imported.ok) {
            throw new IllegalArgumentException(imported.errorCode);
        }
        return imported.bundle;
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    public static final class ReadResult {
        public final ProductPolicyTransactions transactions;
        public final boolean present;
        public final boolean valid;
        public final String errorCode;
        public final String errorMessage;

        private ReadResult(ProductPolicyTransactions transactions, boolean present,
                           boolean valid, String errorCode, String errorMessage) {
            this.transactions = transactions == null
                    ? new ProductPolicyTransactions(AuthoringPolicyBundle.empty())
                    : transactions;
            this.present = present;
            this.valid = valid;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        private static ReadResult absent(ProductPolicyTransactions transactions) {
            return new ReadResult(transactions, false, true, "", "");
        }

        private static ReadResult valid(ProductPolicyTransactions transactions) {
            return new ReadResult(transactions, true, true, "", "");
        }

        private static ReadResult invalid(boolean present, String errorCode, String errorMessage) {
            return new ReadResult(new ProductPolicyTransactions(AuthoringPolicyBundle.empty()),
                    present, false, errorCode, errorMessage);
        }
    }
}
