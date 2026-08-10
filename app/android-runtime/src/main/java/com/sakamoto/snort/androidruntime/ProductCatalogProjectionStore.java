package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Durable bounded UI/evidence projection published by RuntimeService's Local
 * Product Backend. This is not product policy/config state.
 */
public final class ProductCatalogProjectionStore {
    private static final int SCHEMA_VERSION = 1;
    private static final int MAX_ROWS = 512;
    private static final String DIRECTORY = "product-catalog-projection";
    private static final String FILE = "projection.properties";
    private static final String TEMP_FILE = "projection.properties.tmp";

    private ProductCatalogProjectionStore() {}

    public static ProductCatalogFormatter.Projection read(File filesDir) {
        return readResult(filesDir).projection;
    }

    public static ReadResult readResult(File filesDir) {
        File target = projectionFile(filesDir);
        if (!target.isFile()) {
            return ReadResult.absent(ProductCatalogFormatter.loading(ProductStateSnapshot.empty()));
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(target)) {
            values.load(input);
            int schema = parseInt(values, "schemaVersion", 0);
            if (schema != SCHEMA_VERSION) {
                throw new IOException("unsupported product catalog projection schema: " + schema);
            }
            RuntimeProfile selectedProfile = RuntimeProfile.parse(values.getProperty(
                    "selectedProfile", RuntimeProfile.ROOT.wireName));
            int boundApplicationCount = parseInt(values, "boundApplicationCount", 0);
            int catalogEntryCount = parseInt(values, "catalogEntryCount", 0);
            String catalogStatus = values.getProperty("catalogStatus", "loading");
            String catalogErrorCode = values.getProperty("catalogErrorCode", "");
            String catalogErrorMessage = values.getProperty("catalogErrorMessage", "");
            String productStateStatus = values.getProperty("productStateStatus", "missing");
            String productStateErrorCode = values.getProperty("productStateErrorCode", "");
            String productStateErrorMessage = values.getProperty("productStateErrorMessage", "");
            List<ProductCatalogFormatter.EntryRow> rows = readRows(values, "rows");
            List<ProductCatalogFormatter.EntryRow> selectableRows =
                    readRows(values, "selectableRows");
            ProductCatalogFormatter.Projection projection =
                    new ProductCatalogFormatter.Projection(selectedProfile,
                            boundApplicationCount, catalogEntryCount, catalogStatus,
                            catalogErrorCode, catalogErrorMessage, rows, selectableRows,
                            firstBindable(selectableRows), firstBound(selectableRows),
                            productStateStatus, productStateErrorCode,
                            productStateErrorMessage);
            return ReadResult.valid(projection);
        } catch (Exception error) {
            return ReadResult.invalid(ProductCatalogFormatter.error(ProductStateSnapshot.empty(),
                    "product_catalog_projection_corrupt",
                    "product catalog projection could not be read; query RuntimeService"));
        }
    }

    public static void write(File filesDir, ProductCatalogFormatter.Projection projection)
            throws IOException {
        File directory = new File(filesDir, DIRECTORY);
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) {
            throw new IOException("unable to create product catalog projection directory: "
                    + directory);
        }
        ProductCatalogFormatter.Projection value = projection == null
                ? ProductCatalogFormatter.loading(ProductStateSnapshot.empty()) : projection;
        Properties values = new Properties();
        values.setProperty("schemaVersion", Integer.toString(SCHEMA_VERSION));
        values.setProperty("selectedProfile", value.selectedProfile.wireName);
        values.setProperty("boundApplicationCount",
                Integer.toString(value.boundApplicationCount));
        values.setProperty("catalogEntryCount", Integer.toString(value.catalogEntryCount));
        values.setProperty("catalogStatus", value.catalogStatus);
        values.setProperty("catalogErrorCode", value.errorCode);
        values.setProperty("catalogErrorMessage", value.errorMessage);
        values.setProperty("productStateStatus", value.productStateStatus);
        values.setProperty("productStateErrorCode", value.productStateErrorCode);
        values.setProperty("productStateErrorMessage", value.productStateErrorMessage);
        writeRows(values, "rows", value.rows);
        writeRows(values, "selectableRows", value.selectableRows);

        File temporary = new File(directory, TEMP_FILE);
        File target = new File(directory, FILE);
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            values.store(output, "Sakamoto Android Product catalog UI projection");
            output.getFD().sync();
        }
        if (!temporary.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw new IOException("unable to replace product catalog projection: " + target);
            }
            if (!temporary.renameTo(target)) {
                throw new IOException("unable to publish product catalog projection: " + target);
            }
        }
    }

    public static File projectionFile(File filesDir) {
        return new File(new File(filesDir, DIRECTORY), FILE);
    }

    private static void writeRows(Properties values, String prefix,
                                  List<ProductCatalogFormatter.EntryRow> rows) {
        List<ProductCatalogFormatter.EntryRow> safeRows = rows == null
                ? java.util.Collections.emptyList() : rows;
        int count = Math.min(safeRows.size(), MAX_ROWS);
        values.setProperty(prefix + ".count", Integer.toString(count));
        for (int i = 0; i < count; i++) {
            ProductCatalogFormatter.EntryRow row = safeRows.get(i);
            String key = prefix + "." + i + ".";
            values.setProperty(key + "subjectId", row.subjectId.encode());
            values.setProperty(key + "packageName", row.packageName);
            values.setProperty(key + "label", row.label);
            values.setProperty(key + "profileLabel", row.profileLabel);
            values.setProperty(key + "iconToken", row.iconToken);
            values.setProperty(key + "userId", Integer.toString(row.userId));
            values.setProperty(key + "fullUid", Integer.toString(row.fullUid));
            values.setProperty(key + "availability", row.availability);
            values.setProperty(key + "bound", Boolean.toString(row.bound));
            values.setProperty(key + "productStateValid",
                    Boolean.toString(row.productStateValid));
        }
    }

    private static List<ProductCatalogFormatter.EntryRow> readRows(Properties values,
                                                                  String prefix)
            throws IOException {
        int count = Math.min(parseInt(values, prefix + ".count", 0), MAX_ROWS);
        ArrayList<ProductCatalogFormatter.EntryRow> rows = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String key = prefix + "." + i + ".";
            ApplicationSubjectId subjectId = ApplicationSubjectId.parse(
                    values.getProperty(key + "subjectId", ""));
            rows.add(new ProductCatalogFormatter.EntryRow(subjectId,
                    values.getProperty(key + "packageName", ""),
                    values.getProperty(key + "label", ""),
                    values.getProperty(key + "profileLabel", ""),
                    values.getProperty(key + "iconToken", ""),
                    parseInt(values, key + "userId", subjectId.userId),
                    parseInt(values, key + "fullUid", subjectId.uid),
                    values.getProperty(key + "availability", "unavailable"),
                    Boolean.parseBoolean(values.getProperty(key + "bound", "false")),
                    Boolean.parseBoolean(values.getProperty(key + "productStateValid", "true"))));
        }
        return rows;
    }

    private static ApplicationSubjectId firstBindable(
            List<ProductCatalogFormatter.EntryRow> rows) {
        for (ProductCatalogFormatter.EntryRow row : rows) {
            if (row.canBind()) {
                return row.subjectId;
            }
        }
        return null;
    }

    private static ApplicationSubjectId firstBound(List<ProductCatalogFormatter.EntryRow> rows) {
        for (ProductCatalogFormatter.EntryRow row : rows) {
            if (row.canUnbind()) {
                return row.subjectId;
            }
        }
        return null;
    }

    private static int parseInt(Properties values, String key, int fallback) throws IOException {
        String value = values.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException error) {
            throw new IOException("invalid product catalog projection " + key, error);
        }
    }

    public static final class ReadResult {
        public final ProductCatalogFormatter.Projection projection;
        public final boolean present;
        public final boolean valid;

        private ReadResult(ProductCatalogFormatter.Projection projection, boolean present,
                           boolean valid) {
            this.projection = projection;
            this.present = present;
            this.valid = valid;
        }

        private static ReadResult absent(ProductCatalogFormatter.Projection projection) {
            return new ReadResult(projection, false, true);
        }

        private static ReadResult valid(ProductCatalogFormatter.Projection projection) {
            return new ReadResult(projection, true, true);
        }

        private static ReadResult invalid(ProductCatalogFormatter.Projection projection) {
            return new ReadResult(projection, true, false);
        }
    }
}
