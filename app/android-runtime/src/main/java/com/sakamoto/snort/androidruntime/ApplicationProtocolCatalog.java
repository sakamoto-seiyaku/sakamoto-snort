package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Generated from resources/application-protocol-catalog/catalog.tsv. */
public final class ApplicationProtocolCatalog {
    public static final int CATALOG_VERSION = 1;
    private ApplicationProtocolCatalog() {}

    public static final class Entry {
        public final int id;
        public final String key;
        public final String status;
        public final String category;
        public final String displayName;

        private Entry(int id, String key, String status, String category, String displayName) {
            this.id = id;
            this.key = key;
            this.status = status;
            this.category = category;
            this.displayName = displayName;
        }

        public boolean active() {
            return "active".equals(status);
        }
    }

    public static final int ID_RESERVED_1000 = 1000;
    public static final int ID_DNS = 1001;
    public static final int ID_HTTP = 1002;
    public static final int ID_TLS = 1003;
    public static final int ID_QUIC = 1004;
    public static final int ID_SSH = 1005;
    public static final int ID_MDNS = 1006;
    public static final int ID_SMTP = 1007;
    public static final int ID_FTP_CONTROL = 1008;
    public static final int ID_FTP_DATA = 1009;
    public static final int ID_FTPS = 1010;

    private static final Entry[] ENTRIES = new Entry[] {
        new Entry(1000, "reserved-1000", "reserved", "", "Reserved tombstone for removed prerelease placeholder"),
        new Entry(1001, "dns", "active", "infrastructure", "DNS"),
        new Entry(1002, "http", "active", "web", "HTTP"),
        new Entry(1003, "tls", "active", "web", "TLS"),
        new Entry(1004, "quic", "active", "web", "QUIC"),
        new Entry(1005, "ssh", "active", "remote-access", "SSH"),
        new Entry(1006, "mdns", "active", "infrastructure", "Multicast DNS"),
        new Entry(1007, "smtp", "active", "mail", "SMTP"),
        new Entry(1008, "ftp-control", "active", "file-transfer", "FTP control"),
        new Entry(1009, "ftp-data", "active", "file-transfer", "FTP data"),
        new Entry(1010, "ftps", "active", "file-transfer", "FTPS"),
    };

    private static final Map<String, Entry> BY_KEY = buildByKey();
    private static final Map<String, Entry> BY_MIGRATION_ALIAS = buildMigrationAliases();
    private static final Map<String, Entry> BY_PROVIDER_ALIAS = buildProviderAliases();
    private static final Map<String, List<Integer>> CATEGORY_EXPANSIONS = buildCategories();

    public static Entry byKey(String key) {
        return BY_KEY.get(key);
    }

    public static Entry byMigrationAlias(String alias) {
        return BY_MIGRATION_ALIAS.get(alias);
    }

    public static Entry byProviderAlias(String alias) {
        return BY_PROVIDER_ALIAS.get(alias);
    }

    public static List<Integer> expandCategory(String category) {
        List<Integer> ids = CATEGORY_EXPANSIONS.get(category);
        return ids == null ? Collections.emptyList() : ids;
    }

    public static List<Entry> entries() {
        List<Entry> copy = new ArrayList<Entry>();
        Collections.addAll(copy, ENTRIES);
        return Collections.unmodifiableList(copy);
    }

    private static Map<String, Entry> buildByKey() {
        Map<String, Entry> byKey = new LinkedHashMap<String, Entry>();
        for (Entry entry : ENTRIES) {
            byKey.put(entry.key, entry);
        }
        return Collections.unmodifiableMap(byKey);
    }

    private static Map<String, Entry> buildMigrationAliases() {
        Map<String, Entry> aliases = new LinkedHashMap<String, Entry>();
        aliases.put("domain-name-system", BY_KEY.get("dns"));
        aliases.put("www", BY_KEY.get("http"));
        aliases.put("ssl", BY_KEY.get("tls"));
        aliases.put("http3", BY_KEY.get("quic"));
        aliases.put("secure-shell", BY_KEY.get("ssh"));
        aliases.put("multicast-dns", BY_KEY.get("mdns"));
        aliases.put("ftp", BY_KEY.get("ftp-control"));
        return Collections.unmodifiableMap(aliases);
    }

    private static Map<String, Entry> buildProviderAliases() {
        Map<String, Entry> aliases = new LinkedHashMap<String, Entry>();
        aliases.put("lpi:dns", BY_KEY.get("dns"));
        aliases.put("lpi:http", BY_KEY.get("http"));
        aliases.put("lpi:ssl", BY_KEY.get("tls"));
        aliases.put("lpi:tls", BY_KEY.get("tls"));
        aliases.put("lpi:quic", BY_KEY.get("quic"));
        aliases.put("lpi:ssh", BY_KEY.get("ssh"));
        aliases.put("sakamoto:mdns", BY_KEY.get("mdns"));
        aliases.put("sakamoto:smtp", BY_KEY.get("smtp"));
        aliases.put("sakamoto:ftp-control", BY_KEY.get("ftp-control"));
        aliases.put("sakamoto:ftp-data", BY_KEY.get("ftp-data"));
        aliases.put("sakamoto:ftps", BY_KEY.get("ftps"));
        return Collections.unmodifiableMap(aliases);
    }

    private static Map<String, List<Integer>> buildCategories() {
        Map<String, List<Integer>> categories = new LinkedHashMap<String, List<Integer>>();
        categories.put("file-transfer", immutableIds(new int[] {1008, 1009, 1010}));
        categories.put("infrastructure", immutableIds(new int[] {1001, 1006}));
        categories.put("mail", immutableIds(new int[] {1007}));
        categories.put("remote-access", immutableIds(new int[] {1005}));
        categories.put("web", immutableIds(new int[] {1002, 1003, 1004}));
        return Collections.unmodifiableMap(categories);
    }

    private static List<Integer> immutableIds(int[] values) {
        List<Integer> ids = new ArrayList<Integer>();
        for (int value : values) {
            ids.add(Integer.valueOf(value));
        }
        return Collections.unmodifiableList(ids);
    }
}
