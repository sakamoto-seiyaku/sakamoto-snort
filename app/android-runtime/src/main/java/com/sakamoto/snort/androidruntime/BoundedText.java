package com.sakamoto.snort.androidruntime;

/** Shared low-cardinality text bound for durable status and diagnostics. */
final class BoundedText {
    static final int MAX_LENGTH = 512;

    private BoundedText() {}

    static String value(String input, int limit) {
        if (input == null) {
            return "";
        }
        String normalized = input.trim();
        return normalized.length() <= limit ? normalized : normalized.substring(0, limit);
    }
}
