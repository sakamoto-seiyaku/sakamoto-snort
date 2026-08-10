package com.sakamoto.snort.androidruntime;

import java.util.Objects;

/** Hot-path-safe Android application identity: the complete Linux UID only. */
public final class ApplicationSubjectId implements Comparable<ApplicationSubjectId> {
    public static final int ANDROID_USER_OFFSET = 100000;
    public static final int ANDROID_APP_ID_START = 10000;
    public static final String ANDROID_VARIANT = "android";

    public final int uid;
    public final int userId;
    public final int appId;

    private ApplicationSubjectId(int uid) {
        if (uid < 0) {
            throw new IllegalArgumentException("complete Linux UID must be non-negative");
        }
        this.uid = uid;
        this.userId = uid / ANDROID_USER_OFFSET;
        this.appId = uid % ANDROID_USER_OFFSET;
        if (appId < ANDROID_APP_ID_START) {
            throw new IllegalArgumentException("UID is not an Android application UID: " + uid);
        }
    }

    public static ApplicationSubjectId fromUid(int uid) {
        return new ApplicationSubjectId(uid);
    }

    public static ApplicationSubjectId parse(String encoded) {
        if (encoded == null || !encoded.startsWith("android.uid:")) {
            throw new IllegalArgumentException("unsupported application subject id");
        }
        try {
            return fromUid(Integer.parseInt(encoded.substring("android.uid:".length())));
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("invalid Android application subject UID", error);
        }
    }

    public String encode() {
        return "android.uid:" + uid;
    }

    @Override
    public int compareTo(ApplicationSubjectId other) {
        return Integer.compare(uid, other.uid);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ApplicationSubjectId
                && uid == ((ApplicationSubjectId) other).uid;
    }

    @Override
    public int hashCode() {
        return Objects.hash(uid);
    }

    @Override
    public String toString() {
        return encode();
    }
}
