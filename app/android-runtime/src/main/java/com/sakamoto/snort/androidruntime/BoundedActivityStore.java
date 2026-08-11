package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Separate bounded, lossy Activity repository. It is not policy/config authority. */
public final class BoundedActivityStore {
    public static final String REPOSITORY_DIRECTORY = "bounded-activity";
    public static final int DEFAULT_CAPACITY = 256;

    public static final class Record {
        public final long timestampMillis;
        public final ApplicationSubjectId subjectId;
        public final String verdict;
        public final String reason;

        public Record(long timestampMillis, ApplicationSubjectId subjectId,
                      String verdict, String reason) {
            if (subjectId == null) {
                throw new IllegalArgumentException("subjectId is required");
            }
            this.timestampMillis = timestampMillis;
            this.subjectId = subjectId;
            this.verdict = BoundedText.value(verdict == null ? "" : verdict,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.reason = BoundedText.value(reason == null ? "" : reason,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
        }
    }

    private final int capacity;
    private final ArrayList<ActivityItem> activityItems = new ArrayList<>();
    private long evictedRecords;

    public BoundedActivityStore(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("activity capacity must be positive");
        }
        this.capacity = capacity;
    }

    public synchronized void append(Record record) {
        append(new ActivityItem(record.subjectId, "", "", record.timestampMillis,
                "", "", 0, "unknown", "unknown", 1L, 0L, record.verdict,
                record.reason, 0L, 0L, 0, "bounded_activity_store", true));
    }

    public synchronized void append(ActivityItem item) {
        if (item == null) {
            throw new IllegalArgumentException("activity item is required");
        }
        if (activityItems.size() == capacity) {
            activityItems.remove(0);
            evictedRecords++;
        }
        activityItems.add(item);
    }

    public synchronized List<Record> records() {
        ArrayList<Record> records = new ArrayList<>();
        for (ActivityItem item : activityItems) {
            records.add(new Record(item.timestampMillis, item.subjectId,
                    item.verdict, item.winner));
        }
        return Collections.unmodifiableList(records);
    }

    public synchronized List<ActivityItem> activityItems() {
        return Collections.unmodifiableList(new ArrayList<>(activityItems));
    }

    public synchronized List<ActivityItem> activityItemsFor(
            ApplicationSubjectId subjectId, int limit) {
        if (subjectId == null) {
            throw new IllegalArgumentException("subjectId is required");
        }
        int max = Math.max(0, limit);
        ArrayList<ActivityItem> out = new ArrayList<>();
        for (int index = activityItems.size() - 1; index >= 0 && out.size() < max; index--) {
            ActivityItem item = activityItems.get(index);
            if (subjectId.equals(item.subjectId)) {
                out.add(item);
            }
        }
        return Collections.unmodifiableList(out);
    }

    public synchronized int capacity() {
        return capacity;
    }

    public synchronized long evictedRecords() {
        return evictedRecords;
    }
}
