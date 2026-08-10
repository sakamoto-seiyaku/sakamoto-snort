package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Separate bounded, lossy Activity repository. It is not policy/config authority. */
public final class BoundedActivityStore {
    public static final String REPOSITORY_DIRECTORY = "bounded-activity";

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
    private final ArrayList<Record> records = new ArrayList<>();
    private long evictedRecords;

    public BoundedActivityStore(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("activity capacity must be positive");
        }
        this.capacity = capacity;
    }

    public synchronized void append(Record record) {
        if (records.size() == capacity) {
            records.remove(0);
            evictedRecords++;
        }
        records.add(record);
    }

    public synchronized List<Record> records() {
        return Collections.unmodifiableList(new ArrayList<>(records));
    }

    public synchronized long evictedRecords() {
        return evictedRecords;
    }
}
