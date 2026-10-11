package com.sakamoto.snort.androidruntime;

/** One fixed, generation-bound native Root listener failure signal. */
final class RootFaultEvent {
    private static final String PREFIX = "SAKAMOTO_ROOT_FAULT_V1 ";
    final long generation;
    final int lane;
    final int errno;
    final String reason;

    private RootFaultEvent(long generation, int lane, int errno, String reason) {
        this.generation = generation;
        this.lane = lane;
        this.errno = errno;
        this.reason = reason;
    }

    static RootFaultEvent parse(byte[] bytes, int length) {
        if (length < PREFIX.length() || length >= 160) return null;
        String text = new String(bytes, 0, length, java.nio.charset.StandardCharsets.US_ASCII);
        if (!text.startsWith(PREFIX)) return null;
        String[] fields = text.substring(PREFIX.length()).split(" ", -1);
        if (fields.length != 4 || !fields[0].startsWith("generation=")
                || !fields[1].startsWith("lane=")
                || !fields[2].startsWith("errno=")
                || !fields[3].startsWith("reason=")) return null;
        String reason = fields[3].substring(7);
        if (!reason.equals("identity") && !reason.equals("recv")
                && !reason.equals("discard") && !reason.equals("epoll")
                && !reason.equals("diagnostic")) return null;
        try {
            long generation = Long.parseLong(fields[0].substring(11));
            int lane = Integer.parseInt(fields[1].substring(5));
            int errno = Integer.parseInt(fields[2].substring(6));
            if (generation <= 0 || lane < 0 || lane > 3 || errno < 0) return null;
            return new RootFaultEvent(generation, lane, errno, reason);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    String detail() {
        return "Root NFQUEUE lane " + lane + " failed: " + reason + " errno=" + errno;
    }

    boolean belongsToGeneration(long channelGeneration) {
        return generation == channelGeneration;
    }
}
