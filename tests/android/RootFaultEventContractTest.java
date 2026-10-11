package com.sakamoto.snort.androidruntime;

import java.nio.charset.StandardCharsets;

public final class RootFaultEventContractTest {
    private static void check(boolean value) {
        if (!value) throw new AssertionError("Root fault event contract failed");
    }

    private static RootFaultEvent parse(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        return RootFaultEvent.parse(bytes, bytes.length);
    }

    public static void main(String[] args) {
        RootFaultEvent event = parse(
                "SAKAMOTO_ROOT_FAULT_V1 generation=1792 lane=0 errno=9 reason=epoll");
        check(event != null && event.generation == 1792L && event.lane == 0
                && event.errno == 9 && event.detail().contains("epoll"));
        check(event.belongsToGeneration(1792L) && !event.belongsToGeneration(1793L));
        check(parse("SAKAMOTO_ROOT_FAULT_V1 generation=1792 lane=0 errno=9 reason=epoll extra=1") == null);
        check(parse("SAKAMOTO_ROOT_FAULT_V1 generation=0 lane=4 errno=-1 reason=epoll") == null);
        check(parse("SAKAMOTO_ROOT_FAULT_V1 generation=1792 lane=0 errno=9 reason=other") == null);
        System.out.println("Root fault event contract: PASS");
    }
}
