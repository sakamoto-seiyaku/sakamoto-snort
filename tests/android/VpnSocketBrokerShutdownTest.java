package com.sakamoto.snort.androidruntime;

import java.util.concurrent.CountDownLatch;

/** Real thread deadline/refusal regression; no Android socket behavior claim. */
public final class VpnSocketBrokerShutdownTest {
    public static void main(String[] args) throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread pending = new Thread(() -> {
            entered.countDown();
            // Model an authorization call that has not yet returned, including
            // implementations that cannot be cancelled by Thread.interrupt().
            while (release.getCount() != 0) {
                try { release.await(); }
                catch (InterruptedException ignored) { }
            }
        });
        pending.start();
        entered.await();
        pending.interrupt();
        if (VpnSocketBroker.awaitExit(pending, 20))
            throw new AssertionError("a live broker was reported closed");
        release.countDown();
        if (!VpnSocketBroker.awaitExit(pending, 1000))
            throw new AssertionError("retry failed after authorization returned");
        if (VpnSocketBroker.awaitExit(Thread.currentThread(), 20))
            throw new AssertionError("a broker cannot certify its own thread exit");
        System.out.println("broker shutdown deadline and retry PASS");
    }
}
