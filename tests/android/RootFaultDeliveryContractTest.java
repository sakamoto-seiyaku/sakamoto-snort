package com.sakamoto.snort.androidruntime;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class RootFaultDeliveryContractTest {
    private static void check(boolean value) {
        if (!value) throw new AssertionError("Root critical delivery failed");
    }

    private static ThreadPoolExecutor executor() {
        return new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(1, true), new ThreadPoolExecutor.AbortPolicy());
    }

    public static void main(String[] args) throws Exception {
        ThreadPoolExecutor executor = executor();
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger delivered = new AtomicInteger();
        executor.execute(() -> {
            running.countDown();
            try { release.await(); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        });
        check(running.await(1, TimeUnit.SECONDS));
        executor.execute(() -> { }); // fill the bounded queue
        AtomicBoolean accepted = new AtomicBoolean();
        Thread sender = new Thread(() -> accepted.set(RootFaultDelivery.enqueue(
                executor, delivered::incrementAndGet, () -> true)));
        sender.start();
        check(delivered.get() == 0 && sender.isAlive());
        release.countDown();
        sender.join(2000L);
        executor.shutdown();
        check(executor.awaitTermination(2, TimeUnit.SECONDS)
                && accepted.get() && delivered.get() == 1);

        for (int cancelled = 0; cancelled < 2; cancelled++) {
            ThreadPoolExecutor blocked = executor();
            CountDownLatch started = new CountDownLatch(1);
            CountDownLatch unblock = new CountDownLatch(1);
            blocked.execute(() -> {
                started.countDown();
                try { unblock.await(); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            });
            check(started.await(1, TimeUnit.SECONDS));
            blocked.execute(() -> { });
            AtomicBoolean current = new AtomicBoolean(true);
            AtomicBoolean result = new AtomicBoolean(true);
            Thread waiting = new Thread(() -> result.set(RootFaultDelivery.enqueue(
                    blocked, delivered::incrementAndGet, current::get)));
            waiting.start();
            current.set(false); // Stop or Destroy invalidates the pending event.
            waiting.join(1500L);
            check(!waiting.isAlive() && !result.get() && delivered.get() == 1);
            unblock.countDown();
            blocked.shutdown();
            check(blocked.awaitTermination(2, TimeUnit.SECONDS));
        }

        ThreadPoolExecutor full = executor();
        CountDownLatch fullStarted = new CountDownLatch(1);
        CountDownLatch fullRelease = new CountDownLatch(1);
        AtomicInteger stale = new AtomicInteger();
        AtomicInteger stops = new AtomicInteger();
        full.execute(() -> {
            fullStarted.countDown();
            try { fullRelease.await(); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        });
        check(fullStarted.await(1, TimeUnit.SECONDS));
        full.execute(stale::incrementAndGet);
        AtomicBoolean stopQueued = new AtomicBoolean();
        Thread stopSender = new Thread(() -> stopQueued.set(RootFaultDelivery.enqueue(
                full, stops::incrementAndGet, () -> true)));
        stopSender.start();
        fullRelease.countDown();
        stopSender.join(2000L);
        full.shutdown();
        check(full.awaitTermination(2, TimeUnit.SECONDS)
                && stopQueued.get() && stale.get() == 1 && stops.get() == 1);

        ThreadPoolExecutor contended = executor();
        CountDownLatch contendedStarted = new CountDownLatch(1);
        CountDownLatch contendedRelease = new CountDownLatch(1);
        AtomicInteger critical = new AtomicInteger();
        contended.execute(() -> {
            contendedStarted.countDown();
            try { contendedRelease.await(); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        });
        check(contendedStarted.await(1, TimeUnit.SECONDS));
        contended.execute(() -> { });
        AtomicBoolean criticalQueued = new AtomicBoolean();
        Thread criticalSender = new Thread(() -> criticalQueued.set(RootFaultDelivery.enqueue(
                contended, critical::incrementAndGet, () -> true)));
        criticalSender.start();
        Thread.sleep(50L); // let the critical offer wait behind the full queue
        AtomicBoolean competing = new AtomicBoolean(true);
        CountDownLatch competitionSeen = new CountDownLatch(1);
        Thread producer = new Thread(() -> {
            while (competing.get()) {
                try { contended.execute(() -> { }); }
                catch (java.util.concurrent.RejectedExecutionException fullQueue) {
                    competitionSeen.countDown();
                    Thread.yield();
                }
            }
        });
        producer.start();
        check(competitionSeen.await(1, TimeUnit.SECONDS));
        contendedRelease.countDown();
        criticalSender.join(2000L);
        competing.set(false);
        producer.join(2000L);
        contended.shutdown();
        check(contended.awaitTermination(2, TimeUnit.SECONDS)
                && criticalQueued.get() && critical.get() == 1);
        System.out.println("Root fault delivery contract: PASS");
    }
}
