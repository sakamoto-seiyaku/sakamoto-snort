package com.sakamoto.snort.androidruntime;

import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/** Critical event admission to the existing serial lifecycle executor. */
final class RootFaultDelivery {
    private RootFaultDelivery() { }

    static boolean enqueue(ThreadPoolExecutor executor, Runnable task,
                           BooleanSupplier current) {
        if (!current.getAsBoolean() || executor.isShutdown()) return false;
        try {
            executor.execute(task);
            return true;
        } catch (RejectedExecutionException full) {
            // The receiver blocks here only while a fatal event is pending.
        }
        while (current.getAsBoolean() && !executor.isShutdown()) {
            try {
                if (!executor.getQueue().offer(task, 1L, TimeUnit.SECONDS)) continue;
                if (current.getAsBoolean() && !executor.isShutdown()) return true;
                executor.getQueue().remove(task);
                return false;
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

}
