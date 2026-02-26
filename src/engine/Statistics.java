package engine;

import java.util.concurrent.atomic.AtomicInteger;

public class Statistics {

    private final AtomicInteger total = new AtomicInteger();
    private final AtomicInteger forwarded = new AtomicInteger();
    private final AtomicInteger dropped = new AtomicInteger();

    public void incrementTotal() { total.incrementAndGet(); }
    public void incrementForwarded() { forwarded.incrementAndGet(); }
    public void incrementDropped() { dropped.incrementAndGet(); }

    public int getTotal() { return total.get(); }
    public int getForwarded() { return forwarded.get(); }
    public int getDropped() { return dropped.get(); }

    public void print() {
        System.out.println("Total Packets : " + getTotal());
        System.out.println("Forwarded     : " + getForwarded());
        System.out.println("Dropped       : " + getDropped());
    }
}