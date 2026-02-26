package engine;

import java.util.LinkedList;
import java.util.Queue;

public class ThreadSafeQueue<T> {

    private final Queue<T> queue = new LinkedList<>();
    private final int capacity;

    public ThreadSafeQueue(int capacity) {
        this.capacity = capacity;
    }

    public synchronized void push(T item) {

        while (queue.size() >= capacity) {
            try { wait(); } catch (InterruptedException ignored) {}
        }

        queue.add(item);
        notifyAll();
    }

    public synchronized T pop() {

        while (queue.isEmpty()) {
            try { wait(); } catch (InterruptedException ignored) {}
        }

        T item = queue.poll();
        notifyAll();
        return item;
    }
}