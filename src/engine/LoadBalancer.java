package engine;

import model.Packet;

public class LoadBalancer {

    private final ThreadSafeQueue<Packet>[] workers;

    public LoadBalancer(ThreadSafeQueue<Packet>[] workers) {
        this.workers = workers;
    }

    public void dispatch(Packet pkt) {

        int hash = pkt.getTuple().hashCode();
        int index = Math.abs(hash) % workers.length;

        workers[index].push(pkt);
    }
}