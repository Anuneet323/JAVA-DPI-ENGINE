package engine;

public class DpiEngine {

    private final Statistics stats;

    public DpiEngine(Statistics stats) {
        this.stats = stats;
    }

    public void shutdown() {
        stats.print();
    }
}