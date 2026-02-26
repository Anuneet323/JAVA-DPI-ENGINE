package engine;

import model.Packet;
import model.FiveTuple;

public class FastPath {

    private final FlowTracker tracker;
    private final RuleManager rules;
    private final Statistics stats;

    public FastPath(FlowTracker tracker,
                    RuleManager rules,
                    Statistics stats) {

        this.tracker = tracker;
        this.rules = rules;
        this.stats = stats;
    }

    public void handle(Packet pkt) {

        FiveTuple tuple = pkt.getTuple();
        Flow flow = tracker.get(tuple);

        if (rules.isBlocked(
                flow.getAppType(),
                flow.getDomain())) {

            flow.setBlocked(true);
            stats.incrementDropped();
            return;
        }

        stats.incrementForwarded();
    }
}