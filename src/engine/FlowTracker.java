package engine;

import model.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FlowTracker {

    private final Map<FiveTuple, Flow> flows = new ConcurrentHashMap<>();

    public Flow get(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, k -> new Flow());
    }
}
