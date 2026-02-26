package engine;

import model.*;

import java.util.HashMap;
import java.util.Map;

public class FlowTracker {

    private Map<FiveTuple, Flow> flows = new HashMap<>();

    public Flow get(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, k -> new Flow());
    }
}
