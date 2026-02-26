package engine;

import java.util.HashSet;
import java.util.Set;
import model.AppType;

public class RuleManager {

    private final Set<AppType> blockedApps = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();

    public void blockApp(AppType type) {
        blockedApps.add(type);
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
    }

    public boolean isBlocked(AppType type, String domain) {

        if (type != null && blockedApps.contains(type))
            return true;

        if (domain != null) {
            domain = domain.toLowerCase();
            for (String d : blockedDomains)
                if (domain.contains(d))
                    return true;
        }

        return false;
    }
}