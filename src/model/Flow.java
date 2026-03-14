package model;

public class Flow {

    private AppType appType = AppType.UNKNOWN;
    private String domain;
    private boolean blocked;

    public AppType getAppType() { return appType; }
    public void setAppType(AppType appType) { this.appType = appType; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public boolean isBlocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }
}