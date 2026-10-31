/** One entry in the threat signature store (Module 1). */
public class Threat {
    final String signatureId;   // unique key, e.g. SIG-0042
    final String threatType;    // e.g. "Modbus Write Flood"
    int frequencyCount;         // how many times this signature has been seen
    final double cvssScore;     // severity, 0.0 - 10.0

    public Threat(String id, String type, int freq, double cvss) {
        this.signatureId = id;
        this.threatType = type;
        this.frequencyCount = freq;
        this.cvssScore = cvss;
    }

    public Threat copy() { return new Threat(signatureId, threatType, frequencyCount, cvssScore); }

    @Override public String toString() {
        return String.format("%s | %-26s | freq=%-3d | CVSS=%.1f", signatureId, threatType, frequencyCount, cvssScore);
    }
}
