import java.util.ArrayList;
import java.util.List;

/** Binary max-heap on CVSS score: the priority queue for alert triage (Module 1). */
public class MaxHeap {
    private final ArrayList<Threat> a = new ArrayList<>();

    // higher CVSS first; if equal, the more frequent signature wins
    private boolean higher(Threat x, Threat y) {
        if (x.cvssScore != y.cvssScore) return x.cvssScore > y.cvssScore;
        return x.frequencyCount > y.frequencyCount;
    }

    public int size() { return a.size(); }
    public boolean isEmpty() { return a.isEmpty(); }
    public Threat peek() { return a.isEmpty() ? null : a.get(0); }

    public void insert(Threat t) {
        a.add(t);
        int i = a.size() - 1;
        while (i > 0) {
            int p = (i - 1) / 2;
            if (!higher(a.get(i), a.get(p))) break;
            swap(i, p);
            i = p;
        }
    }

    public Threat extractMax() {
        if (a.isEmpty()) return null;
        Threat top = a.get(0);
        Threat last = a.remove(a.size() - 1);
        if (!a.isEmpty()) { a.set(0, last); siftDown(0); }
        return top;
    }

    private void siftDown(int i) {
        int n = a.size();
        while (true) {
            int l = 2 * i + 1, r = l + 1, best = i;
            if (l < n && higher(a.get(l), a.get(best))) best = l;
            if (r < n && higher(a.get(r), a.get(best))) best = r;
            if (best == i) return;
            swap(i, best);
            i = best;
        }
    }

    private void swap(int i, int j) { Threat t = a.get(i); a.set(i, a.get(j)); a.set(j, t); }

    /** Top-K without destroying this heap. */
    public List<Threat> topK(int k) {
        MaxHeap copy = new MaxHeap();
        copy.a.addAll(this.a);          // a valid heap stays a valid heap when copied as is
        List<Threat> out = new ArrayList<>();
        for (int i = 0; i < k && !copy.isEmpty(); i++) out.add(copy.extractMax());
        return out;
    }

    /** Heap sort: returns the threats in descending severity. */
    public static List<Threat> heapSort(List<Threat> items) {
        MaxHeap h = new MaxHeap();
        for (Threat t : items) h.insert(t);
        List<Threat> out = new ArrayList<>();
        while (!h.isEmpty()) out.add(h.extractMax());
        return out;
    }
}
