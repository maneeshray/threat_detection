import java.util.List;

/** Plain binary search tree keyed on signatureId. Used as the baseline in Module 1. */
public class BST {
    static class Node {
        Threat t; Node left, right;
        Node(Threat t) { this.t = t; }
    }

    Node root;
    int size;
    long comparisons;   // key comparisons, used to compare BST and AVL fairly

    /** Insert a signature; a repeated ID just adds to its frequency count. */
    public void insert(Threat t) {
        if (root == null) { root = new Node(t); size++; return; }
        Node cur = root;
        while (true) {
            comparisons++;
            int c = t.signatureId.compareTo(cur.t.signatureId);
            if (c == 0) { cur.t.frequencyCount += t.frequencyCount; return; }
            if (c < 0) {
                if (cur.left == null) { cur.left = new Node(t); size++; return; }
                cur = cur.left;
            } else {
                if (cur.right == null) { cur.right = new Node(t); size++; return; }
                cur = cur.right;
            }
        }
    }

    public Threat search(String id) {
        Node cur = root;
        while (cur != null) {
            comparisons++;
            int c = id.compareTo(cur.t.signatureId);
            if (c == 0) return cur.t;
            cur = (c < 0) ? cur.left : cur.right;
        }
        return null;
    }

    /** Record one more sighting of an existing signature. */
    public boolean recordHit(String id) {
        Threat t = search(id);
        if (t == null) return false;
        t.frequencyCount++;
        return true;
    }

    public int height() { return height(root); }
    private int height(Node n) { return n == null ? 0 : 1 + Math.max(height(n.left), height(n.right)); }

    public void inorder(List<Threat> out)   { inorder(root, out); }
    public void preorder(List<Threat> out)  { preorder(root, out); }
    public void postorder(List<Threat> out) { postorder(root, out); }
    private void inorder(Node n, List<Threat> o)   { if (n == null) return; inorder(n.left, o); o.add(n.t); inorder(n.right, o); }
    private void preorder(Node n, List<Threat> o)  { if (n == null) return; o.add(n.t); preorder(n.left, o); preorder(n.right, o); }
    private void postorder(Node n, List<Threat> o) { if (n == null) return; postorder(n.left, o); postorder(n.right, o); o.add(n.t); }
}
