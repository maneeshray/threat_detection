import java.util.List;

/** Self-balancing AVL tree (Module 1). Same interface as BST so the two can be compared. */
public class AVLTree {
    static class Node {
        Threat t; Node left, right; int h = 1;
        Node(Threat t) { this.t = t; }
    }

    Node root;
    int size;
    long comparisons;
    int rotLL, rotRR, rotLR, rotRL;   // how often each rotation case fired

    private int h(Node n) { return n == null ? 0 : n.h; }
    private void update(Node n) { n.h = 1 + Math.max(h(n.left), h(n.right)); }
    private int balance(Node n) { return n == null ? 0 : h(n.left) - h(n.right); }

    private Node rotateRight(Node y) {
        Node x = y.left;
        y.left = x.right;
        x.right = y;
        update(y); update(x);
        return x;
    }
    private Node rotateLeft(Node x) {
        Node y = x.right;
        x.right = y.left;
        y.left = x;
        update(x); update(y);
        return y;
    }

    public void insert(Threat t) { root = insert(root, t); }

    private Node insert(Node n, Threat t) {
        if (n == null) { size++; return new Node(t); }
        comparisons++;
        int c = t.signatureId.compareTo(n.t.signatureId);
        if (c < 0) n.left = insert(n.left, t);
        else if (c > 0) n.right = insert(n.right, t);
        else { n.t.frequencyCount += t.frequencyCount; return n; }

        update(n);
        int bal = balance(n);
        if (bal > 1 && t.signatureId.compareTo(n.left.t.signatureId) < 0)  { rotLL++; return rotateRight(n); }          // LL
        if (bal < -1 && t.signatureId.compareTo(n.right.t.signatureId) > 0) { rotRR++; return rotateLeft(n); }          // RR
        if (bal > 1 && t.signatureId.compareTo(n.left.t.signatureId) > 0)  { rotLR++; n.left = rotateLeft(n.left); return rotateRight(n); }   // LR
        if (bal < -1 && t.signatureId.compareTo(n.right.t.signatureId) < 0) { rotRL++; n.right = rotateRight(n.right); return rotateLeft(n); } // RL
        return n;
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

    public boolean recordHit(String id) {
        Threat t = search(id);
        if (t == null) return false;
        t.frequencyCount++;
        return true;
    }

    public int height() { return h(root); }
    public int rotations() { return rotLL + rotRR + rotLR + rotRL; }

    /** True if every node's balance factor is within -1..1. */
    public boolean isBalanced() { return isBalanced(root); }
    private boolean isBalanced(Node n) {
        if (n == null) return true;
        return Math.abs(balance(n)) <= 1 && isBalanced(n.left) && isBalanced(n.right);
    }

    public void inorder(List<Threat> out) { inorder(root, out); }
    private void inorder(Node n, List<Threat> o) { if (n == null) return; inorder(n.left, o); o.add(n.t); inorder(n.right, o); }
}
