import java.util.*;

/** Backtracking and branch-and-bound routines (Module 5). */
public class Backtrack {
    static long nodes;   // search-tree nodes visited, reset by each routine

    // ---- Graph colouring: assign security zones so linked devices never share a zone ----
    public static int[] colour(NetworkGraph g, int m) {
        nodes = 0;
        int[] col = new int[g.n()];
        return colourFrom(g, 0, m, col) ? col : null;
    }
    private static boolean colourFrom(NetworkGraph g, int v, int m, int[] col) {
        if (v == g.n()) return true;
        for (int c = 1; c <= m; c++) {
            nodes++;
            boolean ok = true;
            for (NetworkGraph.Edge e : g.adj.get(v)) if (col[e.to] == c) { ok = false; break; }
            if (!ok) continue;
            col[v] = c;
            if (colourFrom(g, v + 1, m, col)) return true;
            col[v] = 0;   // backtrack
        }
        return false;
    }

    // ---- Sum of subsets: pick alerts whose handling time exactly fills a shift ----
    public static List<Integer> subsetSum(int[] w, int target) {
        nodes = 0;
        List<Integer> chosen = new ArrayList<>();
        int total = 0;
        for (int x : w) total += x;
        return subset(w, 0, 0, total, target, chosen) ? chosen : null;
    }
    private static boolean subset(int[] w, int i, int sum, int remaining, int target, List<Integer> chosen) {
        nodes++;
        if (sum == target) return true;
        if (i == w.length || sum > target || sum + remaining < target) return false;   // pruning
        chosen.add(w[i]);
        if (subset(w, i + 1, sum + w[i], remaining - w[i], target, chosen)) return true;
        chosen.remove(chosen.size() - 1);                                                // backtrack
        return subset(w, i + 1, sum, remaining - w[i], target, chosen);
    }

    // ---- Travelling salesman by branch and bound: shortest inspection round ----
    static int bestCost;
    static int[] bestTour;
    public static int tsp(int[][] d, int start, int[] tourOut) {
        int n = d.length;
        nodes = 0;
        bestCost = Integer.MAX_VALUE;
        bestTour = null;
        int[] minOut = new int[n];
        for (int i = 0; i < n; i++) {
            minOut[i] = Integer.MAX_VALUE;
            for (int j = 0; j < n; j++) if (i != j) minOut[i] = Math.min(minOut[i], d[i][j]);
        }
        int[] path = new int[n];
        boolean[] used = new boolean[n];
        path[0] = start; used[start] = true;
        explore(d, minOut, path, used, 1, 0);
        System.arraycopy(bestTour, 0, tourOut, 0, n);
        return bestCost;
    }
    private static void explore(int[][] d, int[] minOut, int[] path, boolean[] used, int depth, int cost) {
        nodes++;
        int n = d.length, cur = path[depth - 1];
        if (depth == n) {
            int total = cost + d[cur][path[0]];
            if (total < bestCost) { bestCost = total; bestTour = path.clone(); }
            return;
        }
        // lower bound: every city still to leave contributes at least its cheapest outgoing link
        int bound = cost + minOut[cur];
        for (int i = 0; i < n; i++) if (!used[i]) bound += minOut[i];
        if (bound >= bestCost) return;   // bound step: prune this branch
        for (int next = 0; next < n; next++) {
            if (used[next]) continue;
            used[next] = true; path[depth] = next;
            explore(d, minOut, path, used, depth + 1, cost + d[cur][next]);
            used[next] = false;          // backtrack
        }
    }
}
