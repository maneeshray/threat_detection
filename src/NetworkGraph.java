import java.util.*;

/** SCADA/ICS topology stored as an adjacency list (Modules 2 and 3). Links are undirected and weighted. */
public class NetworkGraph {
    static final int INF = 1_000_000;

    static class Edge {
        final int to, w;
        Edge(int to, int w) { this.to = to; this.w = w; }
    }

    final List<String> names = new ArrayList<>();
    final List<List<Edge>> adj = new ArrayList<>();
    int edgeCount;

    public int addDevice(String name) {
        names.add(name);
        adj.add(new ArrayList<>());
        return names.size() - 1;
    }

    public int id(String name) { return names.indexOf(name); }
    public int n() { return names.size(); }

    public void link(int a, int b, int w) {
        adj.get(a).add(new Edge(b, w));
        adj.get(b).add(new Edge(a, w));
        edgeCount++;
    }

    // ---------- Module 2: traversal and components ----------

    /** BFS order from s; hops[] receives the hop count (-1 = unreachable). */
    public List<Integer> bfs(int s, int[] hops) {
        Arrays.fill(hops, -1);
        List<Integer> order = new ArrayList<>();
        ArrayDeque<Integer> q = new ArrayDeque<>();
        hops[s] = 0; q.add(s);
        while (!q.isEmpty()) {
            int u = q.poll();
            order.add(u);
            for (Edge e : adj.get(u))
                if (hops[e.to] == -1) { hops[e.to] = hops[u] + 1; q.add(e.to); }
        }
        return order;
    }

    public List<Integer> dfs(int s) {
        List<Integer> order = new ArrayList<>();
        dfs(s, new boolean[n()], order);
        return order;
    }
    private void dfs(int u, boolean[] seen, List<Integer> order) {
        seen[u] = true; order.add(u);
        for (Edge e : adj.get(u)) if (!seen[e.to]) dfs(e.to, seen, order);
    }

    /** Connected components = separate network segments. */
    public List<List<Integer>> components() {
        boolean[] seen = new boolean[n()];
        List<List<Integer>> comps = new ArrayList<>();
        for (int i = 0; i < n(); i++) {
            if (seen[i]) continue;
            List<Integer> c = new ArrayList<>();
            dfs(i, seen, c);
            comps.add(c);
        }
        return comps;
    }

    // ---------- Module 3: spanning trees ----------

    /** Prim's MST for the component containing s. Returns total weight; edges added to out as "A-B(w)". */
    public int prim(int s, List<String> out) {
        boolean[] in = new boolean[n()];
        PriorityQueue<int[]> pq = new PriorityQueue<>((x, y) -> x[0] - y[0]);   // {weight, to, from}
        pq.add(new int[]{0, s, -1});
        int total = 0;
        while (!pq.isEmpty()) {
            int[] cur = pq.poll();
            int u = cur[1];
            if (in[u]) continue;
            in[u] = true;
            total += cur[0];
            if (cur[2] >= 0) out.add(names.get(cur[2]) + "-" + names.get(u) + "(" + cur[0] + ")");
            for (Edge e : adj.get(u)) if (!in[e.to]) pq.add(new int[]{e.w, e.to, u});
        }
        return total;
    }

    // union-find used by Kruskal
    private int find(int[] p, int x) { while (p[x] != x) { p[x] = p[p[x]]; x = p[x]; } return x; }

    /** Kruskal's minimum spanning forest. Returns total weight. */
    public int kruskal(List<String> out) {
        List<int[]> edges = new ArrayList<>();
        for (int u = 0; u < n(); u++)
            for (Edge e : adj.get(u)) if (u < e.to) edges.add(new int[]{e.w, u, e.to});
        edges.sort((x, y) -> x[0] - y[0]);
        int[] parent = new int[n()];
        for (int i = 0; i < n(); i++) parent[i] = i;
        int total = 0;
        for (int[] e : edges) {
            int ru = find(parent, e[1]), rv = find(parent, e[2]);
            if (ru != rv) {
                parent[ru] = rv;
                total += e[0];
                out.add(names.get(e[1]) + "-" + names.get(e[2]) + "(" + e[0] + ")");
            }
        }
        return total;
    }

    // ---------- Module 3: shortest paths ----------

    /** Dijkstra from s. dist[] and prev[] are filled in. */
    public void dijkstra(int s, int[] dist, int[] prev) {
        Arrays.fill(dist, INF); Arrays.fill(prev, -1);
        dist[s] = 0;
        PriorityQueue<int[]> pq = new PriorityQueue<>((x, y) -> x[0] - y[0]);
        pq.add(new int[]{0, s});
        while (!pq.isEmpty()) {
            int[] cur = pq.poll();
            int u = cur[1];
            if (cur[0] > dist[u]) continue;
            for (Edge e : adj.get(u))
                if (dist[u] + e.w < dist[e.to]) { dist[e.to] = dist[u] + e.w; prev[e.to] = u; pq.add(new int[]{dist[e.to], e.to}); }
        }
    }

    /** Bellman-Ford from s. Returns false if a negative cycle is reachable. */
    public boolean bellmanFord(int s, int[] dist) {
        Arrays.fill(dist, INF);
        dist[s] = 0;
        for (int i = 0; i < n() - 1; i++) {
            boolean changed = false;
            for (int u = 0; u < n(); u++) {
                if (dist[u] == INF) continue;
                for (Edge e : adj.get(u))
                    if (dist[u] + e.w < dist[e.to]) { dist[e.to] = dist[u] + e.w; changed = true; }
            }
            if (!changed) break;
        }
        for (int u = 0; u < n(); u++) {
            if (dist[u] == INF) continue;
            for (Edge e : adj.get(u)) if (dist[u] + e.w < dist[e.to]) return false;
        }
        return true;
    }

    /** Floyd-Warshall all-pairs shortest paths. */
    public int[][] floydWarshall() {
        int n = n();
        int[][] d = new int[n][n];
        for (int[] row : d) Arrays.fill(row, INF);
        for (int i = 0; i < n; i++) {
            d[i][i] = 0;
            for (Edge e : adj.get(i)) d[i][e.to] = Math.min(d[i][e.to], e.w);
        }
        for (int k = 0; k < n; k++)
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    if (d[i][k] + d[k][j] < d[i][j]) d[i][j] = d[i][k] + d[k][j];
        return d;
    }

    /** Transitive closure (Warshall): can device i ever reach device j? */
    public boolean[][] transitiveClosure() {
        int n = n();
        boolean[][] r = new boolean[n][n];
        for (int i = 0; i < n; i++) { r[i][i] = true; for (Edge e : adj.get(i)) r[i][e.to] = true; }
        for (int k = 0; k < n; k++)
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    r[i][j] = r[i][j] || (r[i][k] && r[k][j]);
        return r;
    }

    public String path(int[] prev, int t) {
        LinkedList<String> p = new LinkedList<>();
        for (int v = t; v != -1; v = prev[v]) p.addFirst(names.get(v));
        return String.join(" -> ", p);
    }
}
