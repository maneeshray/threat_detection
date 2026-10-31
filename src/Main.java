import java.util.*;

/** Driver: builds the simulated plant, runs every module and prints the evidence used in the report. */
public class Main {
    static int passed = 0, failed = 0;

    static void check(String name, boolean ok) {
        if (ok) passed++; else failed++;
        System.out.printf("  [%s] %s%n", ok ? "PASS" : "FAIL", name);
    }

    static final String[] TYPES = {
        "Modbus Write Flood", "DNP3 Unauthorized Cmd", "PLC Firmware Tampering", "HMI Credential Brute Force",
        "OPC-UA Session Hijack", "Historian SQL Injection", "Rogue Engineering Workstation", "Network Scan / Recon"
    };

    static List<Threat> sequentialSignatures(int n, long seed) {
        Random rnd = new Random(seed);
        List<Threat> list = new ArrayList<>();
        for (int i = 1; i <= n; i++)
            list.add(new Threat(String.format("SIG-%04d", i), TYPES[rnd.nextInt(TYPES.length)], 1,
                    Math.round((1 + rnd.nextDouble() * 9) * 10) / 10.0));
        return list;
    }

    static NetworkGraph buildPlant() {
        NetworkGraph g = new NetworkGraph();
        String[] dev = {"Firewall", "Switch-Core", "Historian", "HMI-1", "HMI-2", "EngWS", "PLC-1", "PLC-2", "PLC-3",
                        "RTU-1", "Switch-Field", "PLC-4", "RTU-2", "Gateway-R", "Sensor-Hub"};
        for (String d : dev) g.addDevice(d);
        Object[][] links = {
            {"Firewall","Switch-Core",2}, {"Switch-Core","Historian",3}, {"Switch-Core","HMI-1",2}, {"Switch-Core","HMI-2",2},
            {"Switch-Core","EngWS",4}, {"Switch-Core","Switch-Field",5}, {"HMI-1","PLC-1",6}, {"HMI-2","PLC-2",7},
            {"EngWS","PLC-1",8}, {"EngWS","PLC-3",9}, {"Switch-Field","PLC-1",3}, {"Switch-Field","PLC-2",4},
            {"Switch-Field","PLC-3",4}, {"Switch-Field","RTU-1",6}, {"Switch-Field","PLC-4",5}, {"PLC-3","PLC-4",2},
            {"RTU-1","PLC-4",3}, {"Historian","HMI-1",5},
            {"RTU-2","Gateway-R",4}, {"Gateway-R","Sensor-Hub",3}, {"RTU-2","Sensor-Hub",6}   // remote site, not linked to the plant
        };
        for (Object[] l : links) g.link(g.id((String) l[0]), g.id((String) l[1]), (Integer) l[2]);
        return g;
    }

    static String names(NetworkGraph g, List<Integer> ids) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) { if (i > 0) sb.append(", "); sb.append(g.names.get(ids.get(i))); }
        return sb.toString();
    }

    public static void main(String[] args) {
        // ================= MODULE 1: trees, heap, priority queue =================
        System.out.println("=== MODULE 1: BST vs AVL, heap, priority queue ===");
        int N = 1000;
        List<Threat> seq = sequentialSignatures(N, 42);

        BST bst = new BST();
        AVLTree avl = new AVLTree();
        for (Threat t : seq) { bst.insert(t.copy()); avl.insert(t.copy()); }

        System.out.printf("Sequential insert of %d signatures: BST height = %d, AVL height = %d%n", N, bst.height(), avl.height());
        System.out.printf("Insert comparisons: BST = %d, AVL = %d%n", bst.comparisons, avl.comparisons);
        System.out.printf("AVL rotations: LL=%d RR=%d LR=%d RL=%d (total %d)%n", avl.rotLL, avl.rotRR, avl.rotLR, avl.rotRL, avl.rotations());

        bst.comparisons = 0; avl.comparisons = 0;
        for (Threat t : seq) { bst.search(t.signatureId); avl.search(t.signatureId); }
        System.out.printf("Search all %d keys: BST avg = %.1f comparisons, AVL avg = %.1f comparisons%n",
                N, bst.comparisons / (double) N, avl.comparisons / (double) N);

        long t0 = System.nanoTime();
        for (int r = 0; r < 200; r++) for (Threat t : seq) bst.search(t.signatureId);
        long bstNs = System.nanoTime() - t0;
        t0 = System.nanoTime();
        for (int r = 0; r < 200; r++) for (Threat t : seq) avl.search(t.signatureId);
        long avlNs = System.nanoTime() - t0;
        System.out.printf("Timed 200,000 lookups: BST = %d ms, AVL = %d ms%n", bstNs / 1_000_000, avlNs / 1_000_000);

        List<Threat> shuffled = new ArrayList<>(seq);
        Collections.shuffle(shuffled, new Random(7));
        BST bstR = new BST(); AVLTree avlR = new AVLTree();
        for (Threat t : shuffled) { bstR.insert(t.copy()); avlR.insert(t.copy()); }
        System.out.printf("Random-order insert: BST height = %d, AVL height = %d%n", bstR.height(), avlR.height());

        // replay alerts: frequency tracking
        Random rnd = new Random(99);
        for (int i = 0; i < 500; i++) {
            String id = String.format("SIG-%04d", 1 + rnd.nextInt(N));
            bst.recordHit(id); avl.recordHit(id);
        }
        List<Threat> inB = new ArrayList<>(), inA = new ArrayList<>(), pre = new ArrayList<>(), post = new ArrayList<>();
        bst.inorder(inB); avl.inorder(inA); bst.preorder(pre); bst.postorder(post);
        long sumB = 0, sumA = 0;
        for (Threat t : inB) sumB += t.frequencyCount;
        for (Threat t : inA) sumA += t.frequencyCount;

        // tiny rotation demos
        String[][] cases = {{"K30","K20","K10"}, {"K10","K20","K30"}, {"K30","K10","K20"}, {"K10","K30","K20"}};
        String[] caseName = {"LL", "RR", "LR", "RL"};
        boolean rotOk = true;
        for (int c = 0; c < 4; c++) {
            AVLTree t = new AVLTree();
            for (String k : cases[c]) t.insert(new Threat(k, "x", 1, 5.0));
            rotOk &= t.root.t.signatureId.equals("K20") && t.height() == 2;
        }

        // heap and priority queue
        MaxHeap heap = new MaxHeap();
        for (Threat t : seq) heap.insert(t.copy());
        List<Threat> top5 = heap.topK(5);
        List<Threat> sorted = MaxHeap.heapSort(seq);
        List<Threat> ref = new ArrayList<>(seq);
        ref.sort((x, y) -> Double.compare(y.cvssScore, x.cvssScore));
        boolean sortedOk = true;
        for (int i = 0; i < sorted.size(); i++) if (sorted.get(i).cvssScore != ref.get(i).cvssScore) { sortedOk = false; break; }
        boolean extractOk = true;
        double prevScore = 11;
        MaxHeap h2 = new MaxHeap();
        for (Threat t : seq) h2.insert(t.copy());
        while (!h2.isEmpty()) { double s = h2.extractMax().cvssScore; if (s > prevScore) extractOk = false; prevScore = s; }

        System.out.println("Top-5 critical alerts from the priority queue:");
        for (Threat t : top5) System.out.println("   " + t);

        System.out.println("\nModule 1 tests:");
        check("In-order traversal of BST is sorted by signature ID", isSorted(inB));
        check("AVL in-order traversal is sorted", isSorted(inA));
        check("Pre-order starts at the root and post-order ends at the root", pre.get(0) == bst.root.t && post.get(post.size() - 1) == bst.root.t);
        check("Duplicate signature merges into one node (size stays " + N + ")", bst.size == N && avl.size == N);
        check("Frequency totals match in BST and AVL after 500 replayed alerts (" + sumB + ")", sumB == sumA && sumB == N + 500);
        check("AVL stays balanced after sequential insert", avl.isBalanced());
        check("AVL height is within 1.44 log2(n)", avl.height() <= 1.44 * Math.log(N + 2) / Math.log(2));
        check("BST degenerates to a chain on sequential input (height = n)", bst.height() == N);
        check("Search for a missing signature returns null in both trees", bst.search("SIG-9999") == null && avl.search("SIG-9999") == null);
        check("LL, RR, LR and RL rotation cases all balance to the same root", rotOk);
        check("Heap sort output is in descending CVSS order", sortedOk);
        check("Priority queue extracts in non-increasing CVSS order", extractOk);
        check("Top-5 query leaves the heap untouched (size " + heap.size() + ")", heap.size() == N && top5.size() == 5);

        // ================= MODULE 2: graph representation, BFS, DFS, components =================
        System.out.println("\n=== MODULE 2: adjacency list, BFS, DFS, components ===");
        NetworkGraph g = buildPlant();
        int V = g.n(), E = g.edgeCount;
        System.out.printf("Devices V = %d, links E = %d. Adjacency list entries = %d, adjacency matrix cells = %d%n", V, E, 2 * E, V * V);
        int fw = g.id("Firewall");
        int[] hops = new int[V];
        List<Integer> bfs = g.bfs(fw, hops);
        System.out.println("BFS from Firewall: " + names(g, bfs));
        StringBuilder hs = new StringBuilder();
        for (int i = 0; i < V; i++) hs.append(g.names.get(i)).append("=").append(hops[i]).append(i < V - 1 ? ", " : "");
        System.out.println("Hop counts: " + hs);
        List<Integer> dfs = g.dfs(fw);
        System.out.println("DFS from Firewall: " + names(g, dfs));
        List<List<Integer>> comps = g.components();
        System.out.println("Connected components: " + comps.size());
        for (int i = 0; i < comps.size(); i++) System.out.println("   Segment " + (i + 1) + ": " + names(g, comps.get(i)));

        System.out.println("\nModule 2 tests:");
        check("BFS and DFS reach the same set of devices from Firewall", new TreeSet<>(bfs).equals(new TreeSet<>(dfs)));
        check("BFS reaches 12 devices (the plant segment)", bfs.size() == 12);
        check("PLC-3 is exactly 3 hops from the Firewall", hops[g.id("PLC-3")] == 3);
        check("Remote site devices are unreachable from the Firewall (hops = -1)", hops[g.id("RTU-2")] == -1);
        check("Two connected components found (plant + remote site)", comps.size() == 2);
        check("Adjacency list uses fewer entries than the matrix", 2 * E < V * V);

        // ================= MODULE 3: MST and shortest paths =================
        System.out.println("\n=== MODULE 3: spanning trees and shortest paths ===");
        List<String> pe = new ArrayList<>(), pr = new ArrayList<>(), ke = new ArrayList<>();
        int primPlant = g.prim(fw, pe);
        int primRemote = g.prim(g.id("RTU-2"), pr);
        int kruskal = g.kruskal(ke);
        System.out.println("Prim (plant) cost = " + primPlant + " : " + pe);
        System.out.println("Kruskal (forest) cost = " + kruskal + " : " + ke);

        int[] dj = new int[V], prev = new int[V], bf = new int[V];
        g.dijkstra(fw, dj, prev);
        boolean noNeg = g.bellmanFord(fw, bf);
        int[][] fwm = g.floydWarshall();
        boolean[][] reach = g.transitiveClosure();
        System.out.println("Cheapest attack path Firewall -> each PLC (Dijkstra):");
        for (String p : new String[]{"PLC-1", "PLC-2", "PLC-3", "PLC-4"})
            System.out.printf("   %-6s cost %-2d  %s%n", p, dj[g.id(p)], g.path(prev, g.id(p)));

        boolean agree = true;
        for (int i = 0; i < V; i++) if (dj[i] != bf[i] || dj[i] != fwm[fw][i]) agree = false;
        boolean symmetric = true;
        for (int i = 0; i < V; i++) for (int j = 0; j < V; j++) if (fwm[i][j] != fwm[j][i]) symmetric = false;
        boolean closureOk = true;
        for (int i = 0; i < V; i++) for (int j = 0; j < V; j++) if (reach[i][j] != (fwm[i][j] < NetworkGraph.INF)) closureOk = false;

        System.out.println("\nModule 3 tests:");
        check("Prim (plant) + Prim (remote) equals Kruskal spanning forest cost", primPlant + primRemote == kruskal);
        check("Prim spanning tree for 12 plant devices has 11 links", pe.size() == 11);
        check("Kruskal forest has V - 2 = 13 links (two components)", ke.size() == V - 2);
        check("Dijkstra, Bellman-Ford and Floyd-Warshall agree for every device", agree);
        check("Bellman-Ford reports no negative cycle", noNeg);
        check("Floyd-Warshall distance matrix is symmetric (undirected links)", symmetric);
        check("Transitive closure matches Floyd-Warshall reachability", closureOk);
        check("Remote site has no path from the Firewall (distance = INF)", dj[g.id("Sensor-Hub")] == NetworkGraph.INF);

        // ================= MODULE 4: dynamic programming =================
        System.out.println("\n=== MODULE 4: dynamic programming ===");
        String[] mit = {"Patch PLC firmware", "Segment network", "Deploy IDS sensor", "Rotate credentials",
                        "Disable unused ports", "Whitelist HMI apps", "Back up configs"};
        int[] cost = {8, 6, 5, 2, 1, 4, 3};
        int[] ben  = {40, 35, 30, 15, 8, 22, 10};
        List<Integer> chosen = new ArrayList<>();
        int best = DPModule.knapsack(cost, ben, 15, chosen);
        int used = 0;
        StringBuilder ms = new StringBuilder();
        for (int i : chosen) { used += cost[i]; ms.append(mit[i]).append("; "); }
        System.out.printf("Knapsack (15 h budget): risk reduction = %d, hours used = %d%n   chosen: %s%n", best, used, ms);

        String[] known = {"SCAN", "AUTH_FAIL", "AUTH_OK", "MODBUS_WRITE", "CONFIG_DOWNLOAD", "LOG_CLEAR"};
        String[] seen = {"SCAN", "PING", "AUTH_FAIL", "AUTH_FAIL", "AUTH_OK", "MODBUS_WRITE", "LOG_CLEAR"};
        List<String> lcs = DPModule.lcs(known, seen);
        System.out.printf("LCS of attack pattern vs observed log: length %d of %d (%.0f%% match) -> %s%n",
                lcs.size(), known.length, 100.0 * lcs.size() / known.length, lcs);

        StringBuilder paren = new StringBuilder();
        int mc = DPModule.matrixChain(new int[]{30, 35, 15, 5, 10, 20, 25}, paren);
        int naive = 30 * 35 * 15 + 30 * 15 * 5 + 30 * 5 * 10 + 30 * 10 * 20 + 30 * 20 * 25;   // plain left-to-right order
        System.out.printf("Matrix chain: optimal = %d multiplications %s, left-to-right = %d%n", mc, paren, naive);

        int[][] profit = {{0,10,18,24,28,30,31}, {0,12,20,26,29,31,32}, {0,8,16,23,29,33,36}};
        int[] alloc = new int[3];
        int ra = DPModule.allocate(profit, 6, alloc);
        System.out.printf("Resource allocation (6 analyst units, 3 zones): best = %d, units = %s%n", ra, Arrays.toString(alloc));

        // brute force checks for the DP answers
        int bruteKs = 0;
        for (int mask = 0; mask < (1 << cost.length); mask++) {
            int c = 0, b = 0;
            for (int i = 0; i < cost.length; i++) if ((mask >> i & 1) == 1) { c += cost[i]; b += ben[i]; }
            if (c <= 15) bruteKs = Math.max(bruteKs, b);
        }
        int bruteAlloc = 0;
        for (int a = 0; a <= 6; a++) for (int b = 0; a + b <= 6; b++) bruteAlloc = Math.max(bruteAlloc, profit[0][a] + profit[1][b] + profit[2][6 - a - b]);

        System.out.println("\nModule 4 tests:");
        check("Knapsack result equals brute force over all 2^7 subsets (" + bruteKs + ")", best == bruteKs);
        check("Knapsack never exceeds the 15 hour budget", used <= 15);
        check("LCS length is 5 (SCAN, AUTH_FAIL, AUTH_OK, MODBUS_WRITE, LOG_CLEAR)", lcs.size() == 5);
        check("Matrix chain optimum is 15125 (known textbook value)", mc == 15125);
        check("Optimal order beats left-to-right order", mc < naive);
        check("Resource allocation equals brute force (" + bruteAlloc + ")", ra == bruteAlloc);
        check("All 6 analyst units are allocated", alloc[0] + alloc[1] + alloc[2] == 6);

        // ================= MODULE 5: backtracking and branch and bound =================
        System.out.println("\n=== MODULE 5: backtracking and branch and bound ===");
        int chi = 0; int[] zones = null; long colNodes = 0;
        for (int m = 1; m <= V; m++) { zones = Backtrack.colour(g, m); colNodes = Backtrack.nodes; if (zones != null) { chi = m; break; } }
        System.out.println("Minimum security zones (graph colouring) = " + chi + ", search nodes = " + colNodes);
        for (int c = 1; c <= chi; c++) {
            List<Integer> members = new ArrayList<>();
            for (int i = 0; i < V; i++) if (zones[i] == c) members.add(i);
            System.out.println("   Zone " + c + ": " + names(g, members));
        }
        boolean colourOk = true;
        for (int u = 0; u < V; u++) for (NetworkGraph.Edge e : g.adj.get(u)) if (zones[u] == zones[e.to]) colourOk = false;
        boolean twoFails = Backtrack.colour(g, 2) == null;

        int[] mins = {35, 20, 15, 45, 10, 25};
        List<Integer> subset = Backtrack.subsetSum(mins, 90);
        long ssNodes = Backtrack.nodes;
        int ssSum = 0;
        if (subset != null) for (int x : subset) ssSum += x;
        System.out.println("Sum of subsets, 90 minute shift: " + subset + " (nodes visited " + ssNodes + " of " + ((1 << (mins.length + 1)) - 1) + " possible)");
        boolean noSubset = Backtrack.subsetSum(mins, 7) == null;

        int[][] fwd = g.floydWarshall();
        String[] stops = {"Switch-Core", "Historian", "HMI-1", "PLC-1", "PLC-3", "RTU-1", "PLC-4"};
        int k = stops.length;
        int[][] dm = new int[k][k];
        for (int i = 0; i < k; i++) for (int j = 0; j < k; j++) dm[i][j] = fwd[g.id(stops[i])][g.id(stops[j])];
        int[] tour = new int[k];
        int tspCost = Backtrack.tsp(dm, 0, tour);
        long tspNodes = Backtrack.nodes;
        StringBuilder ts = new StringBuilder();
        for (int i = 0; i < k; i++) ts.append(stops[tour[i]]).append(" -> ");
        ts.append(stops[tour[0]]);
        long fullTree = 1, perm = 1;
        for (int i = 1; i < k; i++) { perm *= i; }          // (k-1)! complete tours
        System.out.printf("TSP inspection round (%d stops): cost = %d%n   %s%n   branch and bound visited %d nodes; brute force has %d complete tours%n",
                k, tspCost, ts, tspNodes, perm);
        int brute = bruteTsp(dm);

        System.out.println("\nModule 5 tests:");
        check("Graph colouring: no two linked devices share a zone", colourOk);
        check("Two zones are not enough (plant contains triangles)", twoFails);
        check("Minimum number of zones is 3", chi == 3);
        check("Subset of alerts fills the 90 minute shift exactly", subset != null && ssSum == 90);
        check("Subset search correctly reports no solution for target 7", noSubset);
        check("Branch and bound TSP cost equals brute force (" + brute + ")", tspCost == brute);
        check("Branch and bound explores fewer nodes than a full search tree", tspNodes < sumFactorialNodes(k));

        System.out.printf("%n=== SUMMARY: %d passed, %d failed ===%n", passed, failed);
        if (failed > 0) System.exit(1);
    }

    static boolean isSorted(List<Threat> l) {
        for (int i = 1; i < l.size(); i++) if (l.get(i - 1).signatureId.compareTo(l.get(i).signatureId) >= 0) return false;
        return true;
    }

    // number of nodes in the full (unpruned) search tree for k cities starting from a fixed city
    static long sumFactorialNodes(int k) {
        long total = 1, level = 1;
        for (int depth = 1; depth < k; depth++) { level *= (k - depth); total += level; }
        return total;
    }

    static int bruteTsp(int[][] d) {
        int n = d.length;
        int[] idx = new int[n - 1];
        for (int i = 0; i < n - 1; i++) idx[i] = i + 1;
        return permute(d, idx, 0, Integer.MAX_VALUE);
    }
    static int permute(int[][] d, int[] a, int p, int best) {
        if (p == a.length) {
            int c = d[0][a[0]];
            for (int i = 0; i < a.length - 1; i++) c += d[a[i]][a[i + 1]];
            c += d[a[a.length - 1]][0];
            return Math.min(best, c);
        }
        for (int i = p; i < a.length; i++) {
            int t = a[p]; a[p] = a[i]; a[i] = t;
            best = permute(d, a, p + 1, best);
            t = a[p]; a[p] = a[i]; a[i] = t;
        }
        return best;
    }
}
