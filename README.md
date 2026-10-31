# Industrial Cybersecurity Threat Detection System (DSA-II PBL)

Java project covering DSA-II Units 1-4: BST/AVL tree, max-heap priority queue and heap sort,
adjacency-list SCADA graph (BFS, DFS, components, Prim, Kruskal, Dijkstra, Bellman-Ford,
Floyd-Warshall, transitive closure), dynamic programming (0/1 knapsack, LCS, matrix chain,
resource allocation) and backtracking / branch and bound (graph colouring, sum of subsets, TSP).

## Run
    mkdir out
    javac -d out src/*.java
    java -cp out Main

Needs JDK 17 or newer. Data is simulated (fixed random seeds), so counts are repeatable;
timings differ per machine. `run_output.txt` holds the output used in the report (41 tests).
