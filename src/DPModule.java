import java.util.*;

/** Dynamic programming routines (Module 4). */
public class DPModule {

    /** 0/1 knapsack: pick mitigations within an effort budget for the largest total risk reduction. */
    public static int knapsack(int[] cost, int[] benefit, int budget, List<Integer> chosen) {
        int n = cost.length;
        int[][] dp = new int[n + 1][budget + 1];
        for (int i = 1; i <= n; i++)
            for (int w = 0; w <= budget; w++) {
                dp[i][w] = dp[i - 1][w];
                if (cost[i - 1] <= w) dp[i][w] = Math.max(dp[i][w], dp[i - 1][w - cost[i - 1]] + benefit[i - 1]);
            }
        int w = budget;
        for (int i = n; i >= 1; i--)
            if (dp[i][w] != dp[i - 1][w]) { chosen.add(0, i - 1); w -= cost[i - 1]; }
        return dp[n][budget];
    }

    /** Longest common subsequence of two event logs. */
    public static List<String> lcs(String[] a, String[] b) {
        int[][] dp = new int[a.length + 1][b.length + 1];
        for (int i = 1; i <= a.length; i++)
            for (int j = 1; j <= b.length; j++)
                dp[i][j] = a[i - 1].equals(b[j - 1]) ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
        LinkedList<String> out = new LinkedList<>();
        int i = a.length, j = b.length;
        while (i > 0 && j > 0) {
            if (a[i - 1].equals(b[j - 1])) { out.addFirst(a[i - 1]); i--; j--; }
            else if (dp[i - 1][j] >= dp[i][j - 1]) i--;
            else j--;
        }
        return out;
    }

    /** Matrix chain multiplication: minimum scalar multiplications for dims p[0..n]. */
    public static int matrixChain(int[] p, StringBuilder paren) {
        int n = p.length - 1;
        int[][] m = new int[n + 1][n + 1], s = new int[n + 1][n + 1];
        for (int len = 2; len <= n; len++)
            for (int i = 1; i <= n - len + 1; i++) {
                int j = i + len - 1;
                m[i][j] = Integer.MAX_VALUE;
                for (int k = i; k < j; k++) {
                    int q = m[i][k] + m[k + 1][j] + p[i - 1] * p[k] * p[j];
                    if (q < m[i][j]) { m[i][j] = q; s[i][j] = k; }
                }
            }
        build(s, 1, n, paren);
        return m[1][n];
    }
    private static void build(int[][] s, int i, int j, StringBuilder sb) {
        if (i == j) { sb.append("A").append(i); return; }
        sb.append("(");
        build(s, i, s[i][j], sb);
        sb.append(" x ");
        build(s, s[i][j] + 1, j, sb);
        sb.append(")");
    }

    /** Resource allocation: profit[z][k] = risk reduction if zone z gets k units. Returns best total; alloc gets units per zone. */
    public static int allocate(int[][] profit, int units, int[] alloc) {
        int z = profit.length;
        int[][] dp = new int[z + 1][units + 1];
        int[][] pick = new int[z + 1][units + 1];
        for (int i = 1; i <= z; i++)
            for (int r = 0; r <= units; r++)
                for (int k = 0; k <= r && k < profit[i - 1].length; k++) {
                    int v = dp[i - 1][r - k] + profit[i - 1][k];
                    if (v > dp[i][r]) { dp[i][r] = v; pick[i][r] = k; }
                }
        int r = units;
        for (int i = z; i >= 1; i--) { alloc[i - 1] = pick[i][r]; r -= pick[i][r]; }
        return dp[z][units];
    }
}
