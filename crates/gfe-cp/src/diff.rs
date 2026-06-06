//! A small line-level diff for `fleet diff` (spec §9): show the change between
//! the fleet's current target render and the render of its present desired
//! state. Because renders are deterministically ordered, a plain LCS line diff
//! produces a clean, stable result without an external diff crate.

/// Produce a line diff of `old` → `new`. Common lines are prefixed `  `,
/// removals `- `, additions `+ `.
pub fn unified(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());

    // dp[i][j] = LCS length of a[i..] and b[j..].
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push_str(&format!("  {}\n", a[i]));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    for line in &a[i..] {
        out.push_str(&format!("- {line}\n"));
    }
    for line in &b[j..] {
        out.push_str(&format!("+ {line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_inputs_have_no_changes() {
        let d = unified("a\nb\nc", "a\nb\nc");
        assert_eq!(d, "  a\n  b\n  c\n");
        assert!(!d.contains("\n- "));
        assert!(!d.contains("\n+ "));
    }

    #[test]
    fn shows_addition_and_removal() {
        let d = unified("a\nb\nc", "a\nB\nc\nd");
        assert!(d.contains("- b\n"));
        assert!(d.contains("+ B\n"));
        assert!(d.contains("+ d\n"));
        assert!(d.contains("  a\n"));
        assert!(d.contains("  c\n"));
    }

    #[test]
    fn from_empty_is_all_additions() {
        let d = unified("", "x\ny");
        assert_eq!(d, "+ x\n+ y\n");
    }
}
