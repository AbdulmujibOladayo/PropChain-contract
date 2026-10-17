// Pagination helper for per-account bridge history (Issue #1104).
//
// Keeps reads bounded by slicing a Vec into zero-indexed pages.

/// Stateless paginator that slices a history Vec into fixed-size pages.
pub struct PaginatedBridgeHistory {
    /// Maximum entries the underlying store retains per account.
    pub max_entries: usize,
}

impl PaginatedBridgeHistory {
    /// Create a paginator with the given per-account cap.
    pub fn new(max_entries: usize) -> Self {
        Self { max_entries }
    }

    /// Return the slice of `history` for the requested zero-indexed `page`
    /// and `page_size`. Out-of-range pages return an empty Vec.
    pub fn paginate<T: Clone>(
        &self,
        history: &[T],
        page: usize,
        page_size: usize,
    ) -> Vec<T> {
        if page_size == 0 {
            return Vec::new();
        }
        let start = page.saturating_mul(page_size);
        if start >= history.len() {
            return Vec::new();
        }
        let end = (start + page_size).min(history.len());
        history[start..end].to_vec()
    }
}
