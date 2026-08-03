//! Custom bump allocator for zero-copy string parsing and bounded payload generation.
//! Thread-local arena ensuring no heap allocations outside designated memory pools.

use std::cell::RefCell;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Global counter tracking total bytes allocated across all arenas
static TOTAL_ARENA_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Maximum size per arena chunk (1MB)
const CHUNK_SIZE: usize = 1024 * 1024;

/// Thread-local bump allocator for zero-copy operations
pub struct Arena {
    chunks: Vec<NonNull<[u8]>>,
    current_offset: usize,
    current_chunk: Option<NonNull<[u8]>>,
}

impl Arena {
    /// Create a new arena with initial capacity
    pub fn new() -> Self {
        let mut arena = Arena {
            chunks: Vec::with_capacity(2048), // Pre-warm for ~2GB total
            current_offset: 0,
            current_chunk: None,
        };
        arena.allocate_chunk();
        arena
    }

    fn allocate_chunk(&mut self) {
        let layout = std::alloc::Layout::from_size_align(CHUNK_SIZE, 8).unwrap();
        unsafe {
            let ptr = std::alloc::alloc(layout);
            if ptr.is_null() {
                panic!("Arena: Failed to allocate chunk - memory limit exceeded");
            }
            let slice = std::slice::from_raw_parts_mut(ptr, CHUNK_SIZE);
            let non_null = NonNull::new_unchecked(slice as *mut [u8]);
            self.chunks.push(non_null);
            self.current_chunk = Some(non_null);
            self.current_offset = 0;
            TOTAL_ARENA_BYTES.fetch_add(CHUNK_SIZE, Ordering::Relaxed);
        }
    }

    /// Allocate memory from the arena without copying
    pub fn alloc(&mut self, size: usize) -> &mut [u8] {
        if self.current_offset + size > CHUNK_SIZE {
            self.allocate_chunk();
        }

        let chunk = self.current_chunk.unwrap();
        let chunk_ref = unsafe { chunk.as_mut() };
        let start = self.current_offset;
        self.current_offset += size;
        &mut chunk_ref[start..start + size]
    }

    /// Allocate and copy data into the arena
    pub fn alloc_copy(&mut self, data: &[u8]) -> &mut [u8] {
        let buf = self.alloc(data.len());
        buf.copy_from_slice(data);
        buf
    }

    /// Reset arena to reuse memory (zero-copy reset)
    pub fn reset(&mut self) {
        self.current_offset = 0;
        if let Some(chunk) = self.chunks.first() {
            self.current_chunk = Some(*chunk);
        }
    }

    /// Get total bytes currently in use
    pub fn bytes_used(&self) -> usize {
        (self.chunks.len() - 1) * CHUNK_SIZE + self.current_offset
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    pub static THREAD_ARENA: RefCell<Arena> = RefCell::new(Arena::new());
}

/// Get thread-local arena reference
pub fn get_arena() -> std::cell::Ref<'static, Arena> {
    THREAD_ARENA.try_with(|a| a.borrow()).expect("Arena access failed")
}

/// Get mutable thread-local arena reference
pub fn get_arena_mut() -> std::cell::RefMut<'static, Arena> {
    THREAD_ARENA.try_with(|a| a.borrow_mut()).expect("Arena access failed")
}

/// Check if we're approaching the 2GB limit
pub fn check_memory_pressure() -> bool {
    const LIMIT_2GB: usize = 2 * 1024 * 1024 * 1024;
    const THRESHOLD: usize = LIMIT_2GB * 90 / 100; // 90% threshold
    TOTAL_ARENA_BYTES.load(Ordering::Relaxed) > THRESHOLD
}

/// Get current total allocated bytes
pub fn get_total_allocated() -> usize {
    TOTAL_ARENA_BYTES.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_allocation() {
        let mut arena = Arena::new();
        let buf = arena.alloc(1024);
        assert_eq!(buf.len(), 1024);
    }

    #[test]
    fn test_arena_reset() {
        let mut arena = Arena::new();
        arena.alloc(1024);
        arena.reset();
        assert!(arena.bytes_used() < 1024);
    }
}
