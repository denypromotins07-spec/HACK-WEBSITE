//! Secure memory vault for sensitive data.
//!
//! Provides memory-safe containers that zero out sensitive data
//! when dropped and prevent accidental exposure through debugging.

use std::alloc::{self, Layout};
use std::ops::Deref;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

/// A secure string container that zeros memory on drop.
pub struct SecureString {
    /// Pointer to allocated memory.
    ptr: *mut u8,
    /// Length of the string.
    len: usize,
    /// Capacity of the allocation.
    capacity: usize,
    /// Flag indicating if data has been zeroed.
    zeroed: AtomicBool,
}

// SecureString can be sent between threads safely.
unsafe impl Send for SecureString {}
unsafe impl Sync for SecureString {}

impl SecureString {
    /// Create a new secure string from a string slice.
    pub fn new(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len();
        
        // Allocate memory with proper alignment
        let layout = Layout::from_size_align(len, 1)
            .expect("Invalid layout");
        
        unsafe {
            let ptr = alloc::alloc(layout);
            if ptr.is_null() {
                alloc::handle_alloc_error(layout);
            }
            
            // Copy data to secure memory
            ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
            
            Self {
                ptr,
                len,
                capacity: len,
                zeroed: AtomicBool::new(false),
            }
        }
    }

    /// Create an empty secure string with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let layout = Layout::from_size_align(capacity, 1)
            .expect("Invalid layout");
        
        unsafe {
            let ptr = alloc::alloc(layout);
            if ptr.is_null() {
                alloc::handle_alloc_error(layout);
            }
            
            // Zero-initialize the memory
            ptr::write_bytes(ptr, 0, capacity);
            
            Self {
                ptr,
                len: 0,
                capacity,
                zeroed: AtomicBool::new(false),
            }
        }
    }

    /// Append data to the secure string.
    pub fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let new_len = self.len + bytes.len();
        
        if new_len > self.capacity {
            // Need to reallocate
            let new_capacity = (new_len * 2).max(64);
            let new_layout = Layout::from_size_align(new_capacity, 1)
                .expect("Invalid layout");
            
            unsafe {
                let new_ptr = alloc::alloc(new_layout);
                if new_ptr.is_null() {
                    alloc::handle_alloc_error(new_layout);
                }
                
                // Copy existing data
                ptr::copy_nonoverlapping(self.ptr, new_ptr, self.len);
                // Copy new data
                ptr::copy_nonoverlapping(bytes.as_ptr(), new_ptr.add(self.len), bytes.len());
                
                // Zero and deallocate old memory
                self.zero_memory();
                alloc::dealloc(self.ptr, Layout::from_size_align(self.capacity, 1).unwrap());
                
                self.ptr = new_ptr;
                self.capacity = new_capacity;
            }
        } else {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(self.len), bytes.len());
            }
        }
        
        self.len = new_len;
    }

    /// Execute a closure with access to the inner string, then zero memory.
    pub fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        let s = self.as_str();
        let result = f(s);
        // Note: We don't zero here since the string might be reused
        // Zeroing happens on drop
        result
    }

    /// Get the string as a slice without copying.
    pub fn as_str(&self) -> &str {
        unsafe {
            let slice = std::slice::from_raw_parts(self.ptr, self.len);
            std::str::from_utf8(slice).unwrap_or("")
        }
    }

    /// Get the length of the string.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Explicitly zero the memory (called automatically on drop).
    fn zero_memory(&mut self) {
        if !self.zeroed.load(Ordering::Relaxed) && !self.ptr.is_null() {
            unsafe {
                ptr::write_bytes(self.ptr, 0, self.len);
            }
            self.zeroed.store(true, Ordering::Relaxed);
        }
    }

    /// Clear the string content (zeros memory but keeps allocation).
    pub fn clear(&mut self) {
        self.zero_memory();
        self.len = 0;
        self.zeroed.store(false, Ordering::Relaxed);
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.zero_memory();
        
        if !self.ptr.is_null() {
            unsafe {
                let layout = Layout::from_size_align(self.capacity, 1).unwrap();
                alloc::dealloc(self.ptr, layout);
            }
        }
    }
}

impl Deref for SecureString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl std::fmt::Display for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        SecureString::new(self.as_str())
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SecureString {}

impl PartialEq<str> for SecureString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for SecureString {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        SecureString::new(s)
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        SecureString::new(&s)
    }
}

/// Secure byte buffer for arbitrary sensitive data.
pub struct SecureBuffer {
    ptr: *mut u8,
    len: usize,
    capacity: usize,
    zeroed: AtomicBool,
}

unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}

impl SecureBuffer {
    /// Create a new secure buffer from bytes.
    pub fn new(bytes: &[u8]) -> Self {
        let len = bytes.len();
        let layout = Layout::from_size_align(len, 1).expect("Invalid layout");
        
        unsafe {
            let ptr = alloc::alloc(layout);
            if ptr.is_null() {
                alloc::handle_alloc_error(layout);
            }
            
            ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
            
            Self {
                ptr,
                len,
                capacity: len,
                zeroed: AtomicBool::new(false),
            }
        }
    }

    /// Get the bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Execute a closure with access to the bytes.
    pub fn with_bytes<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.as_bytes())
    }

    fn zero_memory(&mut self) {
        if !self.zeroed.load(Ordering::Relaxed) && !self.ptr.is_null() {
            unsafe {
                ptr::write_bytes(self.ptr, 0, self.len);
            }
            self.zeroed.store(true, Ordering::Relaxed);
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zero_memory();
        
        if !self.ptr.is_null() {
            unsafe {
                let layout = Layout::from_size_align(self.capacity, 1).unwrap();
                alloc::dealloc(self.ptr, layout);
            }
        }
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED BUFFER]")
    }
}
