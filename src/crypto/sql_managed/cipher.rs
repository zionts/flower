//! Exact pinned AES256GCM and dalek SigningKey owners, in one locked mapping.
//! Drop the audited AES owner, then scrub the WHOLE representation: pinned
//! polyval0.6.2 autodetect has no Drop, so feature unification alone is NOT a
//! GHASH-owner cleanup proof. No unsafe byte mutation of a live cipher occurs.
use super::{Control, Error, SlotTicket, slab};
use aes_gcm::{Aes256Gcm, KeyInit};
use ed25519_dalek::SigningKey;
use zeroize::Zeroize;

#[derive(Clone, Copy)]
enum State {
    Empty,
    EnvelopeCipher,
    SigningKey,
}
pub(super) struct CipherSlot {
    storage: slab::Slab,
    state: State,
}
impl CipherSlot {
    pub(super) fn mapped_bytes() -> Result<usize, Error> {
        slab::mapped_bytes(size_of::<Aes256Gcm>().max(size_of::<SigningKey>()))
    }
    pub(super) fn validate_alignment() -> Result<(), Error> {
        if !super::slab::page_size()?
            .is_multiple_of(align_of::<Aes256Gcm>().max(align_of::<SigningKey>()))
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    pub(super) fn new(control: &Control<'_>, ticket: Option<&SlotTicket>) -> Result<Self, Error> {
        // A page-aligned mmap must also satisfy the actual pinned type alignment.
        fn requires_schedule_drop<T: zeroize::ZeroizeOnDrop>() {}
        requires_schedule_drop::<aes::Aes256>();
        Self::validate_alignment()?;
        let len = size_of::<Aes256Gcm>().max(size_of::<SigningKey>());
        let storage = slab::Slab::allocate(len, ticket, control)?;
        if !(storage.as_ptr() as usize)
            .is_multiple_of(align_of::<Aes256Gcm>().max(align_of::<SigningKey>()))
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            storage,
            state: State::Empty,
        })
    }
    pub(super) fn initialize(&mut self, key: &[u8; 32]) {
        self.clear();
        // Construction can leave transient compiler/stack/register copies;
        // these are explicitly outside the owned-state erasure guarantee.
        unsafe {
            self.storage
                .as_mut_ptr()
                .cast::<Aes256Gcm>()
                .write(Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key)));
        }
        self.state = State::EnvelopeCipher;
    }
    pub(super) fn get(&self) -> Result<&Aes256Gcm, Error> {
        if !matches!(self.state, State::EnvelopeCipher) {
            return Err(Error::SecretUnavailable);
        }
        // The mapping is aligned, initialized exactly once and is not moved.
        Ok(unsafe { &*self.storage.as_ptr().cast::<Aes256Gcm>() })
    }
    pub(super) fn initialize_signing(&mut self, seed: &[u8; 32]) {
        self.clear();
        unsafe {
            self.storage
                .as_mut_ptr()
                .cast::<SigningKey>()
                .write(SigningKey::from_bytes(seed))
        };
        self.state = State::SigningKey;
    }
    pub(super) fn signing_key(&self) -> Result<&SigningKey, Error> {
        if !matches!(self.state, State::SigningKey) {
            return Err(Error::SecretUnavailable);
        }
        Ok(unsafe { &*self.storage.as_ptr().cast::<SigningKey>() })
    }
    pub(super) fn clear(&mut self) {
        let state = self.state;
        self.state = State::Empty;
        unsafe {
            match state {
                State::Empty => (),
                State::EnvelopeCipher => {
                    std::ptr::drop_in_place(self.storage.as_mut_ptr().cast::<Aes256Gcm>())
                }
                State::SigningKey => {
                    std::ptr::drop_in_place(self.storage.as_mut_ptr().cast::<SigningKey>())
                }
            }
        }
        // After Drop the typed object is dead; raw volatile zeroization also
        // covers GHASH state, inactive union storage and page padding.
        self.storage.zeroize();
    }
    #[cfg(test)]
    pub(super) fn is_erased(&self) -> bool {
        matches!(self.state, State::Empty) && self.storage.is_erased()
    }
}
impl Drop for CipherSlot {
    fn drop(&mut self) {
        self.clear();
    }
}
