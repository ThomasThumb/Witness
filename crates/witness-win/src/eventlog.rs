//! Event Log subscription. This is the only place Witness reads anything from
//! the OS, and one of only four modules with `unsafe` (see keys.rs, harden.rs,
//! notify.rs).
//!
//! SAFETY model: each subscription owns a leaked `Box<SyncSender<String>>`
//! passed to the OS as an opaque context pointer. The OS calls `callback` on
//! its own thread with that pointer. We unsubscribe (`EvtClose`) *before*
//! freeing the box in `Drop`, so the pointer is never dangling while the OS
//! can call us.
//!
//! The queue between the OS thread and the watcher is bounded twice: by
//! record count (the channel) and by bytes ([`MAX_QUEUE_BYTES`]). Any process
//! on the machine can raise a mitigation event at will, and each rendered
//! record can be up to 8 MB; an unbounded queue would let a flood of them
//! grow the watcher's memory until Windows killed it. When the queue is full
//! the record is dropped and counted; the watcher logs the count. Windows
//! keeps the record in the Event Log regardless.
//!
//! Signatures below were checked by hand against `windows` 0.61.3
//! (`Win32::System::EventLog`). If a bump changes one, this file is where it
//! shows up.

use std::{
    ffi::c_void,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{SyncSender, TrySendError},
    },
};
use windows::{
    core::HSTRING,
    Win32::System::EventLog::{
        EvtChannelConfigEnabled, EvtClose, EvtGetChannelConfigProperty, EvtOpenChannelConfig, EvtRender,
        EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents, EvtVarTypeBoolean,
        EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EVT_VARIANT,
    },
};
use witness_core::winevt::MAX_EVENT_BYTES;

/// Records the queue may hold. Real records are a few KB, so this is far more
/// than a burst (Chromium's four CIG events at start) and far less than a flood.
pub const QUEUE_RECORDS: usize = 256;

/// Bytes the queue may hold across all records; a second, tighter bound for
/// the case where records are large.
pub const MAX_QUEUE_BYTES: usize = 64 * 1024 * 1024;

static QUEUED_BYTES: AtomicUsize = AtomicUsize::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Hand a rendered record to the watcher, or drop and count it if the queue
/// is full. Never blocks: this runs on the OS's callback thread.
pub fn enqueue(tx: &SyncSender<String>, xml: String) {
    let len = xml.len();
    if QUEUED_BYTES.load(Ordering::Relaxed).saturating_add(len) > MAX_QUEUE_BYTES {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    match tx.try_send(xml) {
        Ok(()) => {
            QUEUED_BYTES.fetch_add(len, Ordering::Relaxed);
        }
        Err(TrySendError::Full(_)) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        Err(TrySendError::Disconnected(_)) => {} // receiver gone = we are shutting down
    }
}

/// The watcher calls this for every record it takes off the queue.
pub fn dequeued(len: usize) {
    QUEUED_BYTES.fetch_sub(len, Ordering::Relaxed);
}

/// Records dropped since start because the queue was full.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// One live subscription. Dropping it unsubscribes.
pub struct Subscription {
    handle: EVT_HANDLE,
    ctx: *mut SyncSender<String>,
}

// SAFETY: the OS thread only touches `ctx` through the callback; we never touch
// it concurrently ourselves. Sending the struct between our threads is fine.
unsafe impl Send for Subscription {}

impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: handle came from a successful EvtSubscribe and is closed once.
        // EvtClose on a subscription blocks until any in-flight callback has
        // returned and guarantees no further callbacks, so reclaiming the Box
        // afterwards is sound.
        unsafe {
            let _ = EvtClose(self.handle);
            drop(Box::from_raw(self.ctx));
        }
    }
}

/// Subscribe to every channel; deliver rendered XML through `tx`.
pub fn subscribe_all(channels: &[&str], tx: &SyncSender<String>) -> Result<Vec<Subscription>, String> {
    channels.iter().map(|ch| subscribe(ch, tx.clone())).collect()
}

fn subscribe(channel: &str, tx: SyncSender<String>) -> Result<Subscription, String> {
    let ctx = Box::into_raw(Box::new(tx));
    let channel_w = HSTRING::from(channel);
    let query_w = HSTRING::from("*");
    // SAFETY: the HSTRINGs outlive the call; `ctx` stays valid until Drop,
    // which closes the subscription first. No session handle, no signal event,
    // no bookmark: push delivery of future events only.
    let handle = unsafe {
        EvtSubscribe(
            None,
            None,
            &channel_w,
            &query_w,
            None,
            Some(ctx.cast_const().cast::<c_void>()),
            Some(callback),
            EvtSubscribeToFutureEvents.0,
        )
    };
    match handle {
        Ok(handle) => Ok(Subscription { handle, ctx }),
        Err(e) => {
            // SAFETY: subscription failed, so the OS never received `ctx`.
            unsafe { drop(Box::from_raw(ctx)) };
            Err(format!("subscribe {channel}: {e}"))
        }
    }
}

/// Can we open this channel at all? Used by `witness check`.
pub fn probe(channel: &str) -> Result<(), String> {
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);
    subscribe(channel, tx).map(drop)
}

/// Is Windows actually writing to this channel? Subscribing to a *disabled*
/// channel succeeds (observed on Windows 11 26200), and then nothing ever
/// arrives: `probe` alone would call a blind Witness "ok". Reading the flag
/// needs no admin. A missing channel is an error, as with `probe`.
pub fn enabled(channel: &str) -> Result<bool, String> {
    let path = HSTRING::from(channel);
    // SAFETY: `path` outlives the call; no session handle means the local machine.
    let cfg = unsafe { EvtOpenChannelConfig(None, &path, 0) }.map_err(|e| format!("config {channel}: {e}"))?;
    let mut value = EVT_VARIANT::default();
    let mut used: u32 = 0;
    let size = u32::try_from(std::mem::size_of::<EVT_VARIANT>()).map_err(|e| e.to_string())?;
    // SAFETY: `cfg` is a live channel-config handle. A boolean property fits in
    // one EVT_VARIANT with no trailing data, so `size` bytes at `value` suffice;
    // `value` and `used` outlive the call.
    let read = unsafe {
        EvtGetChannelConfigProperty(cfg, EvtChannelConfigEnabled, 0, size, Some(&raw mut value), &raw mut used)
    };
    // SAFETY: `cfg` came from a successful EvtOpenChannelConfig and is closed exactly once.
    let _ = unsafe { EvtClose(cfg) };
    read.map_err(|e| format!("config {channel}: {e}"))?;
    if i32::try_from(value.Type) != Ok(EvtVarTypeBoolean.0) {
        return Err(format!("config {channel}: Enabled has variant type {}, expected boolean", value.Type));
    }
    // SAFETY: `Type` says the union holds `BooleanVal`.
    Ok(unsafe { value.Anonymous.BooleanVal }.as_bool())
}

unsafe extern "system" fn callback(action: EVT_SUBSCRIBE_NOTIFY_ACTION, ctx: *const c_void, event: EVT_HANDLE) -> u32 {
    if action != EvtSubscribeActionDeliver || ctx.is_null() {
        return 0; // EvtSubscribeActionError: nothing we can do; `witness check` covers it
    }
    // SAFETY: `ctx` is the `Box<SyncSender<String>>` we leaked in `subscribe`,
    // and is alive because Drop closes the subscription before freeing it.
    let tx = unsafe { &*ctx.cast::<SyncSender<String>>() };
    // SAFETY: `event` is a valid handle for the duration of this callback.
    if let Some(xml) = unsafe { render_xml(event) } {
        enqueue(tx, xml);
    }
    0
}

/// Render an event handle to XML. Two calls: size, then fill.
unsafe fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used: u32 = 0;
    let mut props: u32 = 0;
    let flags = EvtRenderEventXml.0;
    // SAFETY: a null buffer with size 0 is the documented way to ask for the
    // required size; the call fails with ERROR_INSUFFICIENT_BUFFER and sets `used`.
    let _ = unsafe { EvtRender(None, event, flags, 0, None, &raw mut used, &raw mut props) };
    if used == 0 || used as usize > MAX_EVENT_BYTES {
        return None; // empty or absurd; never allocate unbounded on OS say-so
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2)];
    // SAFETY: `buf` is `used` bytes (rounded up to whole u16s) and outlives the call.
    unsafe {
        EvtRender(None, event, flags, used, Some(buf.as_mut_ptr().cast::<c_void>()), &raw mut used, &raw mut props)
            .ok()?;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

#[cfg(test)]
mod tests {
    use super::{dequeued, dropped, enabled, enqueue};

    #[test]
    fn a_full_queue_drops_and_counts_instead_of_growing() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1);
        let before = dropped();
        enqueue(&tx, "<Event>1</Event>".into());
        enqueue(&tx, "<Event>2</Event>".into()); // queue of one: dropped
        assert_eq!(dropped(), before + 1);
        let got = rx.try_recv().unwrap_or_default();
        dequeued(got.len());
        assert_eq!(got, "<Event>1</Event>", "the first record is queued");
        assert!(rx.try_recv().is_err(), "the dropped record never arrives");
        enqueue(&tx, "<Event>3</Event>".into()); // room again
        assert_eq!(dropped(), before + 1);
    }

    #[test]
    fn reads_whether_a_channel_is_enabled() {
        assert_eq!(enabled("Application"), Ok(true));
        // Analytic channels ship disabled on every Windows install.
        assert_eq!(enabled("Microsoft-Windows-Kernel-Process/Analytic"), Ok(false));
        assert!(enabled("No-Such-Channel/Operational").is_err());
    }
}
