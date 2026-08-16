//! `constructSignBidirectionalEventNotificationV1` — the callee's own
//! constructor for its notification argument.
//!
//! HAND-WRITTEN, and the only hand-written module in this crate: a
//! constructor is Compact SOURCE (`Signet.compact`'s exported circuit), not
//! something a compiled artifact carries, so the generator cannot produce
//! it. It lives here rather than in a caller because the layout of the
//! bytes is the CALLEE's business — the payload's meaning is Signet's, and
//! a caller that packed it itself would be reimplementing the callee's
//! format at every call site.

use minocrab::v3::Circuit3;
use minocrab_std::v3::{BytesN, Uint, Vis3, B32};

use crate::SignBidirectionalEventNotification;

/// `constructSignBidirectionalEventNotificationV1(callerAddress, depth,
/// path)` with a compile-time path: the version byte (1) and the
/// `Bytes<128>` payload `callerAddress ‖ depth ‖ path[0..4] ‖ zeros`.
pub fn construct_notification_v1<V: Vis3>(
    c: &mut Circuit3,
    caller_address: &B32<V>,
    requests_path_depth: u8,
    requests_path: [u8; 4],
) -> SignBidirectionalEventNotification<V> {
    c.region("signet: notification", |c| {
        let version = V::from_public(c.constant(1u64));
        // The payload's 31-byte limbs line up with the caller address:
        // bytes 0..30 are caller.lo verbatim; bytes 31..61 pack caller.hi
        // (weight 1) with the compile-time depth ‖ path bytes at weights
        // 2^8..2^47; bytes 62..127 are zero.
        let mut packed: u64 = u64::from(requests_path_depth) << 8;
        for (i, p) in requests_path.into_iter().enumerate() {
            packed |= u64::from(p) << (16 + 8 * i);
        }
        let packed = V::from_public(c.constant(packed));
        let second = c.add(caller_address.hi, packed);
        let zero = V::from_public(c.constant(0u64));
        let payload = BytesN::from_limbs(vec![zero, zero, zero, second, caller_address.lo]);
        SignBidirectionalEventNotification {
            version: Uint::from_field_unchecked(version),
            payload,
        }
    })
}
