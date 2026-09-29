//! Negative control for ADR-MCPRE-061 §6.1: the size, nesting and arithmetic lints are
//! ENABLED, not merely configured. Built only by
//! `scripts/clippy_ratchet_gate.py --activation-probe`, under the flags `measure()` uses.

pub fn long_fn() {
    let _ = 0;
    let _ = 1;
    let _ = 2;
    let _ = 3;
    let _ = 4;
    let _ = 5;
    let _ = 6;
    let _ = 7;
    let _ = 8;
    let _ = 9;
    let _ = 10;
    let _ = 11;
    let _ = 12;
    let _ = 13;
    let _ = 14;
    let _ = 15;
    let _ = 16;
    let _ = 17;
    let _ = 18;
    let _ = 19;
    let _ = 20;
    let _ = 21;
    let _ = 22;
    let _ = 23;
    let _ = 24;
    let _ = 25;
    let _ = 26;
    let _ = 27;
    let _ = 28;
    let _ = 29;
    let _ = 30;
    let _ = 31;
    let _ = 32;
    let _ = 33;
    let _ = 34;
    let _ = 35;
    let _ = 36;
    let _ = 37;
    let _ = 38;
    let _ = 39;
    let _ = 40;
    let _ = 41;
    let _ = 42;
    let _ = 43;
    let _ = 44;
    let _ = 45;
    let _ = 46;
    let _ = 47;
    let _ = 48;
    let _ = 49;
    let _ = 50;
    let _ = 51;
    let _ = 52;
    let _ = 53;
    let _ = 54;
    let _ = 55;
    let _ = 56;
    let _ = 57;
    let _ = 58;
    let _ = 59;
    let _ = 60;
    let _ = 61;
    let _ = 62;
    let _ = 63;
    let _ = 64;
    let _ = 65;
    let _ = 66;
    let _ = 67;
    let _ = 68;
    let _ = 69;
}

#[allow(clippy::collapsible_if)]
pub fn deep(a: bool, b: bool, c: bool) -> u32 {
    if a {
        if b {
            if c {
                return 3;
            }
        }
    }
    0
}

// Unconstrained integer addition: overflow semantics are not statically evident. The
// neighbours are the forms the lint deliberately EXCLUDES, so a probe that started
// reporting them would be flagging the wrong thing.
pub fn unbounded(x: u64) -> u64 {
    x + 1
}

pub fn saturating(x: u64) -> u64 {
    x.saturating_add(1)
}

pub fn wrapping(x: u64) -> u64 {
    x.wrapping_add(1)
}

pub fn floating(x: f64) -> f64 {
    x + 1.0
}

pub fn wrapped(x: std::num::Wrapping<u64>) -> std::num::Wrapping<u64> {
    x + std::num::Wrapping(1)
}

pub const fn constant() -> u64 {
    2 + 2
}
