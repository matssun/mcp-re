//! Negative control for ADR-MCPRE-061 §6.1: the size, nesting and arithmetic lints are
//! ENABLED, not merely configured. Built only by
//! `scripts/clippy_ratchet_gate.py --activation-probe`, under the flags `measure()` uses.

pub fn long_fn() {
    let x0 = 0;
    let _ = x0;
    let x1 = 1;
    let _ = x1;
    let x2 = 2;
    let _ = x2;
    let x3 = 3;
    let _ = x3;
    let x4 = 4;
    let _ = x4;
    let x5 = 5;
    let _ = x5;
    let x6 = 6;
    let _ = x6;
    let x7 = 7;
    let _ = x7;
    let x8 = 8;
    let _ = x8;
    let x9 = 9;
    let _ = x9;
    let x10 = 10;
    let _ = x10;
    let x11 = 11;
    let _ = x11;
    let x12 = 12;
    let _ = x12;
    let x13 = 13;
    let _ = x13;
    let x14 = 14;
    let _ = x14;
    let x15 = 15;
    let _ = x15;
    let x16 = 16;
    let _ = x16;
    let x17 = 17;
    let _ = x17;
    let x18 = 18;
    let _ = x18;
    let x19 = 19;
    let _ = x19;
    let x20 = 20;
    let _ = x20;
    let x21 = 21;
    let _ = x21;
    let x22 = 22;
    let _ = x22;
    let x23 = 23;
    let _ = x23;
    let x24 = 24;
    let _ = x24;
    let x25 = 25;
    let _ = x25;
    let x26 = 26;
    let _ = x26;
    let x27 = 27;
    let _ = x27;
    let x28 = 28;
    let _ = x28;
    let x29 = 29;
    let _ = x29;
    let x30 = 30;
    let _ = x30;
    let x31 = 31;
    let _ = x31;
    let x32 = 32;
    let _ = x32;
    let x33 = 33;
    let _ = x33;
    let x34 = 34;
    let _ = x34;
    let x35 = 35;
    let _ = x35;
    let x36 = 36;
    let _ = x36;
    let x37 = 37;
    let _ = x37;
    let x38 = 38;
    let _ = x38;
    let x39 = 39;
    let _ = x39;
    let x40 = 40;
    let _ = x40;
    let x41 = 41;
    let _ = x41;
    let x42 = 42;
    let _ = x42;
    let x43 = 43;
    let _ = x43;
    let x44 = 44;
    let _ = x44;
    let x45 = 45;
    let _ = x45;
    let x46 = 46;
    let _ = x46;
    let x47 = 47;
    let _ = x47;
    let x48 = 48;
    let _ = x48;
    let x49 = 49;
    let _ = x49;
    let x50 = 50;
    let _ = x50;
    let x51 = 51;
    let _ = x51;
    let x52 = 52;
    let _ = x52;
    let x53 = 53;
    let _ = x53;
    let x54 = 54;
    let _ = x54;
    let x55 = 55;
    let _ = x55;
    let x56 = 56;
    let _ = x56;
    let x57 = 57;
    let _ = x57;
    let x58 = 58;
    let _ = x58;
    let x59 = 59;
    let _ = x59;
    let x60 = 60;
    let _ = x60;
    let x61 = 61;
    let _ = x61;
    let x62 = 62;
    let _ = x62;
    let x63 = 63;
    let _ = x63;
    let x64 = 64;
    let _ = x64;
    let x65 = 65;
    let _ = x65;
    let x66 = 66;
    let _ = x66;
    let x67 = 67;
    let _ = x67;
    let x68 = 68;
    let _ = x68;
    let x69 = 69;
    let _ = x69;
    let x70 = 70;
    let _ = x70;
    let x71 = 71;
    let _ = x71;
    let x72 = 72;
    let _ = x72;
    let x73 = 73;
    let _ = x73;
    let x74 = 74;
    let _ = x74;
    let x75 = 75;
    let _ = x75;
    let x76 = 76;
    let _ = x76;
    let x77 = 77;
    let _ = x77;
    let x78 = 78;
    let _ = x78;
    let x79 = 79;
    let _ = x79;
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
