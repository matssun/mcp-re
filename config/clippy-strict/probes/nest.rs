//! Negative control for the nesting rule (ADR-MCPRE-061 §6.5, C-5): depth 2 is accepted,
//! depth 3 is rejected. Built only by `scripts/clippy_ratchet_gate.py --nesting-probe`.
#![allow(clippy::collapsible_if)]

pub fn depth_two(a: bool, b: bool) -> u32 {
    if a {
        if b {
            return 2;
        }
    }
    0
}

pub fn depth_three(a: bool, b: bool, c: bool) -> u32 {
    if a {
        if b {
            if c {
                return 3;
            }
        }
    }
    0
}
