#!/usr/bin/env python3
"""
Generate the "Analog to Quantum" 5-second intro sound design (Concept 1).

Timeline (exactly as scripted, nothing else):
  0:00 - 0:03  High-frequency mechanical clicking / data-rain static (sharp, busy).
  0:03         Snap cut: static stops dead. A massive, deep, warm analog-saw
               "braam" hits on the word "boy band".
  0:04 - 0:05  The braam rings out, reverb tail fading into silence.

Pure-numpy DSP -> 48 kHz stereo 16-bit WAV. Deterministic (seeded).
"""
import math
import wave
import numpy as np

SR = 48000
DUR = 8.0
N = int(SR * DUR)
CUT = 4.3  # snap-cut / braam onset (= the MCP-S reveal), in seconds
rng = np.random.default_rng(20260626)

t = np.arange(N) / SR


# ---------- helpers ----------
def fft_filter(x, sr, *, lp=None, hp=None, order=4):
    """Zero-phase Butterworth-magnitude low/high pass via FFT."""
    X = np.fft.rfft(x)
    f = np.fft.rfftfreq(len(x), 1 / sr)
    H = np.ones_like(f)
    if lp is not None:
        H = H / np.sqrt(1 + (f / lp) ** (2 * order))
    if hp is not None:
        H = H * (1 - 1 / np.sqrt(1 + (f / hp) ** (2 * order)))
    return np.fft.irfft(X * H, len(x))


def saw(freq, n):
    ph = (freq * np.arange(n) / SR) % 1.0
    return 2.0 * ph - 1.0


def envelope(points):
    """Piecewise-linear envelope from (time_s, level) breakpoints over full N."""
    ts = np.array([p[0] for p in points]) * SR
    ls = np.array([p[1] for p in points])
    return np.interp(np.arange(N), ts, ls)


# ============================================================
# 1) DATA-RAIN CLICKS  (0.0 -> CUT, then hard snap)
# ============================================================
clk_L = np.zeros(N)
clk_R = np.zeros(N)
CLEN = int(0.012 * SR)
cenv = np.exp(-np.arange(CLEN) / SR / 0.0016)  # sharp exponential decay

tt = 0.02
while tt < CUT - 0.01:
    rate = 11 + 26 * (tt / CUT) ** 1.4          # density ramps up -> "data burst"
    tt += rng.exponential(1.0 / rate)
    if tt >= CUT - 0.01:
        break
    s0 = int(tt * SR)
    amp = 0.35 + 0.65 * rng.random() ** 2       # mostly quiet ticks, occasional accents
    grain = rng.standard_normal(CLEN) * cenv * amp
    if rng.random() < 0.22:                      # occasional metallic ping
        fp = rng.uniform(3000, 6500)
        grain += 0.4 * amp * np.sin(2 * np.pi * fp * np.arange(CLEN) / SR) * np.exp(
            -np.arange(CLEN) / SR / 0.004
        )
    pan = rng.random()                           # equal-power stereo placement
    e = min(s0 + CLEN, N)
    clk_L[s0:e] += grain[: e - s0] * math.sqrt(1 - pan)
    clk_R[s0:e] += grain[: e - s0] * math.sqrt(pan)

# faint continuous static bed under the clicks
bed = rng.standard_normal(N)
flutter = 0.5 + 0.5 * fft_filter(rng.standard_normal(N), SR, lp=18)
bed = bed * flutter * 0.05
bed_L = bed * (0.5 + 0.5 * fft_filter(rng.standard_normal(N), SR, lp=9))
bed_R = bed * (0.5 + 0.5 * fft_filter(rng.standard_normal(N), SR, lp=9))

clk_L += bed_L
clk_R += bed_R

# sharp + bright: emphasise highs so it reads as "data", not "noise"
clk_L = fft_filter(clk_L, SR, hp=1500)
clk_R = fft_filter(clk_R, SR, hp=1500)

# gate everything to 0..CUT with a tiny anti-pop edge -> the SNAP cut
gate = np.ones(N)
gate[: int(0.02 * SR)] = np.linspace(0, 1, int(0.02 * SR))      # 20 ms fade-in
snap = int(CUT * SR)
gate[snap:] = 0.0
gate[snap - int(0.003 * SR): snap] = np.linspace(1, 0, int(0.003 * SR))  # 3 ms snap
clk_L *= gate
clk_R *= gate

clk_L *= 0.5
clk_R *= 0.5


# ============================================================
# 2) THE BRAAM  (onset at CUT)
# ============================================================
braam = np.zeros(N)
off = int(CUT * SR)
bn = N - off
lt = np.arange(bn) / SR  # local time from braam onset

f0 = 45.0  # deep fundamental
detunes = [-0.006, -0.003, 0.0, 0.003, 0.006, 0.011]
stack = np.zeros(bn)
for d in detunes:
    stack += saw(f0 * (1 + d), bn)
stack /= len(detunes)
stack += 0.7 * saw(f0 * 2, bn)        # octave up for body
stack += 0.9 * np.sin(2 * np.pi * f0 * lt)  # pure sub sine for chest weight

# amplitude: punch on the hit, then a continuous graceful decay to silence
# under the MCP-S reveal + subtitle (no late swell).
benv = np.interp(
    lt,
    [0.0, 0.025, 0.15, 0.7, 1.8, 2.8, 3.6],
    [0.0, 1.0, 0.92, 0.8, 0.55, 0.28, 0.0],
)
# Saturate first (steady analog timbre + harmonics), THEN apply the decay
# envelope on top -- otherwise saturation squares off the sustain and the
# graceful fade-out is lost.
tone = np.tanh(1.6 * stack)
tone = fft_filter(tone, SR, lp=320, order=3)  # warm, low
body = tone * benv

# onset transient: clicky thump that "transitions" the data burst into the braam
tlen = int(0.05 * SR)
trans = (
    rng.standard_normal(tlen) * np.exp(-np.arange(tlen) / SR / 0.006) * 0.6
    + np.sin(2 * np.pi * 70 * np.arange(tlen) / SR) * np.exp(-np.arange(tlen) / SR / 0.03)
)
body[:tlen] += trans

braam[off:] = body
braam = fft_filter(braam, SR, lp=900, order=2)  # tame highs


# ---- reverb tail (braam only): convolve with decaying-noise IR ----
def make_ir(seconds, decay):
    m = int(seconds * SR)
    ir = rng.standard_normal(m) * np.exp(-np.arange(m) / SR / decay)
    ir = fft_filter(ir, SR, lp=2500)   # damped (warm) tail
    ir[: int(0.005 * SR)] *= np.linspace(0, 1, int(0.005 * SR))
    return ir


def convolve(x, ir):
    nfft = 1 << (len(x) + len(ir) - 1).bit_length()
    y = np.fft.irfft(np.fft.rfft(x, nfft) * np.fft.rfft(ir, nfft), nfft)
    return y[: len(x)]


wet_L = convolve(braam, make_ir(2.8, 0.6))
wet_R = convolve(braam, make_ir(2.8, 0.57))
braam_L = braam + 0.45 * wet_L
braam_R = braam + 0.45 * wet_R

# The reverb refills the tail, so impose a macro fade across the whole braam:
# full through the impact, then a smooth ease-out to silence under the reveal.
mfade = np.ones(N)
fstart, fend = off + int(1.0 * SR), off + int(3.5 * SR)  # ~5.3s -> ~7.8s
mfade[fstart:fend] = np.linspace(1, 0, fend - fstart) ** 1.6
mfade[fend:] = 0.0
braam_L *= mfade
braam_R *= mfade


# ============================================================
# 3) MIX + MASTER
# ============================================================
L = clk_L + 1.25 * braam_L
R = clk_R + 1.25 * braam_R

# fade the very end into silence by 5.0s; tiny fade-in guard
tail = int(0.35 * SR)
fade = np.ones(N)
fade[-tail:] = np.linspace(1, 0, tail)
fade[: int(0.004 * SR)] = np.linspace(0, 1, int(0.004 * SR))
L *= fade
R *= fade

# soft-limit, then normalise to -1 dBFS
L = np.tanh(L)
R = np.tanh(R)
peak = max(np.abs(L).max(), np.abs(R).max())
g = 0.891 / peak
L *= g
R *= g

stereo = np.empty((N, 2), dtype=np.float32)
stereo[:, 0] = L
stereo[:, 1] = R
pcm = (stereo * 32767).astype(np.int16)

out = "assets/audio/intro-analog-to-quantum.wav"
with wave.open(out, "wb") as w:
    w.setnchannels(2)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes(pcm.tobytes())

print(f"wrote {out}  ({DUR:.0f}s, {SR} Hz stereo)")
