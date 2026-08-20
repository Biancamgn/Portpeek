"""
fingerprint.py -- OS fingerprinting (the "OS fingerprinting" requirement).

A deliberately honest heuristic rather than a pretend-NMAP full stack. We send
one probe and read two cheap signals from the reply:

  * initial TTL  -- OS families ship distinctive defaults. Because routers
                    decrement TTL by 1 per hop, we round the observed value UP
                    to the nearest known default (64, 128, 255) before matching.
  * TCP window   -- a secondary hint that helps separate the tie cases.

This is presented in the report as a *guess with confidence*, which is both
accurate and defensible in the demo. NMAP's real fingerprinting is far deeper;
we say so rather than oversell.
"""

from __future__ import annotations

from scapy.all import IP, ICMP, TCP, sr1


# Rounded-up initial TTL -> likely OS family.
_TTL_TABLE = {
    64:  "Linux / Unix",
    128: "Windows",
    255: "Network device / Solaris",
}

# Common initial TCP window sizes as a tie-breaker hint.
_WINDOW_HINTS = {
    8192:  "Windows",
    64240: "Windows (10/11 era)",
    65535: "Linux/BSD or Windows",
    5840:  "Linux (older)",
    29200: "Linux (modern)",
    14600: "Linux",
}


def _round_up_ttl(ttl: int) -> int:
    """Snap an observed TTL up to the nearest known initial value."""
    for base in (64, 128, 255):
        if ttl <= base:
            return base
    return 255


def fingerprint(ip: str, open_port: int | None = None,
                timeout: float = 2.0, verbose: bool = False) -> tuple[str, str]:
    """
    Guess the OS of `ip`.

    Prefers a TCP SYN to a known-open port (gives us TTL *and* window). Falls
    back to ICMP echo (TTL only) if no open port is known or TCP is silent.

    Returns (os_guess, confidence) where confidence is "low"/"medium"/"high".
    """
    ttl = None
    window = None

    if open_port is not None:
        resp = sr1(IP(dst=ip) / TCP(dport=open_port, flags="S"),
                   timeout=timeout, verbose=False)
        if resp is not None and resp.haslayer(TCP):
            ttl = resp[IP].ttl
            window = resp[TCP].window

    if ttl is None:  # fall back to ICMP
        resp = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=False)
        if resp is not None:
            ttl = resp[IP].ttl

    if ttl is None:
        return "Unknown (no response to probes)", "low"

    base = _round_up_ttl(ttl)
    os_guess = _TTL_TABLE.get(base, "Unknown")

    # Use the window size to raise confidence or refine the guess.
    confidence = "medium"
    if window is not None and window in _WINDOW_HINTS:
        hint = _WINDOW_HINTS[window]
        if os_guess.split()[0].lower() in hint.lower():
            confidence = "high"          # TTL and window agree
        else:
            os_guess = f"{os_guess} (window suggests {hint})"

    if verbose:
        print(f"  [os ] {ip}: ttl={ttl} (~{base}) "
              f"window={window} -> {os_guess} [{confidence}]")

    return os_guess, confidence
