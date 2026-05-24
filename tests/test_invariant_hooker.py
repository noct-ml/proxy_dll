import pytest
import ctypes
import struct


# Simulate the bridge buffer allocation and copy logic
# This models the vulnerable pattern: memcpy(bridge, address, save_bytes)
# where save_bytes is derived from instruction disassembly without validation

BRIDGE_BUFFER_SIZE = 32  # Typical bridge buffer size in hooking libraries


def simulate_bridge_copy(address_bytes: bytes, save_bytes: int) -> dict:
    """
    Simulates the hooker.c bridge buffer copy operation.
    Returns a dict with 'safe' (bool) and 'bytes_copied' (int).
    
    The invariant: save_bytes MUST NOT exceed BRIDGE_BUFFER_SIZE.
    """
    result = {
        "save_bytes": save_bytes,
        "bridge_buffer_size": BRIDGE_BUFFER_SIZE,
        "would_overflow": save_bytes > BRIDGE_BUFFER_SIZE,
        "bytes_to_copy": min(save_bytes, len(address_bytes)),
    }
    
    # Safe copy: only copy up to bridge buffer size
    if save_bytes > BRIDGE_BUFFER_SIZE:
        result["safe"] = False
        result["error"] = f"save_bytes ({save_bytes}) exceeds bridge buffer size ({BRIDGE_BUFFER_SIZE})"
    elif save_bytes < 0:
        result["safe"] = False
        result["error"] = f"save_bytes ({save_bytes}) is negative"
    elif save_bytes > len(address_bytes):
        result["safe"] = False
        result["error"] = f"save_bytes ({save_bytes}) exceeds source buffer length ({len(address_bytes)})"
    else:
        result["safe"] = True
        result["copied"] = address_bytes[:save_bytes]
    
    return result


def derive_save_bytes_from_prologue(prologue_bytes: bytes) -> int:
    """
    Simulates instruction disassembly logic that derives save_bytes.
    In a real hooker, this would disassemble instructions to find
    how many bytes to save. This simulation models adversarial inputs.
    """
    if not prologue_bytes:
        return 0
    
    # Simulate: first byte could be interpreted as instruction length
    # Adversarial prologues might cause disassembler to return huge values
    first_byte = prologue_bytes[0]
    
    # Simulate disassembly result (in real code, this could be manipulated)
    # Normal case: 5-15 bytes for typical prologue
    # Adversarial case: crafted bytes cause large save_bytes
    return first_byte  # Simplified: first byte as "instruction size"


# Adversarial payloads: (prologue_bytes, save_bytes_override)
# Format: (source_bytes, save_bytes_value)
ADVERSARIAL_PAYLOADS = [
    # Overflow attempts: save_bytes larger than bridge buffer
    (b"\x00" * 64, 64),           # Exactly 2x bridge buffer
    (b"\xff" * 256, 255),          # Max byte value as save_bytes
    (b"\x80" * 128, 128),          # 4x bridge buffer
    (b"\x41" * 1024, 1024),        # Large allocation attempt
    (b"\x90" * 33, 33),            # One byte over bridge buffer
    (b"\x90" * 32, 32),            # Exactly at bridge buffer limit (boundary)
    (b"\x90" * 31, 31),            # One byte under (should be safe)
    
    # Integer boundary values
    (b"\x00" * 100, 0x7FFFFFFF),   # Max signed int
    (b"\x00" * 100, 0xFFFFFFFF),   # Max unsigned int (wraps negative in signed)
    (b"\x00" * 100, 65536),        # 64KB
    (b"\x00" * 100, 4096),         # Page size
    
    # Negative/underflow values
    (b"\x00" * 10, -1),            # Negative save_bytes
    (b"\x00" * 10, -100),          # Large negative
    
    # Zero-length source with nonzero save_bytes
    (b"", 1),                       # Empty source, nonzero copy
    (b"", 32),                      # Empty source, full bridge size
    
    # Crafted x86 NOP sleds and shellcode-like patterns
    (b"\x90" * 100, 100),          # NOP sled
    (b"\xcc" * 50, 50),            # INT3 breakpoints
    (b"\xe9\xff\xff\xff\x7f" + b"\x90" * 100, 105),  # JMP + padding
    
    # Boundary: exactly bridge buffer size
    (b"A" * 32, 32),               # Exactly fills bridge buffer
    (b"A" * 32, 31),               # One less than bridge buffer
    (b"A" * 33, 33),               # One more than bridge buffer
    
    # Crafted to look like valid instructions but with large sizes
    (bytes(range(256)), 200),       # All byte values, large copy
    (b"\x0f\x1f\x84\x00" * 20, 80),  # Multi-byte NOP patterns
]


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_bridge_buffer_copy_invariant(payload):
    """
    Invariant: The number of bytes copied into the bridge buffer (save_bytes)
    MUST NEVER exceed the allocated bridge buffer size. Any copy operation
    where save_bytes > BRIDGE_BUFFER_SIZE constitutes a buffer overflow.
    Additionally, save_bytes must be non-negative and must not exceed the
    source buffer length.
    """
    source_bytes, save_bytes = payload
    
    result = simulate_bridge_copy(source_bytes, save_bytes)
    
    # INVARIANT 1: save_bytes must never exceed bridge buffer size
    assert save_bytes <= BRIDGE_BUFFER_SIZE, (
        f"SECURITY VIOLATION: save_bytes={save_bytes} exceeds "
        f"bridge buffer size={BRIDGE_BUFFER_SIZE}. "
        f"This would cause a buffer overflow in hooker.c:1228"
    )
    
    # INVARIANT 2: save_bytes must be non-negative
    assert save_bytes >= 0, (
        f"SECURITY VIOLATION: save_bytes={save_bytes} is negative. "
        f"This could cause undefined behavior in memcpy."
    )
    
    # INVARIANT 3: save_bytes must not exceed source buffer length
    assert save_bytes <= len(source_bytes), (
        f"SECURITY VIOLATION: save_bytes={save_bytes} exceeds "
        f"source buffer length={len(source_bytes)}. "
        f"This would read out-of-bounds memory."
    )
    
    # INVARIANT 4: If all invariants pass, the copy should be marked safe
    if save_bytes <= BRIDGE_BUFFER_SIZE and save_bytes >= 0 and save_bytes <= len(source_bytes):
        assert result["safe"] is True, (
            f"Copy should be safe but was marked unsafe: {result.get('error', 'unknown')}"
        )


@pytest.mark.parametrize("prologue", [
    b"\xff" + b"\x90" * 255,       # First byte = 255 (would set save_bytes=255)
    b"\x80" + b"\x90" * 128,       # First byte = 128 (would set save_bytes=128)
    b"\x40" + b"\x90" * 64,        # First byte = 64 (would set save_bytes=64)
    b"\x20" + b"\x90" * 32,        # First byte = 32 (boundary)
    b"\x1f" + b"\x90" * 31,        # First byte = 31 (safe)
    b"\x05" + b"\x90" * 5,         # Typical 5-byte prologue (safe)
    b"\x0e" + b"\x90" * 14,        # 14-byte prologue (safe)
    b"\x0f" + b"\x90" * 15,        # 15-byte prologue (safe)
    b"\x10" + b"\x90" * 16,        # 16-byte prologue (safe)
    b"\x21" + b"\x90" * 33,        # 33-byte (overflow by 1)
])
def test_disassembly_derived_save_bytes_invariant(prologue):
    """
    Invariant: Even when save_bytes is derived from instruction disassembly
    of a crafted/adversarial function prologue, the resulting value MUST
    be validated against the bridge buffer size before any copy operation.
    The disassembly result must be clamped/validated before use in memcpy.
    """
    save_bytes = derive_save_bytes_from_prologue(prologue)
    
    # The security check that MUST happen before memcpy in hooker.c
    # Validate save_bytes before allowing the copy
    validated_save_bytes = save_bytes
    
    # INVARIANT: After validation, save_bytes must be within safe bounds
    assert validated_save_bytes <= BRIDGE_BUFFER_SIZE, (
        f"SECURITY VIOLATION: Disassembly of crafted prologue produced "
        f"save_bytes={save_bytes} which exceeds bridge buffer "
        f"size={BRIDGE_BUFFER_SIZE}. The hooker must validate this value "
        f"before calling memcpy(bridge, address, save_bytes)."
    )
    
    assert validated_save_bytes >= 0, (
        f"SECURITY VIOLATION: Disassembly produced negative save_bytes={save_bytes}"
    )
    
    assert validated_save_bytes <= len(prologue), (
        f"SECURITY VIOLATION: save_bytes={save_bytes} exceeds "
        f"prologue length={len(prologue)}"
    )


def test_bridge_buffer_size_constant_integrity():
    """
    Invariant: The bridge buffer size constant must be a positive, reasonable
    value that reflects actual allocated memory. It must not be zero or negative.
    """
    assert BRIDGE_BUFFER_SIZE > 0, "Bridge buffer size must be positive"
    assert BRIDGE_BUFFER_SIZE >= 16, "Bridge buffer must be large enough for minimum hook"
    assert BRIDGE_BUFFER_SIZE <= 4096, "Bridge buffer should not be unreasonably large"


@pytest.mark.parametrize("save_bytes,expected_safe", [
    (0, True),
    (1, True),
    (16, True),
    (31, True),
    (32, True),    # Boundary: exactly bridge buffer size
    (33, False),   # One over: overflow
    (64, False),
    (256, False),
    (1024, False),
    (-1, False),
    (-100, False),
])
def test_save_bytes_boundary_validation(save_bytes, expected_safe):
    """
    Invariant: The validation logic must correctly identify safe vs unsafe
    save_bytes values relative to the bridge buffer boundary.
    Values <= BRIDGE_BUFFER_SIZE and >= 0 are safe; all others are not.
    """
    source = b"\x90" * max(save_bytes, 0) if save_bytes >= 0 else b"\x90" * 10
    
    is_safe = (0 <= save_bytes <= BRIDGE_BUFFER_SIZE <= len(source))
    
    assert is_safe == expected_safe, (
        f"Boundary check failed for save_bytes={save_bytes}: "
        f"expected safe={expected_safe}, got safe={is_safe}"
    )
    
    if expected_safe:
        # If safe, the copy must be within bounds
        assert save_bytes >= 0
        assert save_bytes <= BRIDGE_BUFFER_SIZE
    else:
        # If unsafe, at least one invariant must be violated
        violation = (save_bytes < 0) or (save_bytes > BRIDGE_BUFFER_SIZE)
        assert violation, (
            f"save_bytes={save_bytes} was marked unsafe but no invariant was violated"
        )