import os

# Set a deterministic default 32-byte integrity key in hex for test runs
os.environ.setdefault(
    "DMINT_INTEGRITY_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
)

# Ensure loopback traffic is never forwarded to external proxies during tests
os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1"
