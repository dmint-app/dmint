"""Request-size enforcement for the MCP gateway JSON parser."""

from __future__ import annotations

import unittest

from dmint.mcp.errors import MCPProtocolError
from dmint.mcp.gateway import parse_gateway_request


class TestGatewayRequestLimits(unittest.TestCase):
    def test_bytes_over_limit_are_rejected_before_json_parsing(self) -> None:
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request(b"X" * 1025, max_bytes=1024)
        self.assertIn("maximum permitted size", str(ctx.exception))
        self.assertEqual(ctx.exception.code, "DMT_MCP_PROTOCOL_ERROR")

    def test_text_over_limit_is_rejected_by_utf8_byte_length(self) -> None:
        payload = '{"text":"' + ("é" * 100) + '"}'
        self.assertGreater(len(payload.encode("utf-8")), len(payload))
        with self.assertRaises(MCPProtocolError):
            parse_gateway_request(payload, max_bytes=64)

    def test_payload_at_exact_limit_is_accepted(self) -> None:
        payload = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
        parsed = parse_gateway_request(payload, max_bytes=len(payload))
        self.assertEqual(parsed["method"], "tools/list")

    def test_duplicate_keys_remain_rejected_under_the_limit(self) -> None:
        with self.assertRaises(MCPProtocolError) as ctx:
            parse_gateway_request('{"a":1,"a":2}', max_bytes=1024)
        self.assertIn("duplicate", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
