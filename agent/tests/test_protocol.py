import json
import unittest

from nixfort_agent.__main__ import handle

from .helpers import make_ctx, request

INJECTIONS = ["; id", "$(id)", "`id`", "a|b", "a&&b", "x\ny", "../../etc/passwd", "\x00", "a b; rm -rf /"]


def call(raw, **ctx_kw):
    return json.loads(handle(raw, ctx_factory=lambda d: make_ctx(**ctx_kw)))


class EnvelopeTests(unittest.TestCase):
    def test_ping_ok(self):
        r = call(request("system.ping.v1"))
        self.assertEqual(r["state"], "OK")
        self.assertEqual(r["os_profile"], "ubuntu-24.04")
        self.assertIn("agent_version", r["result"])

    def test_not_json(self):
        r = call(b"{not json")
        self.assertEqual((r["state"], r["error_code"]), ("REJECTED", "invalid_request"))

    def test_too_large(self):
        r = call(b"{" + b" " * (70 * 1024) + b"}")
        self.assertEqual(r["error_code"], "invalid_request")

    def test_extra_envelope_key(self):
        raw = json.loads(request("system.ping.v1"))
        raw["shell"] = "id"
        r = call(json.dumps(raw).encode())
        self.assertEqual(r["state"], "REJECTED")

    def test_missing_envelope_key(self):
        raw = json.loads(request("system.ping.v1"))
        del raw["deadline_s"]
        self.assertEqual(call(json.dumps(raw).encode())["state"], "REJECTED")

    def test_bad_protocol(self):
        self.assertEqual(call(request("system.ping.v1", protocol="other/1"))["state"], "REJECTED")

    def test_bad_request_id(self):
        r = call(request("system.ping.v1", request_id="123"))
        self.assertEqual(r["state"], "REJECTED")

    def test_unknown_action(self):
        r = call(request("system.exec.v1"))
        self.assertEqual((r["state"], r["error_code"]), ("REJECTED", "unknown_action"))
        self.assertEqual(r["action"], "system.exec.v1")

    def test_action_name_injection(self):
        for bad in INJECTIONS:
            r = call(request(bad))
            self.assertEqual(r["state"], "REJECTED", bad)

    def test_unknown_param_rejected(self):
        r = call(request("system.ping.v1", {"cmd": "id"}))
        self.assertEqual((r["state"], r["error_code"]), ("REJECTED", "invalid_params"))

    def test_deadline_range(self):
        for d in (0, 601, "30", True, None):
            self.assertEqual(call(request("system.ping.v1", deadline_s=d))["state"], "REJECTED", d)

    def test_request_id_echoed_on_error(self):
        raw = request("system.ping.v1", {"x": 1})
        rid = json.loads(raw)["request_id"]
        self.assertEqual(call(raw)["request_id"], rid)

    def test_params_injection_in_ip(self):
        for bad in INJECTIONS + ["10.0.0.1; id", "10.0.0.256", "10.0.0.0/8"]:
            r = call(request("net.tcp_probe.v1", {"targets": [{"ip": bad, "port": 80}], "timeout_ms": 500}))
            self.assertEqual((r["state"], r["error_code"]), ("REJECTED", "invalid_params"), bad)

    def test_port_bool_rejected(self):
        r = call(request("net.tcp_probe.v1", {"targets": [{"ip": "10.0.0.1", "port": True}], "timeout_ms": 500}))
        self.assertEqual(r["state"], "REJECTED")

    def test_internal_error_does_not_leak(self):
        from nixfort_agent.registry import REGISTRY

        orig = REGISTRY["system.ping.v1"]
        try:
            from dataclasses import replace

            def boom(ctx, params):
                raise ValueError("secret-path /root/.ssh/id_rsa")

            REGISTRY["system.ping.v1"] = replace(orig, handler=boom)
            out = handle(request("system.ping.v1"), ctx_factory=lambda d: make_ctx()).decode()
            r = json.loads(out)
            self.assertEqual((r["state"], r["error_code"]), ("ERROR", "internal_error"))
            self.assertNotIn("secret-path", out)
        finally:
            REGISTRY["system.ping.v1"] = orig

    def test_response_is_single_json_with_fixed_keys(self):
        r = call(request("system.ping.v1"))
        self.assertEqual(
            set(r),
            {
                "protocol",
                "request_id",
                "action",
                "state",
                "result",
                "error_code",
                "agent_version",
                "os_profile",
                "duration_ms",
            },
        )


if __name__ == "__main__":
    unittest.main()
