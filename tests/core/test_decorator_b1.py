"""Comprehensive tests for Group B1: Decorator mode for real web applications."""

import asyncio
import gc
import inspect
import unittest
import weakref
from datetime import datetime, timedelta, timezone

from dmint import (
    ApprovalRequiredError,
    Decision,
    Dmint,
    NO_RESOURCE,
    Policy,
    PolicyProvenance,
    Rule,
    SQLiteApprovalStore,
    ToolRequest,
    TrustedContext,
)
from dmint.errors import AuthorizationError, RequestValidationError
from dmint.policy import policy_digest


class DecoratorB1Tests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.policy = Policy(
            (
                Rule.allow("math", "add"),
                Rule.allow("calc", "Calculator.multiply"),
                Rule.allow("calc", "Calculator.class_version"),
                Rule.allow("calc", "static_square"),
                Rule.allow("calc", "AsyncService.compute"),
                Rule.approval_required("math", "divide"),
                Rule.allow(
                    "constrained",
                    "action",
                    constraints={"properties": {"level": {"enum": ["admin"]}}},
                ),
            )
        )
        self.provenance = PolicyProvenance(
            "epoch-b1", policy_digest(self.policy), datetime(2026, 1, 1, tzinfo=timezone.utc)
        )
        self.dmint = Dmint(
            self.policy,
            agent_id="agent-b1",
            context=TrustedContext({"role": "worker"}),
            policy_provenance=self.provenance,
            approval_ttl=timedelta(minutes=10),
        )

    # -------------------------------------------------------------------------
    # (a) Support async def (authorize first, then await)
    # -------------------------------------------------------------------------
    async def test_async_def_allowed_authorizes_then_awaits(self) -> None:
        execution_order = []

        @self.dmint.protected("math.add")
        async def add_numbers(a: int, b: int) -> int:
            execution_order.append("executing")
            await asyncio.sleep(0.001)
            return a + b

        res = await add_numbers(10, 20)
        self.assertEqual(res, 30)
        self.assertEqual(execution_order, ["executing"])

    async def test_async_def_denied_fails_before_execution(self) -> None:
        executed = False

        @self.dmint.protected("math.subtract")
        async def subtract(a: int, b: int) -> int:
            nonlocal executed
            executed = True
            return a - b

        with self.assertRaises(AuthorizationError):
            await subtract(10, 5)

        self.assertFalse(executed)

    # -------------------------------------------------------------------------
    # (b) Methods: exclude self/cls, include class name in capability
    # -------------------------------------------------------------------------
    async def test_instance_methods_exclude_self_and_execute_correctly(self) -> None:
        calls = []

        class Calculator:
            def __init__(self, multiplier: int) -> None:
                self.multiplier = multiplier

            @self.dmint.protected("calc.multiply")
            def multiply(self, value: int) -> int:
                calls.append((self.multiplier, value))
                return self.multiplier * value

        calc = Calculator(3)
        # multiply's capability becomes calc.Calculator.multiply
        result = calc.multiply(4)
        self.assertEqual(result, 12)
        self.assertEqual(calls, [(3, 4)])

    async def test_class_methods_exclude_cls_and_execute_correctly(self) -> None:
        class Calculator:
            version = "2.1"

            @classmethod
            @self.dmint.protected("calc.class_version")
            def class_version(cls) -> str:
                return f"version-{cls.version}"

        res = Calculator.class_version()
        self.assertEqual(res, "version-2.1")

    async def test_static_methods_execute_correctly(self) -> None:
        class Calculator:
            @staticmethod
            @self.dmint.protected("calc.static_square")
            def static_square(x: int) -> int:
                return x * x

        self.assertEqual(Calculator.static_square(5), 25)

    async def test_async_instance_method_support(self) -> None:
        class AsyncService:
            def __init__(self, prefix: str) -> None:
                self.prefix = prefix

            @self.dmint.protected("calc.compute")
            async def compute(self, x: int) -> str:
                await asyncio.sleep(0.001)
                return f"{self.prefix}-{x}"

        svc = AsyncService("out")
        res = await svc.compute(42)
        self.assertEqual(res, "out-42")

    # -------------------------------------------------------------------------
    # (c) Generators and async generators are rejected with clear error
    # -------------------------------------------------------------------------
    def test_generators_rejected_at_decoration(self) -> None:
        def sync_gen(x: int):
            yield x

        with self.assertRaises(RequestValidationError) as err:
            self.dmint.protected("math.add")(sync_gen)
        self.assertIn("generator and async generator functions cannot be protected", str(err.exception))

    def test_async_generators_rejected_at_decoration(self) -> None:
        async def async_gen(x: int):
            yield x

        with self.assertRaises(RequestValidationError) as err:
            self.dmint.protected("math.add")(async_gen)
        self.assertIn("generator and async generator functions cannot be protected", str(err.exception))

    # -------------------------------------------------------------------------
    # (d) WeakKeyDictionary registry and stale id reuse after GC
    # -------------------------------------------------------------------------
    def test_weakref_registry_no_stale_id_reuse_after_gc(self) -> None:
        def temp_tool(x: int) -> int:
            return x

        wrapped = self.dmint.protected("math.add")(temp_tool)
        old_id = id(temp_tool)
        self.assertTrue(hasattr(wrapped, "__dmint_binding__"))

        # Verify weakref dictionary stores binding
        self.assertIsInstance(self.dmint._registered, weakref.WeakKeyDictionary)

        del temp_tool
        del wrapped
        gc.collect()

        # Create a new function that might occupy the recycled memory id
        def new_tool(y: int) -> int:
            return y * 2

        # A new function never inherits old bindings
        self.assertIsNone(getattr(new_tool, "__dmint_binding__", None))
        self.assertNotIn(new_tool, self.dmint._registered)

    # -------------------------------------------------------------------------
    # (f) TOCTOU snapshot guarantees and constraint ordering
    # -------------------------------------------------------------------------
    async def test_toctou_guarantee_on_async_path(self) -> None:
        calls = []

        async def process_payload(data: dict) -> dict:
            calls.append(dict(data))
            return data

        self.dmint.register(process_payload, "math.add")

        mutable_payload = {"count": 1}
        authorized = self.dmint.authorize(
            process_payload,
            mutable_payload,
            capability="math.add",
        )
        # Tamper payload before execution
        mutable_payload["count"] = 999
        res = self.dmint.execute(authorized)
        if inspect.iscoroutine(res):
            await res

        # Snapshot was frozen before tampering, so executed call received original value
        self.assertEqual(calls, [{"count": 1}])

    def test_constraint_violation_denies_before_any_approval_persisted(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = Path(tmpdir) / "test.db"
            store = SQLiteApprovalStore(store_path, deployment_epoch="epoch-b1")
            dmint_with_store = Dmint(
                self.policy,
                agent_id="agent-b1",
                context=TrustedContext({"role": "worker"}),
                approval_store=store,
                policy_provenance=self.provenance,
                approval_ttl=timedelta(minutes=10),
            )

            @dmint_with_store.protected("constrained.action")
            def admin_action(level: str) -> str:
                return level

            # Failed constraint: level="guest" != "admin"
            with self.assertRaises(AuthorizationError):
                admin_action("guest")

            # Store must have NO pending records created!
            self.assertEqual(store.list_pending(), [])
            store.close()
