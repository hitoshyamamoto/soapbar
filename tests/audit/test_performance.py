"""
Performance benchmarks for soapbar.

Reports p50/p95/p99 latencies and memory deltas for core operations.
All benchmarks run in-process with no network I/O.

Run with:
    uv run pytest tests/audit/test_performance.py -v -s
"""
from __future__ import annotations

import statistics
import time
import tracemalloc

from lxml import etree

from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import SoapEnvelope, SoapVersion
from soapbar.core.fault import SoapFault
from soapbar.core.types import xsd
from soapbar.core.wsdl import (
    WsdlBinding,
    WsdlBindingOperation,
    WsdlDefinition,
    WsdlMessage,
    WsdlOperation,
    WsdlOperationMessage,
    WsdlPart,
    WsdlPort,
    WsdlPortType,
    WsdlService,
)
from soapbar.core.wsdl.builder import build_wsdl_bytes
from soapbar.core.wsdl.parser import parse_wsdl
from soapbar.server.application import SoapApplication
from soapbar.server.service import SoapService, soap_operation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _percentiles(times_ns: list[float]) -> dict[str, float]:
    s = sorted(times_ns)
    n = len(s)
    return {
        "min_us": s[0] / 1000,
        "p50_us": statistics.median(s) / 1000,
        "p95_us": s[int(n * 0.95)] / 1000,
        "p99_us": s[int(n * 0.99)] / 1000,
        "max_us": s[-1] / 1000,
        "mean_us": statistics.mean(s) / 1000,
    }


def _print_table(label: str, stats: dict[str, float]) -> None:
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    for k, v in stats.items():
        print(f"  {k:15s}: {v:10.2f} µs")


def _make_sig() -> OperationSignature:
    return OperationSignature(
        name="add",
        input_params=[
            OperationParameter("a", xsd.resolve("int")),    # type: ignore[arg-type]
            OperationParameter("b", xsd.resolve("int")),    # type: ignore[arg-type]
        ],
        output_params=[OperationParameter("result", xsd.resolve("int"))],  # type: ignore[arg-type]
        soap_action="add",
        input_namespace="http://example.com/calc",
        output_namespace="http://example.com/calc",
    )


def _make_app() -> SoapApplication:
    class _Calc(SoapService):
        __service_name__ = "Calc"
        __tns__ = "http://example.com/calc"
        __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED

        @soap_operation(soap_action="add")
        def add(self, a: int, b: int) -> int:
            return a + b

    app = SoapApplication(service_url="http://example.com/calc")
    app.register(_Calc())
    return app


DLW_ADD_REQUEST = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:tns="http://example.com/calc">
  <soapenv:Body>
    <tns:add><a>3</a><b>5</b></tns:add>
  </soapenv:Body>
</soapenv:Envelope>"""

N = 1000  # number of iterations for benchmarks


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

class TestPerformanceBenchmarks:
    """Performance benchmark suite — results printed to stdout with -s flag."""

    def test_bench_serialize_dlw_request(self):
        """Serialize 1000 DLW requests (envelope build + to_bytes)."""
        sig = _make_sig()
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        times: list[float] = []

        for _ in range(N):
            t0 = time.perf_counter_ns()
            env = SoapEnvelope(version=SoapVersion.SOAP_11)
            body_container = etree.Element("_body")
            serializer.serialize_request(sig, {"a": 3, "b": 5}, body_container)
            for child in body_container:
                env.add_body_content(child)
            _ = env.to_bytes()
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table(f"BENCH: Serialize DLW request (N={N})", stats)
        # Sanity: p99 should be well under 10ms = 10,000 µs for a simple serialize
        assert stats["p99_us"] < 10_000, f"Serialization p99 too slow: {stats['p99_us']:.0f} µs"

    def test_bench_deserialize_dlw_response(self):
        """Deserialize 1000 DLW responses (parse XML + extract params)."""
        sig = _make_sig()
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)

        # Build a response envelope to deserialize
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        body_container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 8}, body_container)
        for child in body_container:
            env.add_body_content(child)
        resp_bytes = env.to_bytes()

        times: list[float] = []
        for _ in range(N):
            t0 = time.perf_counter_ns()
            parsed_env = SoapEnvelope.from_xml(resp_bytes)
            container = etree.Element("_body")
            if parsed_env.first_body_element is not None:
                container.append(parsed_env.first_body_element)
            _ = serializer.deserialize_response(sig, container)
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table(f"BENCH: Deserialize DLW response (N={N})", stats)
        assert stats["p99_us"] < 10_000

    def test_bench_full_round_trip_handle_request(self):
        """1000 full round-trips through SoapApplication.handle_request()."""
        app = _make_app()
        times: list[float] = []

        for _ in range(N):
            t0 = time.perf_counter_ns()
            status, _ct, _body = app.handle_request(DLW_ADD_REQUEST, soap_action="add")
            times.append(time.perf_counter_ns() - t0)
            assert status == 200

        stats = _percentiles(times)
        _print_table(f"BENCH: Full round-trip handle_request (N={N})", stats)
        # Full dispatch should be under 10ms p99
        assert stats["p99_us"] < 10_000

    def test_bench_wsdl_parse(self):
        """Parse WSDL 100 times — measures WSDL parsing throughput."""
        app = _make_app()
        wsdl_bytes = app.get_wsdl()
        times: list[float] = []

        for _ in range(100):
            t0 = time.perf_counter_ns()
            parse_wsdl(wsdl_bytes)
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table("BENCH: WSDL parse (N=100)", stats)
        assert stats["p99_us"] < 50_000  # Under 50ms per parse

    def test_bench_wsdl_build(self):
        """Build WSDL 100 times from WsdlDefinition."""
        app = _make_app()
        wsdl_bytes = app.get_wsdl()
        defn = parse_wsdl(wsdl_bytes)
        times: list[float] = []

        for _ in range(100):
            t0 = time.perf_counter_ns()
            _ = build_wsdl_bytes(defn, "http://example.com/calc")
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table("BENCH: WSDL build (N=100)", stats)
        assert stats["p99_us"] < 50_000

    def test_bench_fault_roundtrip(self):
        """Build + serialize + parse 1000 SOAP 1.1 fault envelopes."""
        times: list[float] = []
        for _ in range(N):
            t0 = time.perf_counter_ns()
            fault = SoapFault("Client", "Invalid input", detail="a must be positive")
            envelope_elem = fault.to_soap11_envelope()
            from soapbar.core.xml import to_bytes
            fault_bytes = to_bytes(envelope_elem)
            parsed = SoapEnvelope.from_xml(fault_bytes)
            assert parsed.is_fault
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table(f"BENCH: SOAP 1.1 fault round-trip (N={N})", stats)
        assert stats["p99_us"] < 10_000

    def test_bench_soap12_fault_roundtrip(self):
        """Build + serialize + parse 1000 SOAP 1.2 fault envelopes."""
        times: list[float] = []
        for _ in range(N):
            t0 = time.perf_counter_ns()
            fault = SoapFault(
                "Server", "Internal error", subcodes=[("http://example.com/", "DBError")]
            )
            envelope_elem = fault.to_soap12_envelope()
            from soapbar.core.xml import to_bytes
            fault_bytes = to_bytes(envelope_elem)
            parsed = SoapEnvelope.from_xml(fault_bytes)
            assert parsed.is_fault
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table(f"BENCH: SOAP 1.2 fault round-trip (N={N})", stats)
        assert stats["p99_us"] < 10_000

    def test_bench_all_5_binding_styles(self):
        """Serialize one request per binding style, 200 times each."""
        sig = _make_sig()
        results: dict[str, dict[str, float]] = {}
        n = 200

        for style in BindingStyle:
            serializer = get_serializer(style)
            times: list[float] = []
            for _ in range(n):
                t0 = time.perf_counter_ns()
                body_container = etree.Element("_body")
                serializer.serialize_request(sig, {"a": 3, "b": 5}, body_container)
                times.append(time.perf_counter_ns() - t0)
            results[style.value] = _percentiles(times)

        print("\n" + "=" * 60)
        print(f"  BENCH: Serialization by binding style (N={n})")
        print("=" * 60)
        for style_name, stats in results.items():
            print(f"\n  {style_name}")
            for k, v in stats.items():
                print(f"    {k:15s}: {v:8.2f} µs")

        for style_name, stats in results.items():
            assert stats["p99_us"] < 5_000, \
                f"Binding style {style_name} p99 too slow: {stats['p99_us']:.0f} µs"

    def test_bench_memory_100_requests(self):
        """Memory delta over 100 end-to-end requests via tracemalloc."""
        app = _make_app()

        # Warm up
        for _ in range(10):
            app.handle_request(DLW_ADD_REQUEST, soap_action="add")

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for _ in range(100):
            app.handle_request(DLW_ADD_REQUEST, soap_action="add")

        snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot_after.compare_to(snapshot_before, "lineno")
        total_delta_kb = sum(s.size_diff for s in top_stats) / 1024

        print(f"\n{'='*60}")
        print("  BENCH: Memory delta over 100 requests")
        print(f"{'='*60}")
        print(f"  Total memory delta: {total_delta_kb:.1f} KB")
        print("\n  Top 5 allocations:")
        for stat in top_stats[:5]:
            print(f"    {stat}")

        # Memory growth should be modest — under 5MB for 100 requests
        assert total_delta_kb < 5_120, \
            f"Memory leak suspected: {total_delta_kb:.0f} KB over 100 requests"

    def test_bench_wsdl_complex_20_operations(self):
        """Parse a WSDL with 20 operations 50 times."""
        # Build a WSDL with 20 operations
        tns = "http://example.com/complex"
        defn = WsdlDefinition(name="Complex", target_namespace=tns)
        pt = WsdlPortType(name="ComplexPortType")
        binding_ops: list[WsdlBindingOperation] = []

        for i in range(20):
            op_name = f"operation{i}"
            in_msg = f"{op_name}Request"
            out_msg = f"{op_name}Response"
            defn.messages[in_msg] = WsdlMessage(
                name=in_msg,
                parts=[
                    WsdlPart(name="param1", type="xsd:string"),
                    WsdlPart(name="param2", type="xsd:int"),
                ],
            )
            defn.messages[out_msg] = WsdlMessage(
                name=out_msg,
                parts=[WsdlPart(name="result", type="xsd:string")],
            )
            pt.operations.append(WsdlOperation(
                name=op_name,
                input=WsdlOperationMessage(message=in_msg),
                output=WsdlOperationMessage(message=out_msg),
            ))
            binding_ops.append(WsdlBindingOperation(
                name=op_name,
                soap_action=op_name,
                style="document",
                use="literal",
            ))

        defn.port_types["ComplexPortType"] = pt
        defn.bindings["ComplexBinding"] = WsdlBinding(
            name="ComplexBinding",
            port_type="ComplexPortType",
            soap_ns="http://schemas.xmlsoap.org/wsdl/soap/",
            style="document",
            transport="http://schemas.xmlsoap.org/soap/http",
            operations=binding_ops,
        )
        defn.services["ComplexService"] = WsdlService(
            name="ComplexService",
            ports=[WsdlPort(
                name="ComplexPort",
                binding="ComplexBinding",
                address="http://example.com/complex",
            )],
        )

        wsdl_bytes = build_wsdl_bytes(defn, "http://example.com/complex")

        times: list[float] = []
        for _ in range(50):
            t0 = time.perf_counter_ns()
            _ = parse_wsdl(wsdl_bytes)
            times.append(time.perf_counter_ns() - t0)

        stats = _percentiles(times)
        _print_table("BENCH: Complex WSDL parse (20 ops, N=50)", stats)
        assert stats["p99_us"] < 100_000  # Under 100ms
