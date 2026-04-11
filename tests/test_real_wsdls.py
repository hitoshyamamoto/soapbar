"""Integration tests: parse real-world WSDL samples.

Each test loads a static WSDL file from tests/wsdl_samples/ and asserts that
parse_wsdl() produces a structurally valid WsdlDefinition.  No network access;
all files are committed locally.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from soapbar import parse_wsdl

SAMPLES = Path(__file__).parent / "wsdl_samples"


@pytest.mark.integration
class TestGlobalWeatherWsdl:
    """GlobalWeather — classic SOAP interop test WSDL (SOAP 1.1 + 1.2 bindings)."""

    def setup_method(self) -> None:
        self.wsdl = parse_wsdl(SAMPLES / "global_weather.wsdl")

    def test_service_present(self) -> None:
        assert len(self.wsdl.services) >= 1

    def test_bindings_present(self) -> None:
        assert len(self.wsdl.bindings) >= 1

    def test_operations_present(self) -> None:
        ops = [op for b in self.wsdl.bindings.values() for op in b.operations]
        assert len(ops) >= 2

    def test_get_weather_operation(self) -> None:
        names = {op.name for b in self.wsdl.bindings.values() for op in b.operations}
        assert "GetWeather" in names

    def test_get_cities_by_country_operation(self) -> None:
        names = {op.name for b in self.wsdl.bindings.values() for op in b.operations}
        assert "GetCitiesByCountry" in names

    def test_soap12_binding_present(self) -> None:
        assert "GlobalWeatherSoap12" in self.wsdl.bindings

    def test_target_namespace(self) -> None:
        assert self.wsdl.target_namespace == "http://www.webserviceX.NET"


@pytest.mark.integration
class TestHelloWorldWsdl:
    """HelloWorld — hand-crafted WSDL covering SOAP 1.1/1.2, rpc/document, optional parts."""

    def setup_method(self) -> None:
        self.wsdl = parse_wsdl(SAMPLES / "hello_world.wsdl")

    def test_service_present(self) -> None:
        assert len(self.wsdl.services) >= 1

    def test_three_bindings(self) -> None:
        assert len(self.wsdl.bindings) == 3

    def test_soap11_and_soap12_binding(self) -> None:
        assert "HelloSoap11" in self.wsdl.bindings
        assert "HelloSoap12" in self.wsdl.bindings

    def test_rpc_binding(self) -> None:
        assert "EchoSoap11" in self.wsdl.bindings

    def test_say_hello_operation(self) -> None:
        names = {op.name for op in self.wsdl.bindings["HelloSoap11"].operations}
        assert "SayHello" in names

    def test_echo_operation(self) -> None:
        names = {op.name for op in self.wsdl.bindings["EchoSoap11"].operations}
        assert "Echo" in names

    def test_target_namespace(self) -> None:
        assert self.wsdl.target_namespace == "urn:hello"

    def test_schema_elements_parsed(self) -> None:
        # Schema is parsed; elements are stored as raw lxml elements
        assert len(self.wsdl.schema_elements) >= 1

    def test_service_ports(self) -> None:
        svc = self.wsdl.services["HelloWorldService"]
        assert len(svc.ports) == 3
