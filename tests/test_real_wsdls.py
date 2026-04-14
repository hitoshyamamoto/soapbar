"""Integration tests: parse real-world WSDL samples.

Each test loads a static WSDL file from tests/wsdl_samples/ and asserts that
parse_wsdl() produces a structurally valid WsdlDefinition.  No network access;
all files are committed locally.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from soapbar import parse_wsdl
from soapbar.core.wsdl.parser import parse_wsdl_file

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


@pytest.mark.integration
class TestMultiSchemaWsdl:
    """CRM — a two-hop xsd:import chain modelled on the shape of real
    enterprise SOAP contracts (SAP, Salesforce partner WSDL, NF-e). The
    top-level WSDL imports types.xsd which imports common.xsd; a
    conformant parser must register complex types from both."""

    def setup_method(self) -> None:
        # parse_wsdl registers harvested complex types into the global
        # xsd registry as a side effect; snapshot before each test and
        # restore in teardown so the 27-types invariant in test_soapbar
        # does not regress under test-order pollution.
        from soapbar.core.types import xsd as _xsd_registry
        self._xsd_snapshot = dict(_xsd_registry._by_name)
        # parse_wsdl_file sets base_url to the fixture's parent directory
        # so relative xsd:import schemaLocation="types.xsd" resolves.
        self.wsdl = parse_wsdl_file(SAMPLES / "multi_schema" / "crm.wsdl")

    def teardown_method(self) -> None:
        from soapbar.core.types import xsd as _xsd_registry
        _xsd_registry._by_name = self._xsd_snapshot

    def test_target_namespace(self) -> None:
        assert self.wsdl.target_namespace == "http://example.com/crm"

    def test_binding_and_operation_present(self) -> None:
        assert "CrmBinding" in self.wsdl.bindings
        names = {op.name for op in self.wsdl.bindings["CrmBinding"].operations}
        assert "GetCustomer" in names

    def test_direct_xsd_import_resolved(self) -> None:
        """Customer is declared in types.xsd (one-hop import)."""
        assert "Customer" in self.wsdl.complex_types

    def test_transitive_xsd_import_resolved(self) -> None:
        """Address is declared in common.xsd, reachable only via
        types.xsd → common.xsd (two-hop transitive import). This is the
        assertion that actually pins the recursion in
        _resolve_schema_imports."""
        assert "Address" in self.wsdl.complex_types

    def test_service_endpoint_address(self) -> None:
        svc = self.wsdl.services["CrmService"]
        assert svc.ports[0].address == "http://example.com/crm"
