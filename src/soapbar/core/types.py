"""XSD type system with registry."""
from __future__ import annotations

import base64
import binascii
from abc import ABC, abstractmethod
from decimal import Decimal, InvalidOperation
from typing import Any

from soapbar.core.namespaces import NS


class XsdType(ABC):
    name: str
    namespace: str = NS.XSD

    @abstractmethod
    def to_xml(self, value: Any) -> str: ...

    @abstractmethod
    def from_xml(self, s: str) -> Any: ...

    def __repr__(self) -> str:
        return f"<XsdType {self.name}>"


# ---------------------------------------------------------------------------
# String types
# ---------------------------------------------------------------------------

class _StringType(XsdType):
    name = "string"

    def to_xml(self, value: Any) -> str:
        return str(value)

    def from_xml(self, s: str) -> str:
        return s


class _NormalizedStringType(_StringType):
    name = "normalizedString"

    def to_xml(self, value: Any) -> str:
        return " ".join(str(value).split())

    def from_xml(self, s: str) -> str:
        return " ".join(s.split())


class _TokenType(_NormalizedStringType):
    name = "token"


class _AnyURIType(_StringType):
    name = "anyURI"


class _QNameType(_StringType):
    name = "QName"


class _AnyTypeType(_StringType):
    name = "anyType"


# ---------------------------------------------------------------------------
# Integer types
# ---------------------------------------------------------------------------

class _IntegerType(XsdType):
    name = "integer"

    def to_xml(self, value: Any) -> str:
        return str(int(value))

    def from_xml(self, s: str) -> int:
        return int(s)


class _IntType(_IntegerType):
    name = "int"


class _LongType(_IntegerType):
    name = "long"


class _ShortType(_IntegerType):
    name = "short"


class _ByteType(_IntegerType):
    name = "byte"


class _UnsignedIntType(_IntegerType):
    name = "unsignedInt"


class _UnsignedShortType(_IntegerType):
    name = "unsignedShort"


class _UnsignedByteType(_IntegerType):
    name = "unsignedByte"


class _UnsignedLongType(_IntegerType):
    name = "unsignedLong"


class _PositiveIntegerType(_IntegerType):
    name = "positiveInteger"


class _NonNegativeIntegerType(_IntegerType):
    name = "nonNegativeInteger"


# ---------------------------------------------------------------------------
# Float / Decimal types
# ---------------------------------------------------------------------------

class _FloatType(XsdType):
    name = "float"

    def to_xml(self, value: Any) -> str:
        f = float(value)
        if f != f:  # NaN
            return "NaN"
        if f == float("inf"):
            return "INF"
        if f == float("-inf"):
            return "-INF"
        return repr(f)

    def from_xml(self, s: str) -> float:
        if s in ("INF", "+INF"):
            return float("inf")
        if s == "-INF":
            return float("-inf")
        if s == "NaN":
            return float("nan")
        return float(s)


class _DoubleType(_FloatType):
    name = "double"


class _DecimalType(XsdType):
    name = "decimal"

    def to_xml(self, value: Any) -> str:
        return str(Decimal(str(value)))

    def from_xml(self, s: str) -> Decimal:
        try:
            return Decimal(s)
        except InvalidOperation as err:
            raise ValueError(f"Invalid decimal: {s!r}") from err


# ---------------------------------------------------------------------------
# Boolean
# ---------------------------------------------------------------------------

class _BooleanType(XsdType):
    name = "boolean"

    def to_xml(self, value: Any) -> str:
        return "true" if value else "false"

    def from_xml(self, s: str) -> bool:
        if s.lower() in ("true", "1"):
            return True
        if s.lower() in ("false", "0"):
            return False
        raise ValueError(f"Invalid boolean: {s!r}")


# ---------------------------------------------------------------------------
# DateTime types
# ---------------------------------------------------------------------------

class _DateTimeType(XsdType):
    name = "dateTime"

    def to_xml(self, value: Any) -> str:
        return str(value)

    def from_xml(self, s: str) -> str:
        return s


class _DateType(_DateTimeType):
    name = "date"


class _TimeType(_DateTimeType):
    name = "time"


class _DurationType(_DateTimeType):
    name = "duration"


# ---------------------------------------------------------------------------
# Binary types
# ---------------------------------------------------------------------------

class _Base64BinaryType(XsdType):
    name = "base64Binary"

    def to_xml(self, value: Any) -> str:
        if isinstance(value, str):
            value = value.encode()
        return base64.b64encode(value).decode()

    def from_xml(self, s: str) -> bytes:
        return base64.b64decode(s)


class _HexBinaryType(XsdType):
    name = "hexBinary"

    def to_xml(self, value: Any) -> str:
        if isinstance(value, str):
            value = value.encode()
        return binascii.hexlify(value).decode().upper()

    def from_xml(self, s: str) -> bytes:
        return binascii.unhexlify(s)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class _TypeRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, XsdType] = {}

    def register(self, t: XsdType) -> None:
        self._by_name[t.name] = t

    def resolve(self, name: str) -> XsdType | None:
        """Resolve bare name, xsd:name, or Clark {ns}local notation."""
        if name.startswith("{"):
            # Clark notation
            close = name.index("}")
            local = name[close + 1:]
            return self._by_name.get(local)
        if ":" in name:
            local = name.split(":", 1)[1]
            return self._by_name.get(local)
        return self._by_name.get(name)

    def python_to_xsd(self, py_type: type) -> XsdType | None:
        # bool must be checked before int (bool is subclass of int)
        mapping: list[tuple[type, str]] = [
            (bool, "boolean"),
            (int, "int"),
            (float, "float"),
            (str, "string"),
            (Decimal, "decimal"),
            (bytes, "base64Binary"),
        ]
        for py, xsd_name in mapping:
            if issubclass(py_type, py):
                return self._by_name.get(xsd_name)
        return None

    def all_types(self) -> list[XsdType]:
        return list(self._by_name.values())


xsd = _TypeRegistry()

_ALL_TYPES: list[XsdType] = [
    _StringType(),
    _NormalizedStringType(),
    _TokenType(),
    _AnyURIType(),
    _QNameType(),
    _AnyTypeType(),
    _IntegerType(),
    _IntType(),
    _LongType(),
    _ShortType(),
    _ByteType(),
    _UnsignedIntType(),
    _UnsignedShortType(),
    _UnsignedByteType(),
    _UnsignedLongType(),
    _PositiveIntegerType(),
    _NonNegativeIntegerType(),
    _FloatType(),
    _DoubleType(),
    _DecimalType(),
    _BooleanType(),
    _DateTimeType(),
    _DateType(),
    _TimeType(),
    _DurationType(),
    _Base64BinaryType(),
    _HexBinaryType(),
]

for _t in _ALL_TYPES:
    xsd.register(_t)
