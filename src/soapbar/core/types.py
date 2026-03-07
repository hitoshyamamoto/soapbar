"""XSD type system with registry."""
from __future__ import annotations

import base64
import binascii
import re as _re
from abc import ABC, abstractmethod
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation
from typing import Any

from soapbar.core.namespaces import NS

_DURATION_RE = _re.compile(
    r'^-?P(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$'
)


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
    min_value: int | None = None
    max_value: int | None = None

    def _check_range(self, v: int) -> int:
        if self.min_value is not None and v < self.min_value:
            raise ValueError(f"{self.name} value {v} is below minimum {self.min_value}")
        if self.max_value is not None and v > self.max_value:
            raise ValueError(f"{self.name} value {v} exceeds maximum {self.max_value}")
        return v

    def to_xml(self, value: Any) -> str:
        return str(self._check_range(int(value)))

    def from_xml(self, s: str) -> int:
        return self._check_range(int(s))


class _IntType(_IntegerType):
    name = "int"
    min_value = -2147483648
    max_value = 2147483647


class _LongType(_IntegerType):
    name = "long"
    min_value = -9223372036854775808
    max_value = 9223372036854775807


class _ShortType(_IntegerType):
    name = "short"
    min_value = -32768
    max_value = 32767


class _ByteType(_IntegerType):
    name = "byte"
    min_value = -128
    max_value = 127


class _UnsignedIntType(_IntegerType):
    name = "unsignedInt"
    min_value = 0
    max_value = 4294967295


class _UnsignedShortType(_IntegerType):
    name = "unsignedShort"
    min_value = 0
    max_value = 65535


class _UnsignedByteType(_IntegerType):
    name = "unsignedByte"
    min_value = 0
    max_value = 255


class _UnsignedLongType(_IntegerType):
    name = "unsignedLong"
    min_value = 0
    max_value = 18446744073709551615


class _PositiveIntegerType(_IntegerType):
    name = "positiveInteger"
    min_value = 1


class _NonNegativeIntegerType(_IntegerType):
    name = "nonNegativeInteger"
    min_value = 0


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
        try:
            datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError as err:
            raise ValueError(f"Invalid {self.name} value: {s!r}") from err
        return s


class _DateType(XsdType):
    name = "date"

    def to_xml(self, value: Any) -> str:
        return str(value)

    def from_xml(self, s: str) -> str:
        try:
            date.fromisoformat(s)
        except ValueError as err:
            raise ValueError(f"Invalid {self.name} value: {s!r}") from err
        return s


class _TimeType(XsdType):
    name = "time"

    def to_xml(self, value: Any) -> str:
        return str(value)

    def from_xml(self, s: str) -> str:
        try:
            time.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError as err:
            raise ValueError(f"Invalid {self.name} value: {s!r}") from err
        return s


class _DurationType(XsdType):
    name = "duration"

    def to_xml(self, value: Any) -> str:
        return str(value)

    def from_xml(self, s: str) -> str:
        if not _DURATION_RE.fullmatch(s) or not any(c.isdigit() for c in s):
            raise ValueError(f"Invalid {self.name} value: {s!r}")
        return s


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
