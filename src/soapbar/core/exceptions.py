# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""The root of soapbar's exception hierarchy.

Every exception soapbar raises deliberately derives from :class:`SoapbarError`,
so a caller can ``except SoapbarError`` to catch anything the library raises —
a SOAP fault, a security or validation failure, a size-limit breach, or a
contrib-client error — without enumerating concrete types.

Concrete classes live next to the code that raises them and all inherit this
base: :class:`~soapbar.core.fault.SoapFault` (the SOAP fault construct),
:class:`~soapbar.core.wssecurity.XmlSecurityError` /
:class:`~soapbar.core.wssecurity.SecurityValidationError`,
:class:`~soapbar.core.xml.BodyTooLargeError` (which also subclasses
:class:`ValueError` for backwards compatibility), and the contrib ``*Error``
types under :mod:`soapbar.contrib` (each with its own typed sub-hierarchy).

This module has no soapbar imports on purpose — it is a dependency-free leaf so
every other module can import the base without risking an import cycle.
"""
from __future__ import annotations


class SoapbarError(Exception):
    """Base class for every error soapbar raises deliberately.

    Catch this to handle any soapbar-originated failure uniformly. Note it does
    not encompass errors raised by the standard library or third-party
    dependencies (e.g. an ``lxml`` parse error on malformed XML, or an ``httpx``
    connection error) — only failures soapbar itself signals.
    """
