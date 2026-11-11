# SPDX-License-Identifier: MPL-2.0
"""pyrfc-compatible exception names, for porting.

Import this module explicitly::

    from saprfclib.compat import ABAPApplicationError, ABAPRuntimeError

Nothing here is re-exported from ``saprfclib/__init__.py``, and that is
deliberate. These names exist to make a port mechanical, not to become a second
public spelling of the exception hierarchy — new code should use the names in
:mod:`saprfclib.exceptions`.

Why a module rather than a find-and-replace: in a port, a missed
``except ABAPApplicationError`` is not an import error. If ``pyrfc`` is still
installed alongside — and during a migration it usually is — the name resolves
against it, the ``except`` clause never matches a ``saprfclib`` exception, and
the handler silently stops running. That failure looks like "the error handling
was removed", months later, with nothing pointing at the port.

Mapping, and where it is not exact:

===========================  ==============================  ====================
pyrfc                        saprfclib                       exact?
===========================  ==============================  ====================
``ABAPApplicationError``     :class:`AbapApplicationError`    yes
``ABAPRuntimeError``         :class:`AbapSystemFailure`       yes
``CommunicationError``       :class:`CommunicationError`      yes, same name
``ExternalRuntimeError``     :class:`SapRfcError`             widened
``LogonError``               :class:`LogonError`              yes, same name
===========================  ==============================  ====================

The widened row is the one to read before relying on it.

``ExternalRuntimeError`` is pyrfc's wrapper for failures raised inside the SDK
itself — a category that cannot exist here, because there is no SDK. It maps to
the base class so an existing handler still catches something rather than
silently matching nothing; it will also catch more than it used to.

``LogonError`` is raised for a logon the server rejects without a structured ABAP
exception — the reply to wrong credentials. A logon refused with a structured
exception (a missing authorization, for example) surfaces as the classified
:class:`AbapApplicationError` or :class:`AbapSystemFailure`, as in pyrfc.
"""

from __future__ import annotations

from saprfclib.exceptions import (
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
    LogonError,
    SapRfcError,
)

__all__ = [
    "ABAPApplicationError",
    "ABAPRuntimeError",
    "CommunicationError",
    "ExternalRuntimeError",
    "LogonError",
]

#: pyrfc's ``ABAPApplicationError`` — an exception raised by the ABAP function.
ABAPApplicationError = AbapApplicationError

#: pyrfc's ``ABAPRuntimeError`` — an ABAP-side runtime failure (short dump, etc).
ABAPRuntimeError = AbapSystemFailure

#: Same name in both libraries; re-exported so one import line covers the set.
CommunicationError = CommunicationError

#: pyrfc's wrapper for failures inside the SDK. Widened — see the module docstring.
ExternalRuntimeError = SapRfcError

#: Same name in both libraries; re-exported so one import line covers the set.
LogonError = LogonError
