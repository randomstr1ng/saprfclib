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
``LogonError``               :class:`CommunicationError`      widened
===========================  ==============================  ====================

The two widened rows are the ones to read before relying on them.

``ExternalRuntimeError`` is pyrfc's wrapper for failures raised inside the SDK
itself — a category that cannot exist here, because there is no SDK. It maps to
the base class so an existing handler still catches something rather than
silently matching nothing; it will also catch more than it used to.

``LogonError`` is the one worth checking by hand. pyrfc raises it for a rejected
logon. This library does not have a dedicated exception for that: depending on
how far the handshake got, a rejection surfaces as
:class:`CommunicationError` or :class:`AbapSystemFailure`. The alias points at
the first, which is the common case, so a handler that catches only
``LogonError`` can still miss a rejection that failed later in the handshake.
Catch :class:`SapRfcError` if the intent is "the logon did not work".

A dedicated ``LogonFailure`` raised at the logon boundary would be worth having
on its own merits, independent of pyrfc parity. It is not defined here because
an exception nothing raises is worse than no exception at all: every ``except``
clause written against it would be dead code that reads as live.
"""

from __future__ import annotations

from saprfclib.exceptions import (
    AbapApplicationError,
    AbapSystemFailure,
    CommunicationError,
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

#: pyrfc's rejected-logon exception. Widened — see the module docstring.
LogonError = CommunicationError
