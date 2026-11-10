# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pure-Python Kerberos 5 client pieces used by Kerberos-based SNC.

Nothing here is imported unless Kerberos SNC parameters are given.
"""

from saprfclib.krb5.login import KerberosLogin

__all__ = ["KerberosLogin"]
