# Logon language

Helpers for converting between the two-character ISO language code and the
one-character SAP language code that the RFC logon frame carries.

Both names match the equivalents exposed by `pyrfc`
(`language_iso_to_sap` / `language_sap_to_iso`), which in turn wrap
`RfcLanguageIsoToSap` / `RfcLanguageSapToIso` in the SAP NetWeaver RFC SDK.

The ISO code is case-insensitive; the SAP code is case-sensitive (`"a"` is
Afrikaans, `"A"` Arabic). The table covers the 41 languages the reference
conversion knows, including the lowercase codes `a`, `b`, `c`, `d` and `i`.

See [Connection Options](../getting-started/connection-options.md#logon-language)
for how this interacts with `connect(lang=…)`.

::: saprfclib.language_iso_to_sap
    options:
      show_root_heading: true

::: saprfclib.language_sap_to_iso
    options:
      show_root_heading: true
