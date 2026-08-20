# TABLE Parameters

Use TABLE parameters to pass rows of structured data into an RFC call (input tables) or to
receive multiple result rows back (output tables).  The pattern is identical for both directions:
Python lists of dicts where each dict key matches an ABAP structure field name.

## Reading rows with RFC_READ_TABLE

```python
import saprfclib

conn = saprfclib.connect(
    ashost="sap-host",
    sysnr=0,
    client="100",
    user="RFC_USER",
    passwd="secret",
)

# FIELDS is a TABLE input parameter.  Pass a list of dicts with the field name you want.
result = conn.call(
    "RFC_READ_TABLE",
    QUERY_TABLE="T001",        # Table to read (company codes)
    DELIMITER="|",             # Delimiter inserted between fields in each DATA row
    ROWCOUNT=10,               # Maximum rows to return (0 = all)
    FIELDS=[
        {"FIELDNAME": "MANDT"},
        {"FIELDNAME": "BUKRS"},
        {"FIELDNAME": "BUTXT"},
    ],
)

# DATA comes back as a list of dicts; each dict has a WA key with the delimited string.
print(f"Returned {len(result['DATA'])} rows")
for row in result["DATA"]:
    print(row["WA"])           # e.g. "100|1000|SAP SE"

conn.close()
```

## Passing SELECT_OPTIONS-style table input

Some RFC function modules accept an `OPTIONS` or `SELECT_OPTIONS` table parameter that
contains WHERE-clause fragments (one per row).

```python
import saprfclib

conn = saprfclib.connect(
    ashost="sap-host",
    sysnr=0,
    client="100",
    user="RFC_USER",
    passwd="secret",
)

# Each OPTIONS row has a TEXT field containing a partial WHERE clause fragment.
result = conn.call(
    "RFC_READ_TABLE",
    QUERY_TABLE="MARC",        # Material-Plant data
    DELIMITER="|",
    ROWCOUNT=5,
    OPTIONS=[
        {"TEXT": "MATNR LIKE '1%'"},   # Each row = one WHERE clause line
    ],
)

for row in result["DATA"]:
    print(row["WA"])

conn.close()
```

## Tips

- `ROWCOUNT=0` returns all rows — be cautious on large tables.
- If `DELIMITER` is omitted, all field values are concatenated without a separator.
- To pass multiple WHERE conditions, add multiple rows to `OPTIONS`.  SAP joins them with AND.
- The `FIELDS` table is optional: omitting it returns all fields concatenated.
