# ECU411 regression: explicit GUI profile in isolated Ghidra Headless

The three historical assertions (pseudocode total 2151, last-page length 951,
raw HighFunction P-code total 10252) are **not** rebaselined. The user reproduced
these values in Ghidra CodeBrowser and in Headless on an identical copy of the
analyzed project (909 functions, 8 memory blocks). Old Headless regression
runs used a different analyzed project (960 functions, 5 blocks) and default
decompiler options (including eliminate unreachable code = true), producing
872/144.

## Controlled opt-in

For the **isolated test Headless JVM only**, set:

```sh
JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Dghidrassistmcp.regression.decompilerProfile=ECU411_GUI_20261028"
```

Normal GUI and MCP defaults remain untouched if the property is unset. Unknown
nonempty profiles fail closed. The explicit profile recreates the GUI options
captured in `ECU411_GUI_CONFIG.json`; it never changes a Program database.

Before launching MCP and calling the three tools, an **external harness** must
make a physical copy of `.gpr` + `.rep` and run a read-only Ghidra preflight:
SHA-256, language, compiler spec, function count, memory block map,
`FUN_0006e968` body, signature, and instruction-byte hash must match the
GUI snapshot. In the same JVM regression profile must be active. If any check
fails, **do not run MCP assertions**. Use the recorded historical expectations
unchanged and capture full raw MCP responses.

The regression fixture contains no user binary, Ghidra project or API credentials.
`-noanalysis -readOnly` is required. A passing native Ghidra reproduction is
not by itself a claim that the original three MCP tests passed; these require
an actual MCP run in this isolated process.
