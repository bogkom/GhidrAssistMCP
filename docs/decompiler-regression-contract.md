# Repeatable decompiler contract and unresolved historical reference

Ghidra 12.1.4 PUBLIC; language `68000:BE:32:CPU32`; function `FUN_0006e968`
at `0006e968`; firmware SHA-256
`b90638412e1955198c67bb1189446e2374a0d468d527aaeba0a218e767d9e296`.
The regression opens an isolated copy of the already analyzed ECU411 project,
uses `-noanalysis -readOnly`, a fresh settings directory, and the production
DecompilerService with a null tool resolver. Simplification action is `decompile`.
No user CodeBrowser settings are inherited. Effective getters, compiler spec,
full C text, HighFunction operations, source frames before pagination, program
identity and repeat runs are exported by `GAMCPDecompilerContract.java`.

Evidence: `evidence/runs/20261027T122424.764556Z-82c0b6ee/` in the regression
workspace. Results are deliberately distinct from the historical assertions:

| Profile | Pseudocode frame | Raw HighFunction frame | Blocks | Operations |
|---|---:|---:|---:|---:|
| Production headless defaults, eliminate unreachable=true | 872 | 144 | 2 | 0 |
| Only eliminate unreachable=false | 2617 | 12031 | 12 | 197 |
| Same profiles repeated | identical | identical | identical | identical |

The full MCP source and both pages match the native oracle byte for byte.
`totalCharacters` describes the full framed source; `char_offset` only selects
its substring. Thus the 872/144 discrepancy is not lost response content or a
pagination cap. `raw=true` enumerates `HighFunction.getPcodeOps()`, not p-code
obtained from individual machine instructions. The latter separately retains
the watchdog writes of 0x55 and 0xAA.

The saved user CodeBrowser option was false. Reproducing that switch alone does
not reproduce historical lengths 2151/10252. Trying a different simplification
action is not a valid replacement: `normalize` does not produce the same C view.
The exact reference project/decompiler configuration and complete original output
are not available from lengths alone. Therefore the three historical assertions
remain FAIL and unchanged. A future reference must carry this complete contract,
not just a firmware hash and output length. The current native comparison is an
additional consistency test, not a rebaseline of those reference cases.

A separate formatting defect was confirmed and fixed: `paginateText` appended
literal backslash-n sequences before its footer. It now uses real newlines.
Two unit tests verify complete 1200+951 substring reconstruction and an empty
tail, without changing the source-length calculation or production defaults.
