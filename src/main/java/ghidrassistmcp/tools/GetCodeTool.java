/*
 * MCP tool for getting code representation of a function.
 * Consolidates decompile_function, disassemble_function, and get_pcode into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets code representation of a function in various formats.
 * Replaces separate decompile_function, disassemble_function, and get_pcode tools.
 */
public class GetCodeTool implements McpTool {

    private final DecompilerService decompilerService;

    public GetCodeTool(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public boolean isLongRunning() {
        // Decompiler and pcode formats require decompilation
        return true;
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getCacheDiscriminator(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend) {
        String format = (String) arguments.get("format");
        if (format != null && format.equalsIgnoreCase("disassembly")) {
            return "disassembly";
        }
        return decompilerService.getOptionsFingerprint(currentProgram);
    }

    @Override
    public String getName() {
        return "get_code";
    }

    @Override
    public String getDescription() {
        return "Get code representation of a function in various formats (decompiler, disassembly, or pcode)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "function", Map.of(
                    "type", "string",
                    "description", "Function identifier (name, qualified name like Namespace::Func, or address like 0x401000)"
                ),
                "format", Map.of(
                    "type", "string",
                    "description", "Output format for the requested function",
                    "enum", List.of("decompiler", "disassembly", "pcode")
                ),
                "raw", Map.of(
                    "type", "boolean",
                    "description", "Optional: Only affects format 'pcode' (raw pcode ops vs grouped by basic blocks)",
                    "default", false
                ),
                "start_address", Map.of("type", "string", "description", "Optional first instruction address for disassembly"),
                "end_address", Map.of("type", "string", "description", "Optional inclusive final instruction address for disassembly"),
                "offset", Map.of("type", "integer", "minimum", 0, "description", "Instruction offset in disassembly range"),
                "max_instructions", Map.of("type", "integer", "minimum", 1, "description", "Maximum disassembly instructions returned per page"),
                "char_offset", Map.of("type", "integer", "minimum", 0, "description", "Character offset for paged pseudocode or pcode"),
                "max_chars", Map.of("type", "integer", "minimum", 1, "description", "Maximum characters per pseudocode/pcode result (default 16000)")
            ),
            List.of("function", "format"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return executeWithMonitor(arguments, currentProgram, TaskMonitor.DUMMY);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, McpTask task) {
        TaskMonitor monitor = new McpTaskMonitor(task, 0, 100, "Retrieving function code");
        return executeWithMonitor(arguments, currentProgram, monitor);
    }

    private McpSchema.CallToolResult executeWithMonitor(Map<String, Object> arguments,
            Program currentProgram, TaskMonitor monitor) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .isError(true)
                .build();
        }

        String functionIdentifier = (String) arguments.get("function");
        String format = (String) arguments.get("format");
        boolean raw = Boolean.TRUE.equals(arguments.get("raw"));

        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function parameter is required")
                .isError(true)
                .build();
        }

        if (format == null || format.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("format parameter is required (decompiler, disassembly, or pcode)")
                .isError(true)
                .build();
        }

        format = format.toLowerCase();
        if (!format.equals("decompiler") && !format.equals("disassembly") && !format.equals("pcode")) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid format. Use 'decompiler', 'disassembly', or 'pcode'")
                .isError(true)
                .build();
        }

        // Find the function
        Function function = findFunction(currentProgram, functionIdentifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionIdentifier)
                .isError(true)
                .build();
        }

        // Dispatch to appropriate handler based on format
        switch (format) {
            case "decompiler":
                return getDecompiledCode(currentProgram, function, arguments, monitor);
            case "disassembly":
                return getDisassemblyCode(currentProgram, function, arguments, monitor);
            case "pcode":
                return getPcodeRepresentation(currentProgram, function, arguments, raw, monitor);
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Unknown format: " + format)
                    .isError(true)
                    .build();
        }
    }

    /**
     * Get decompiled C-like code for a function.
     */
    private McpSchema.CallToolResult getDecompiledCode(Program program, Function function, Map<String, Object> args, TaskMonitor monitor) {
        try (DecompilerSession session = decompilerService.open(function.getProgram())) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), monitor);

            if (monitor.isCancelled()) {
                return cancelledResult();
            }
            if (results.isTimedOut()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation timed out for function: " + function.getName(true))
                    .isError(true)
                    .build();
            }

            if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation error for function " + function.getName(true) + ": " + results.getErrorMessage())
                    .isError(true)
                    .build();
            }

            String decompiledCode = results.getDecompiledFunction().getC();

            if (decompiledCode == null || decompiledCode.trim().isEmpty()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No decompiled code available for function: " + function.getName(true))
                    .isError(true)
                    .build();
            }

            return McpSchema.CallToolResult.builder()
                .addTextContent(paginateText("Decompiled function " + function.getName(true) + ":\n\n" + decompiledCode, args))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error decompiling function " + function.getName(true) + ": " + e.getMessage())
                .isError(true)
                .build();
        }
    }

    /**
     * Get disassembly for a function.
     */
    private McpSchema.CallToolResult getDisassemblyCode(Program program, Function function,
            Map<String, Object> arguments, TaskMonitor monitor) {
        StringBuilder result = new StringBuilder();
        result.append("Disassembly of function: ").append(function.getName(true)).append("\\n");
        result.append("Entry Point: ").append(function.getEntryPoint()).append("\\n\\n");

        Address start = function.getBody().getMinAddress();
        Address end = function.getBody().getMaxAddress();
        try {
            if (arguments.get("start_address") instanceof String value && !value.isBlank()) {
                start = program.getAddressFactory().getAddress(value);
            }
            if (arguments.get("end_address") instanceof String value && !value.isBlank()) {
                end = program.getAddressFactory().getAddress(value);
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid disassembly address: " + e.getMessage())
                .isError(true).build();
        }
        if (start == null || end == null || start.compareTo(end) > 0) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid disassembly range")
                .isError(true).build();
        }
        int offset = arguments.get("offset") instanceof Number n ? n.intValue() : 0;
        int max = arguments.get("max_instructions") instanceof Number n ? n.intValue() : 100;
        if (offset < 0 || max < 1) {
            return McpSchema.CallToolResult.builder().addTextContent("offset must be >= 0 and max_instructions >= 1")
                .isError(true).build();
        }

        InstructionIterator iter = program.getListing().getInstructions(function.getBody(), true);
        int total = 0;
        int returned = 0;
        Address first = null;
        Address last = null;
        while (iter.hasNext()) {
            if (monitor.isCancelled()) return cancelledResult();
            Instruction instruction = iter.next();
            Address address = instruction.getAddress();
            if (address.compareTo(start) < 0 || address.compareTo(end) > 0) continue;
            if (total >= offset && returned < max) {
                if (first == null) first = address;
                last = address;
                result.append(address).append(": ").append(instruction.getMnemonicString());
                for (int i = 0; i < instruction.getNumOperands(); i++) {
                    result.append(i == 0 ? " " : ", ").append(instruction.getDefaultOperandRepresentation(i));
                }
                String comment = instruction.getComment(CommentType.EOL);
                if (comment != null && !comment.isBlank()) result.append(" ; ").append(comment.trim());
                result.append("\\n");
                returned++;
            }
            total++;
        }
        boolean hasMore = total > (long) offset + returned;
        result.append("\\nTotal instructions in requested range: ").append(total)
              .append("\\nreturnedCount=").append(returned)
              .append(" offset=").append(offset)
              .append(" hasMore=").append(hasMore)
              .append(" truncated=").append(hasMore)
              .append(" nextOffset=").append(hasMore ? Integer.toString(offset + returned) : "null")
              .append(" firstAddress=").append(first == null ? "null" : first)
              .append(" lastAddress=").append(last == null ? "null" : last);
        return McpSchema.CallToolResult.builder().addTextContent(result.toString()).build();
    }

    /**
     * Get P-Code representation for a function.
     */
    private McpSchema.CallToolResult getPcodeRepresentation(Program program, Function function, Map<String, Object> args, boolean raw, TaskMonitor monitor) {
        StringBuilder result = new StringBuilder();
        result.append("P-Code for: ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        try (DecompilerSession session = decompilerService.open(program)) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), monitor);

            if (monitor.isCancelled()) {
                return cancelledResult();
            }
            if (!results.decompileCompleted()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Decompilation failed for function: " + function.getName(true))
                    .isError(true)
                    .build();
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Could not get high function for: " + function.getName(true))
                    .isError(true)
                    .build();
            }

            // Get P-Code operations
            if (raw) {
                // Raw P-Code from high function
                result.append("## Raw P-Code Operations:\n```\n");
                Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
                while (ops.hasNext()) {
                    if (monitor.isCancelled()) {
                        return cancelledResult();
                    }
                    PcodeOpAST op = ops.next();
                    result.append(op.getSeqnum().getTarget()).append(": ")
                          .append(op.toString()).append("\n");
                }
                result.append("```\n");
            } else {
                // P-Code organized by basic blocks
                result.append("## P-Code by Basic Blocks:\n\n");
                var blocks = highFunction.getBasicBlocks();

                for (var block : blocks) {
                    if (monitor.isCancelled()) {
                        return cancelledResult();
                    }
                    if (block instanceof PcodeBlockBasic basicBlock) {
                        result.append("### Block ").append(basicBlock.getIndex())
                              .append(" @ ").append(basicBlock.getStart()).append("\n");
                        result.append("```\n");

                        Iterator<PcodeOp> blockOps = basicBlock.getIterator();
                        while (blockOps.hasNext()) {
                            if (monitor.isCancelled()) {
                                return cancelledResult();
                            }
                            PcodeOp op = blockOps.next();
                            result.append("  ").append(op.toString()).append("\n");
                        }
                        result.append("```\n\n");
                    }
                }
            }

            // Add summary
            result.append("## Summary:\n");
            result.append("- Function: ").append(function.getName(true)).append("\n");
            result.append("- Entry: ").append(function.getEntryPoint()).append("\n");

            var blocks = highFunction.getBasicBlocks();
            result.append("- Basic Blocks: ").append(blocks.size()).append("\n");

        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(paginateText(result.toString(), args))
            .build();
    }

    /** Bounded result pages preserve complete source text without downstream truncation. */
    private static String paginateText(String content, Map<String,Object> args) {
        int offset = args.get("char_offset") instanceof Number n ? n.intValue() : 0;
        int max = args.get("max_chars") instanceof Number n ? n.intValue() : 16000;
        if (offset < 0 || max < 1 || max > 64000)
            return "ERROR: char_offset must be >=0 and max_chars must be 1..64000";
        int from = Math.min(offset, content.length());
        int to = (int) Math.min(content.length(), (long) from + max);
        boolean hasMore = to < content.length();
        return content.substring(from, to)
            + "\n\nPAGINATION totalCharacters=" + content.length()
            + " returnedCharacters=" + (to-from)
            + " charOffset=" + offset
            + " hasMore=" + hasMore
            + " truncated=" + hasMore
            + " nextCharOffset=" + (hasMore ? Integer.toString(to) : "null");
    }

    private static McpSchema.CallToolResult cancelledResult() {
        return McpSchema.CallToolResult.builder()
            .addTextContent("Function code retrieval cancelled")
            .isError(true)
            .build();
    }

    /**
     * Find a function by name or address.
     * Supports C++ qualified names (e.g., "Class::method" or "Outer::Inner::method").
     */
    private Function findFunction(Program program, String identifier) {
        // Try to parse as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                // Try to get function at the address
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;

                // If not found at address, try containing function
                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not an address, try as function name
        }

        // Handles C++ qualified names (Class::method) and plain names
        return FunctionLookup.findByQualifiedName(program, identifier);
    }
}
