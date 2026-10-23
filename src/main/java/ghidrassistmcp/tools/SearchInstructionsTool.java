package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Search only decoded instructions, never arbitrary byte-pattern matches.
 * Register direction comes from the Ghidra instruction input/result objects.
 */
public final class SearchInstructionsTool implements McpTool {
    @Override public String getName() { return "search_instructions"; }
    @Override public String getDescription() {
        return "Search decoded instructions globally by mnemonic, operand text and CPU register "
            + "with optional read/write access. Results include address, function, instruction and pagination.";
    }
    @Override public boolean isCacheable() { return true; }

    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "mnemonic", Map.of("type","string","description","Optional mnemonic, e.g. MOVEC"),
            "operand_text", Map.of("type","string","description","Optional operand substring"),
            "register", Map.of("type","string","description","Optional CPU register name, e.g. VBR"),
            "access", Map.of("type","string","enum",List.of("read","write","either"),"default","either"),
            "offset", Map.of("type","integer","minimum",0),
            "limit", Map.of("type","integer","minimum",1,"maximum",1000)
        ), List.of(),null,null,null);
    }

    private static boolean containsRegister(Object[] objects, String name) {
        if (objects == null) return false;
        for (Object object : objects) {
            if (object instanceof Register register && register.getName().equalsIgnoreCase(name))
                return true;
        }
        return false;
    }

    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }

    @Override public McpSchema.CallToolResult execute(Map<String,Object> args, Program program) {
        if (program == null) return error("No program currently loaded");
        String mnemonic = args.get("mnemonic") instanceof String s ? s.trim() : "";
        String operand = args.get("operand_text") instanceof String s ? s.trim() : "";
        String register = args.get("register") instanceof String s ? s.trim() : "";
        String access = args.get("access") instanceof String s ? s.toLowerCase(Locale.ROOT) : "either";
        int offset = args.get("offset") instanceof Number n ? n.intValue() : 0;
        int limit = args.get("limit") instanceof Number n ? n.intValue() : 100;
        if (mnemonic.isBlank() && operand.isBlank() && register.isBlank())
            return error("Provide at least one of mnemonic, operand_text or register");
        if (!List.of("read","write","either").contains(access))
            return error("access must be read, write or either");
        if (offset < 0 || limit < 1 || limit > 1000)
            return error("offset must be nonnegative, limit must be 1..1000");

        List<Instruction> page = new ArrayList<>();
        int matches = 0;
        InstructionIterator instructions = program.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (!mnemonic.isBlank() && !instruction.getMnemonicString().equalsIgnoreCase(mnemonic))
                continue;
            StringBuilder operandText = new StringBuilder();
            for (int i=0; i<instruction.getNumOperands(); i++) {
                if (i>0) operandText.append(", ");
                operandText.append(instruction.getDefaultOperandRepresentation(i));
            }
            if (!operand.isBlank() && !operandText.toString().toLowerCase(Locale.ROOT)
                    .contains(operand.toLowerCase(Locale.ROOT))) continue;
            boolean reads = register.isBlank() || containsRegister(instruction.getInputObjects(), register);
            boolean writes = register.isBlank() || containsRegister(instruction.getResultObjects(), register);
            if (!register.isBlank() && !(reads || writes)) continue;
            if (!register.isBlank() && access.equals("read") && !reads) continue;
            if (!register.isBlank() && access.equals("write") && !writes) continue;
            if (matches >= offset && page.size() < limit) page.add(instruction);
            matches++;
        }

        StringBuilder result = new StringBuilder("Instruction search: mnemonic=").append(mnemonic)
            .append(" operand_text=").append(operand).append(" register=").append(register)
            .append(" access=").append(access).append("\n");
        for (Instruction instruction : page) {
            Function fn = program.getFunctionManager().getFunctionContaining(instruction.getAddress());
            result.append(instruction.getAddress()).append(" ")
                  .append(instruction.getMnemonicString()).append(" ");
            for (int i=0; i<instruction.getNumOperands(); i++) {
                if (i>0) result.append(", ");
                result.append(instruction.getDefaultOperandRepresentation(i));
            }
            if (!register.isBlank()) {
                boolean read = containsRegister(instruction.getInputObjects(), register);
                boolean write = containsRegister(instruction.getResultObjects(), register);
                result.append(" [").append(read ? "READ" : "")
                      .append(read && write ? "," : "")
                      .append(write ? "WRITE" : "").append("]");
            }
            result.append(" function=").append(fn == null ? "NONE" : fn.getName())
                .append("\n");
        }
        boolean hasMore = (long) offset + page.size() < matches;
        result.append("totalCount=").append(matches)
              .append(" returnedCount=").append(page.size())
              .append(" offset=").append(offset)
              .append(" hasMore=").append(hasMore)
              .append(" truncated=").append(hasMore)
              .append(" nextOffset=").append(hasMore ? Integer.toString(offset + page.size()) : "null");
        return McpSchema.CallToolResult.builder().addTextContent(result.toString()).build();
    }
}
