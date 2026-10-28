// @category GhidrAssistRegression
// Fail-closed read-only preflight before the isolated MCP server starts.
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class ECU411TargetPreflight extends GhidraScript {
    private static void require(boolean valid, String message) {
        if (!valid) throw new IllegalStateException("REGRESSION PREFLIGHT FAILED: " + message);
    }
    private static String value(JsonObject object, String key) { return object.get(key).getAsString(); }
    private String instructionHash(Function f) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) digest.update(it.next().getBytes());
        return java.util.HexFormat.of().formatHex(digest.digest());
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 2, "expected GUI snapshot and output path");
        Path baseline = Path.of(args[0]), output = Path.of(args[1]);
        JsonObject gui = JsonParser.parseString(Files.readString(baseline)).getAsJsonObject();
        JsonObject options = gui.getAsJsonObject("guiAsIs").getAsJsonObject("effectiveOptions");
        JsonObject expected = gui.getAsJsonObject("function");
        require("ECU411_GUI_20261028".equals(System.getProperty("ghidrassistmcp.regression.decompilerProfile")),
            "explicit profile is not active");
        require(!options.get("eliminateUnreachable").getAsBoolean() &&
            options.get("maxPayloadMBytes").getAsInt()==150 &&
            "Always".equals(value(options,"namespaceStrategy")) &&
            options.get("plateCommentIncluded").getAsBoolean() &&
            options.get("maxWidth").getAsInt()==160 &&
            options.get("indentWidth").getAsInt()==4 &&
            options.get("nullToken").getAsBoolean(), "invalid GUI baseline options");
        require(gui.getAsJsonObject("guiAsIs").get("mcpPseudocodeCharacters").getAsInt()==2151 &&
            gui.getAsJsonObject("guiAsIs").get("mcpRawPcodeCharacters").getAsInt()==10252,
            "reference counts differ from original manual tests");
        require(value(gui,"programName").equals(currentProgram.getName()), "program name");
        require(value(gui,"executableSha256").equals(currentProgram.getExecutableSHA256()), "firmware SHA256");
        require(value(gui,"languageId").equals(currentProgram.getLanguageID().toString()), "language ID");
        require(value(gui,"compilerSpec").equals(currentProgram.getCompilerSpec().getCompilerSpecID().toString()), "compiler spec");
        require(gui.get("functionCount").getAsInt()==currentProgram.getFunctionManager().getFunctionCount(), "function count");
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        JsonArray expectedBlocks = gui.getAsJsonArray("memoryBlocks");
        require(blocks.length == expectedBlocks.size(), "memory block count");
        for (int i=0;i<blocks.length;i++) {
            JsonObject b=expectedBlocks.get(i).getAsJsonObject();
            require(value(b,"name").equals(blocks[i].getName()) &&
                value(b,"start").equals(blocks[i].getStart().toString()) &&
                value(b,"end").equals(blocks[i].getEnd().toString()),"memory block " + i);
        }
        Function f=getFunctionAt(toAddr(0x0006e968L));
        require(f!=null,"missing FUN_0006e968");
        require(value(expected,"name").equals(f.getName(true)),"function name");
        require(value(expected,"signature").equals(f.getSignature().toString()),"function signature");
        require(value(expected,"bodyStart").equals(f.getBody().getMinAddress().toString()),"function start");
        require(value(expected,"bodyEnd").equals(f.getBody().getMaxAddress().toString()),"function end");
        require(value(expected,"instructionBytesSha256").equals(instructionHash(f)),"instruction bytes");
        JsonObject result=new JsonObject();
        result.addProperty("pass",true);result.addProperty("profile","ECU411_GUI_20261028");
        result.addProperty("functionCount",currentProgram.getFunctionManager().getFunctionCount());
        result.addProperty("memoryBlockCount",blocks.length);
        result.addProperty("expectedPseudocodeLength",2151);result.addProperty("expectedRawPcodeLength",10252);
        Files.createDirectories(output.getParent());
        Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n",StandardCharsets.UTF_8);
        println("ECU411_REGRESSION_PREFLIGHT_PASS="+output);
    }
}
