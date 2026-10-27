// Diagnostic only: no program, options or user preferences are changed.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.pcode.*;
import ghidrassistmcp.decompiler.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class GAMCPDecompilerContract extends GhidraScript {
 private final Gson json=new GsonBuilder().setPrettyPrinting().create();
 private JsonObject measure(String id,boolean keep,String style,boolean service) throws Exception {
  var function=getFunctionAt(toAddr(0x6e968));
  DecompilerSession session=service?new DecompilerService(program->null).open(currentProgram):null;
  DecompileOptions options=service?session.options():DecompilerUtils.getDecompileOptions(null,currentProgram);
  if(!service)options.setEliminateUnreachable(!keep);
  DecompInterface decompiler=service?session.decompiler():new DecompInterface();
  try {
   if(!service){decompiler.setOptions(options);decompiler.openProgram(currentProgram);}
   decompiler.setSimplificationStyle(style);
   var result=decompiler.decompileFunction(function,options.getDefaultTimeout(),monitor);
   JsonObject value=new JsonObject();value.addProperty("id",id);value.addProperty("style",style);
   value.addProperty("service",service);value.addProperty("eliminate_unreachable",options.isEliminateUnreachable());
   value.addProperty("completed",result.decompileCompleted());value.addProperty("timed_out",result.isTimedOut());value.addProperty("error",result.getErrorMessage());
   JsonObject getters=new JsonObject();
   var methods=new ArrayList<>(Arrays.asList(DecompileOptions.class.getMethods()));methods.sort(Comparator.comparing(java.lang.reflect.Method::getName));
   for(var method:methods)if(method.getParameterCount()==0&&!method.getName().equals("getClass")&&(method.getName().startsWith("get")||method.getName().startsWith("is"))) {
    try{Object setting=method.invoke(options);getters.addProperty(method.getName(),String.valueOf(setting));}catch(Exception ignored){}
   }
   value.add("effective_options",getters);
   String c=result.getDecompiledFunction()==null?"":result.getDecompiledFunction().getC();
   value.addProperty("c",c);value.addProperty("c_characters",c.length());
   String pseudo="Decompiled function "+function.getName(true)+":\n\n"+c;
   value.addProperty("mcp_pseudocode_source",pseudo);value.addProperty("mcp_pseudocode_characters",pseudo.length());
   var high=result.getHighFunction();JsonArray ops=new JsonArray();
   StringBuilder raw=new StringBuilder("P-Code for: "+function.getName(true)+" @ "+function.getEntryPoint()+"\n\n## Raw P-Code Operations:\n```\n");
   if(high!=null){var iterator=high.getPcodeOps();while(iterator.hasNext()){var op=iterator.next();String text=op.getSeqnum().getTarget()+": "+op;ops.add(text);raw.append(text).append('\n');}}
   raw.append("```\n## Summary:\n- Function: ").append(function.getName(true)).append("\n- Entry: ").append(function.getEntryPoint()).append("\n- Basic Blocks: ").append(high==null?0:high.getBasicBlocks().size()).append('\n');
   value.addProperty("high_basic_blocks",high==null?0:high.getBasicBlocks().size());value.addProperty("high_operations",ops.size());value.add("high_operation_text",ops);
   value.addProperty("mcp_raw_source",raw.toString());value.addProperty("mcp_raw_characters",raw.length());
   return value;
  }finally{if(session!=null)session.close();else decompiler.dispose();}
 }
 public void run()throws Exception {
  JsonObject out=new JsonObject();out.addProperty("run_id",getScriptArgs()[1]);out.addProperty("generated_at",java.time.Instant.now().toString());
  out.addProperty("program",currentProgram.getName());out.addProperty("project",currentProgram.getDomainFile().getProjectLocator().toString());out.addProperty("program_sha256",currentProgram.getExecutableSHA256());
  out.addProperty("language",currentProgram.getLanguageID().toString());out.addProperty("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
  out.addProperty("function_count",currentProgram.getFunctionManager().getFunctionCount());
  out.addProperty("options_fingerprint",new DecompilerService(program->null).getOptionsFingerprint(currentProgram));
  JsonObject profiles=new JsonObject();
  profiles.add("default",measure("default",false,"decompile",true));profiles.add("default_repeat",measure("default_repeat",false,"decompile",true));
  profiles.add("keep_unreachable",measure("keep_unreachable",true,"decompile",false));profiles.add("keep_repeat",measure("keep_repeat",true,"decompile",false));
  profiles.add("normalize_keep",measure("normalize_keep",true,"normalize",false));out.add("profiles",profiles);
  JsonArray machine=new JsonArray();for(long address:new long[]{0x6e98a,0x6e992}){JsonObject instruction=new JsonObject();instruction.addProperty("address",toAddr(address).toString());JsonArray text=new JsonArray();for(var op:getInstructionAt(toAddr(address)).getPcode())text.add(op.toString());instruction.add("operations",text);machine.add(instruction);}out.add("machine_instruction_pcode",machine);
  Files.writeString(Path.of(getScriptArgs()[0]),json.toJson(out)+"\n");
  println("DECOMPILER_CONTRACT written to "+getScriptArgs()[0]);
 }
}
