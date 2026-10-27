package ghidrassistmcp.tools;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
class GetCodeTextPaginationTest {
 private String page(String text,int offset,int max)throws Exception{
  var method=GetCodeTool.class.getDeclaredMethod("paginateText",String.class,Map.class);method.setAccessible(true);
  return (String)method.invoke(null,text,Map.of("char_offset",offset,"max_chars",max));
 }
 @Test void preservesEverySourceCharacterAndUsesRealNewlines()throws Exception {
  String source="x".repeat(2151);String first=page(source,0,1200),last=page(source,1200,1200);
  assertTrue(first.contains("\n\nPAGINATION totalCharacters=2151 returnedCharacters=1200"));
  assertTrue(last.contains("returnedCharacters=951"));
  assertEquals(source,first.substring(0,1200)+last.substring(0,951));
  assertFalse(first.contains("\\n\\nPAGINATION"));
 }
 @Test void handlesEmptyTailWithoutInventingCharacters()throws Exception {
  String result=page("abc",1200,1200);assertTrue(result.startsWith("\n\nPAGINATION"));
  assertTrue(result.contains("totalCharacters=3 returnedCharacters=0 charOffset=1200 hasMore=false"));
 }
}
