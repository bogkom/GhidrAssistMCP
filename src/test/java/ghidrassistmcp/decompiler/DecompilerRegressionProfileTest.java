package ghidrassistmcp.decompiler;

import ghidra.app.decompiler.DecompileOptions;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DecompilerRegressionProfileTest {
    @Test void absentProfilePreservesOriginalOptions() {
        DecompileOptions options = new DecompileOptions();
        boolean eliminate = options.isEliminateUnreachable();
        int width = options.getMaxWidth();
        DecompilerRegressionProfile.apply(options, null);
        assertEquals(eliminate, options.isEliminateUnreachable());
        assertEquals(width, options.getMaxWidth());
    }

    @Test void explicitProfileMatchesGuiConfiguration() {
        DecompileOptions options = new DecompileOptions();
        DecompilerRegressionProfile.apply(options, DecompilerRegressionProfile.ECU411_GUI_20261028);
        assertFalse(options.isEliminateUnreachable());
        assertEquals(150, options.getMaxPayloadMBytes());
        assertEquals(DecompileOptions.NamespaceStrategy.All, options.getNamespaceStrategy());
        assertTrue(options.isPLATECommentIncluded());
        assertEquals(160, options.getMaxWidth());
        assertEquals(4, options.getIndentWidth());
        assertTrue(options.isNullToken());
        assertTrue(options.isAnalyzeForLoops());
        assertFalse(options.isIgnoreUnimplemented());
        assertEquals(30, options.getDefaultTimeout());
        assertEquals(100000, options.getMaxInstructions());
        assertEquals(1024, options.getMaxJumpTableEntries());
        assertEquals("__stdcall", options.getProtoEvalModel());
    }

    @Test void unknownProfileIsRejected() {
        assertThrows(IllegalArgumentException.class,
            () -> DecompilerRegressionProfile.apply(new DecompileOptions(), "NO_SUCH_PROFILE"));
    }
}
