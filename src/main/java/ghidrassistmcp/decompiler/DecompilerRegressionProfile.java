package ghidrassistmcp.decompiler;

import ghidra.app.decompiler.DecompileOptions;

/** An explicit opt-in profile for deterministic GUI-to-headless regression. */
public final class DecompilerRegressionProfile {
    public static final String PROPERTY = "ghidrassistmcp.regression.decompilerProfile";
    public static final String ECU411_GUI_20261028 = "ECU411_GUI_20261028";

    private DecompilerRegressionProfile() {}

    public static String activeProfile() {
        String value = System.getProperty(PROPERTY);
        return value == null || value.isBlank() ? null : value;
    }

    public static void apply(DecompileOptions options, String profile) {
        if (profile == null || profile.isBlank()) return;
        if (!ECU411_GUI_20261028.equals(profile)) {
            throw new IllegalArgumentException("Unsupported explicit regression decompiler profile: " + profile);
        }
        // Exact CodeBrowser effective options from the captured GUI configuration.
        options.setEliminateUnreachable(false);
        options.setMaxPayloadMBytes(150);
        options.setNamespaceStrategy(DecompileOptions.NamespaceStrategy.All);
        options.setPLATECommentIncluded(true);
        options.setMaxWidth(160);
        options.setIndentWidth(4);
        options.setNullToken(true);
        options.setAnalyzeForLoops(true);
        options.setIgnoreUnimplemented(false);
        options.setDefaultTimeout(30);
        options.setMaxInstructions(100000);
        options.setMaxJumpTableEntries(1024);
        options.setProtoEvalModel("__stdcall");
    }
}
