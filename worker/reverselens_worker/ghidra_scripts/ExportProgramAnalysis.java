// ReverseLens bounded headless native analysis export.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;

public class ExportProgramAnalysis extends ghidra.app.script.GhidraScript {
    private static final int MAX_FUNCTIONS = 3000;
    private static final int MAX_CALL_EDGES = 20000;
    private static final int MAX_PSEUDOCODE_CHARS = 12000;

    private String escape(String value) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (ch < 0x20) out.append(String.format("\\u%04x", (int) ch));
                    else out.append(ch);
            }
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("Expected output directory.");
        File outputDirectory = new File(args[0]);
        outputDirectory.mkdirs();
        String safeName = currentProgram.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File output = new File(outputDirectory, safeName + ".json");

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        StringBuilder functionsJson = new StringBuilder();
        StringBuilder callsJson = new StringBuilder();
        Set<String> seenCalls = new HashSet<>();
        int functionCount = 0, callCount = 0;
        boolean firstFunction = true, firstCall = true;

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && functionCount < MAX_FUNCTIONS && !monitor.isCancelled()) {
            Function function = functions.next();
            if (!firstFunction) functionsJson.append(',');
            firstFunction = false;
            String name = function.getName();
            String entry = function.getEntryPoint().toString();
            String pseudocode = "";
            if (functionCount < 750) {
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    pseudocode = result.getDecompiledFunction().getC();
                    if (pseudocode.length() > MAX_PSEUDOCODE_CHARS)
                        pseudocode = pseudocode.substring(0, MAX_PSEUDOCODE_CHARS);
                }
            }
            functionsJson.append("{\"name\":\"").append(escape(name))
                .append("\",\"entry\":\"").append(escape(entry))
                .append("\",\"pseudocode\":\"").append(escape(pseudocode)).append("\"}");

            AddressIterator addresses = function.getBody().getAddresses(true);
            while (addresses.hasNext() && callCount < MAX_CALL_EDGES && !monitor.isCancelled()) {
                Address from = addresses.next();
                Reference[] references = currentProgram.getReferenceManager().getReferencesFrom(from);
                for (Reference reference : references) {
                    if (!reference.getReferenceType().isCall()) continue;
                    Function target = currentProgram.getFunctionManager().getFunctionContaining(reference.getToAddress());
                    if (target == null) continue;
                    String key = entry + "->" + target.getEntryPoint();
                    if (!seenCalls.add(key)) continue;
                    if (!firstCall) callsJson.append(',');
                    firstCall = false;
                    callsJson.append("{\"caller\":\"").append(escape(entry))
                        .append("\",\"callee\":\"").append(escape(target.getEntryPoint().toString()))
                        .append("\",\"caller_name\":\"").append(escape(name))
                        .append("\",\"callee_name\":\"").append(escape(target.getName()))
                        .append("\",\"at\":\"").append(escape(from.toString())).append("\"}");
                    callCount++;
                    if (callCount >= MAX_CALL_EDGES) break;
                }
            }
            functionCount++;
        }
        decompiler.dispose();

        String json = "{"
            + "\"schema_version\":\"1.0.0\","
            + "\"binary_name\":\"" + escape(currentProgram.getName()) + "\","
            + "\"language_id\":\"" + escape(currentProgram.getLanguageID().toString()) + "\","
            + "\"compiler_spec\":\"" + escape(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\","
            + "\"functions\":[" + functionsJson + "],"
            + "\"call_edges\":[" + callsJson + "],"
            + "\"limits\":{\"max_functions\":" + MAX_FUNCTIONS
            + ",\"max_call_edges\":" + MAX_CALL_EDGES
            + ",\"decompiled_functions\":750},"
            + "\"limitations\":[\"Static disassembler references are not proof of runtime execution.\","
            + "\"Only the first 750 functions are decompiled to pseudocode.\","
            + "\"Function and call export is capped to protect worker resources.\"]"
            + "}";
        Files.writeString(output.toPath(), json, StandardCharsets.UTF_8);
    }
}
