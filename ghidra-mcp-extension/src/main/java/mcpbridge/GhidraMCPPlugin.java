package mcpbridge;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "FirmwareMCP",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "MCP Server for Firmware RE",
    description = "Exposes firmware reverse engineering tools via MCP for LLM-driven analysis"
)
//@formatter:on
public class GhidraMCPPlugin extends ProgramPlugin {

    private HttpServer server;
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        startServer();
    }

    @Override
    protected void dispose() {
        stopServer();
        super.dispose();
    }

    private Program getActiveProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    // ── HTTP Server Lifecycle ──────────────────────────────────────────

    private void startServer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", DEFAULT_PORT), 0);

            // Health
            server.createContext("/health", this::handleHealth);
            server.createContext("/ping", this::handleHealth);

            // Environment Context
            server.createContext("/get_binary_info", this::handleGetBinaryInfo);
            server.createContext("/get_memory_map", this::handleGetMemoryMap);

            // Reconnaissance
            server.createContext("/search_strings", this::handleSearchStrings);
            server.createContext("/get_function_list", this::handleGetFunctionList);
            server.createContext("/search_bytes", this::handleSearchBytes);
            server.createContext("/get_imports", this::handleGetImports);
            server.createContext("/get_exports", this::handleGetExports);
            server.createContext("/get_segments", this::handleGetSegments);
            server.createContext("/get_data_items", this::handleGetDataItems);
            server.createContext("/disassemble_at", this::handleDisassembleAt);

            // Analysis
            server.createContext("/decompile_function", this::handleDecompileFunction);
            server.createContext("/get_function_info", this::handleGetFunctionInfo);
            server.createContext("/get_xrefs_to", this::handleGetXrefsTo);
            server.createContext("/get_xrefs_from", this::handleGetXrefsFrom);
            server.createContext("/read_raw_bytes", this::handleReadRawBytes);

            // Mutation
            server.createContext("/rename_function", this::handleRenameFunction);
            server.createContext("/add_comment", this::handleAddComment);
            server.createContext("/define_data", this::handleDefineData);
            server.createContext("/rename_data", this::handleRenameData);
            server.createContext("/create_function", this::handleCreateFunction);
            server.createContext("/rename_variable", this::handleRenameVariable);

            // Extended Firmware Analysis
            server.createContext("/get_interrupt_vector_table", this::handleGetInterruptVectorTable);
            server.createContext("/find_function_prologues", this::handleFindFunctionPrologues);
            server.createContext("/identify_mmio_accesses", this::handleIdentifyMmioAccesses);
            server.createContext("/find_register_patterns", this::handleFindRegisterPatterns);
            server.createContext("/find_crypto_constants", this::handleFindCryptoConstants);
            server.createContext("/find_hardcoded_credentials", this::handleFindHardcodedCredentials);
            server.createContext("/trace_call_path", this::handleTraceCallPath);
            server.createContext("/find_dangerous_sinks", this::handleFindDangerousSinks);
            server.createContext("/find_format_string_vulns", this::handleFindFormatStringVulns);
            server.createContext("/detect_rtos", this::handleDetectRtos);
            server.createContext("/find_function_pointer_tables", this::handleFindFunctionPointerTables);
            server.createContext("/get_string_clusters", this::handleGetStringClusters);
            server.createContext("/get_function_hashes", this::handleGetFunctionHashes);

            server.setExecutor(null);
            server.start();
            Msg.info(this, "FirmwareMCP HTTP Server started on port " + DEFAULT_PORT);
        } catch (IOException e) {
            Msg.error(this, "Failed to start FirmwareMCP HTTP server", e);
        }
    }

    private void stopServer() {
        if (server != null) {
            server.stop(0);
            Msg.info(this, "FirmwareMCP HTTP Server stopped");
        }
    }

    // ── Utility Methods ────────────────────────────────────────────────

    private Map<String, String> parseQuery(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        String query = uri.getRawQuery();
        if (query == null || query.isEmpty()) return params;
        for (String pair : query.split("&")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                params.put(key, val);
            }
        }
        return params;
    }

    private void sendResponse(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendText(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Address parseAddress(Program program, String addrStr) {
        if (addrStr == null) return null;
        addrStr = addrStr.trim();
        Address addr = program.getAddressFactory().getAddress(addrStr);
        if (addr == null && addrStr.startsWith("0x")) {
            addr = program.getAddressFactory().getAddress(addrStr.substring(2));
        }
        return addr;
    }

    private int parseInt(String s, int defaultVal) {
        if (s == null) return defaultVal;
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return defaultVal; }
    }

    private JsonObject errorJson(String msg) {
        JsonObject obj = new JsonObject();
        obj.addProperty("error", msg);
        return obj;
    }

    /** Run a Ghidra API block on the Swing EDT and return the result. */
    @FunctionalInterface
    interface SwingSupplier<T> { T get() throws Exception; }

    private <T> T runOnSwing(SwingSupplier<T> supplier) throws Exception {
        final Object[] result = new Object[1];
        final Exception[] error = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                result[0] = supplier.get();
            } catch (Exception e) {
                error[0] = e;
            }
        });
        if (error[0] != null) throw error[0];
        @SuppressWarnings("unchecked")
        T t = (T) result[0];
        return t;
    }

    // ── Health ─────────────────────────────────────────────────────────

    private void handleHealth(HttpExchange exchange) throws IOException {
        sendResponse(exchange, 200, "{\"status\":\"ok\"}");
    }

    // ── GET /get_binary_info ───────────────────────────────────────────

    private void handleGetBinaryInfo(HttpExchange exchange) throws IOException {
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonObject obj = new JsonObject();
                obj.addProperty("name", p.getName());
                obj.addProperty("architecture", p.getLanguage().getProcessor().toString());
                obj.addProperty("endianness", p.getLanguage().isBigEndian() ? "big" : "little");
                obj.addProperty("address_size", p.getAddressFactory().getDefaultAddressSpace().getSize());
                obj.addProperty("compiler", p.getCompilerSpec().getCompilerSpecID().getIdAsString());
                obj.addProperty("base_address", p.getImageBase().toString());
                obj.addProperty("executable_format", p.getExecutableFormat());
                obj.addProperty("language_id", p.getLanguageID().getIdAsString());
                obj.addProperty("num_functions", p.getFunctionManager().getFunctionCount());
                obj.addProperty("num_symbols", p.getSymbolTable().getNumSymbols());
                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_memory_map ────────────────────────────────────────────

    private void handleGetMemoryMap(HttpExchange exchange) throws IOException {
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonArray arr = new JsonArray();
                for (MemoryBlock block : p.getMemory().getBlocks()) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("name", block.getName());
                    obj.addProperty("start", block.getStart().toString());
                    obj.addProperty("end", block.getEnd().toString());
                    obj.addProperty("size", block.getSize());
                    String perms = (block.isRead() ? "R" : "-")
                                 + (block.isWrite() ? "W" : "-")
                                 + (block.isExecute() ? "X" : "-");
                    obj.addProperty("permissions", perms);
                    obj.addProperty("type", block.getType().toString());
                    obj.addProperty("initialized", block.isInitialized());
                    obj.addProperty("volatile", block.isVolatile());
                    obj.addProperty("source_name", block.getSourceName());
                    arr.add(obj);
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /search_strings ────────────────────────────────────────────

    private void handleSearchStrings(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String keyword = params.get("keyword");
        if (keyword == null || keyword.isEmpty()) {
            sendResponse(exchange, 400, errorJson("Missing 'keyword' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonArray arr = new JsonArray();
                String kw = keyword.toLowerCase();
                int count = 0;
                DataIterator it = p.getListing().getDefinedData(true);
                while (it.hasNext() && count < 200) {
                    Data data = it.next();
                    if (data.hasStringValue()) {
                        Object val = data.getValue();
                        if (val != null) {
                            String sv = val.toString();
                            if (sv.toLowerCase().contains(kw)) {
                                JsonObject obj = new JsonObject();
                                obj.addProperty("address", data.getAddress().toString());
                                obj.addProperty("value", sv);
                                obj.addProperty("length", data.getLength());
                                arr.add(obj);
                                count++;
                            }
                        }
                    }
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_function_list ─────────────────────────────────────────

    private void handleGetFunctionList(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String filterText = params.get("filter_text");
        int offset = parseInt(params.get("offset"), 0);
        int limit = Math.min(parseInt(params.get("limit"), 100), 500);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                List<Function> matched = new ArrayList<>();
                FunctionIterator fi = p.getFunctionManager().getFunctions(true);
                while (fi.hasNext()) {
                    Function f = fi.next();
                    if (filterText == null || f.getName().toLowerCase().contains(filterText.toLowerCase())) {
                        matched.add(f);
                    }
                }
                int total = matched.size();
                JsonArray arr = new JsonArray();
                int end = Math.min(offset + limit, total);
                for (int i = offset; i < end; i++) {
                    Function f = matched.get(i);
                    JsonObject obj = new JsonObject();
                    obj.addProperty("address", f.getEntryPoint().toString());
                    obj.addProperty("name", f.getName());
                    obj.addProperty("size", f.getBody().getNumAddresses());
                    obj.addProperty("calling_convention", f.getCallingConventionName());
                    obj.addProperty("is_thunk", f.isThunk());
                    obj.addProperty("is_external", f.isExternal());
                    arr.add(obj);
                }
                JsonObject result = new JsonObject();
                result.addProperty("total", total);
                result.add("functions", arr);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /search_bytes ──────────────────────────────────────────────

    private void handleSearchBytes(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String hexPattern = params.get("hex_pattern");
        if (hexPattern == null || hexPattern.isEmpty()) {
            sendResponse(exchange, 400, errorJson("Missing 'hex_pattern' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                String[] parts = hexPattern.trim().split("\\s+");
                byte[] pattern = new byte[parts.length];
                byte[] mask = new byte[parts.length];
                for (int i = 0; i < parts.length; i++) {
                    if (parts[i].equals("??")) {
                        pattern[i] = 0;
                        mask[i] = 0;
                    } else {
                        pattern[i] = (byte) Integer.parseInt(parts[i], 16);
                        mask[i] = (byte) 0xFF;
                    }
                }

                JsonArray arr = new JsonArray();
                Memory mem = p.getMemory();
                Address start = mem.getMinAddress();
                int count = 0;
                while (start != null && count < 100) {
                    Address found = mem.findBytes(start, pattern, mask, true, new ConsoleTaskMonitor());
                    if (found == null) break;
                    arr.add(found.toString());
                    count++;
                    start = found.add(1);
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_imports ───────────────────────────────────────────────

    private void handleGetImports(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String filterText = params.get("filter_text");
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonArray arr = new JsonArray();
                SymbolTable st = p.getSymbolTable();
                SymbolIterator si = st.getExternalSymbols();
                while (si.hasNext()) {
                    Symbol s = si.next();
                    if (filterText != null && !s.getName().toLowerCase().contains(filterText.toLowerCase())) {
                        continue;
                    }
                    JsonObject obj = new JsonObject();
                    obj.addProperty("name", s.getName());
                    obj.addProperty("address", s.getAddress().toString());
                    // Get library name from parent namespace
                    obj.addProperty("library", s.getParentNamespace().getName());
                    arr.add(obj);
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_exports ───────────────────────────────────────────────

    private void handleGetExports(HttpExchange exchange) throws IOException {
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonArray arr = new JsonArray();
                SymbolTable st = p.getSymbolTable();
                SymbolIterator si = st.getAllSymbols(true);
                while (si.hasNext()) {
                    Symbol s = si.next();
                    if (s.isExternalEntryPoint()) {
                        JsonObject obj = new JsonObject();
                        obj.addProperty("name", s.getName());
                        obj.addProperty("address", s.getAddress().toString());
                        obj.addProperty("type", s.getSymbolType().toString());
                        arr.add(obj);
                    }
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_segments ──────────────────────────────────────────────

    private void handleGetSegments(HttpExchange exchange) throws IOException {
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonArray arr = new JsonArray();
                for (MemoryBlock block : p.getMemory().getBlocks()) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("name", block.getName());
                    obj.addProperty("start", block.getStart().toString());
                    obj.addProperty("end", block.getEnd().toString());
                    obj.addProperty("size", block.getSize());
                    String perms = (block.isRead() ? "R" : "-")
                                 + (block.isWrite() ? "W" : "-")
                                 + (block.isExecute() ? "X" : "-");
                    obj.addProperty("permissions", perms);
                    obj.addProperty("type", block.getType().toString());
                    arr.add(obj);
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_data_items ────────────────────────────────────────────

    private void handleGetDataItems(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String filterType = params.get("filter_type");
        int offset = parseInt(params.get("offset"), 0);
        int limit = Math.min(parseInt(params.get("limit"), 100), 500);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                JsonArray arr = new JsonArray();
                DataIterator di = p.getListing().getDefinedData(true);
                int idx = 0;
                int count = 0;
                while (di.hasNext() && count < limit) {
                    Data data = di.next();
                    if (filterType != null && !data.getDataType().getDisplayName().toLowerCase().contains(filterType.toLowerCase())) {
                        continue;
                    }
                    if (idx < offset) { idx++; continue; }
                    JsonObject obj = new JsonObject();
                    obj.addProperty("address", data.getAddress().toString());
                    obj.addProperty("type", data.getDataType().getDisplayName());
                    Object val = data.getValue();
                    obj.addProperty("value", val != null ? val.toString() : "");
                    obj.addProperty("size", data.getLength());
                    arr.add(obj);
                    count++;
                    idx++;
                }
                JsonObject result = new JsonObject();
                result.addProperty("total", idx);
                result.add("items", arr);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /disassemble_at ────────────────────────────────────────────

    private void handleDisassembleAt(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        if (addrStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' parameter").toString());
            return;
        }
        int numInstructions = Math.min(parseInt(params.get("num_instructions"), 20), 200);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                JsonArray arr = new JsonArray();
                Instruction inst = p.getListing().getInstructionAt(addr);
                if (inst == null) {
                    // Try getting the instruction containing the address
                    inst = p.getListing().getInstructionContaining(addr);
                }
                int count = 0;
                while (inst != null && count < numInstructions) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("address", inst.getAddress().toString());
                    obj.addProperty("mnemonic", inst.getMnemonicString());
                    obj.addProperty("operands", inst.toString());
                    // Get bytes
                    byte[] bytes = inst.getBytes();
                    StringBuilder hex = new StringBuilder();
                    for (byte b : bytes) {
                        if (hex.length() > 0) hex.append(" ");
                        hex.append(String.format("%02X", b & 0xFF));
                    }
                    obj.addProperty("bytes", hex.toString());
                    obj.addProperty("length", inst.getLength());
                    arr.add(obj);
                    inst = inst.getNext();
                    count++;
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /decompile_function ────────────────────────────────────────

    private void handleDecompileFunction(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        if (addrStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' parameter").toString());
            return;
        }
        try {
            String result = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return "Error: No program loaded";
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return "Error: Invalid address: " + addrStr;

                Function func = p.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = p.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) return "Error: No function at address " + addrStr;

                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(p);
                    DecompileResults dr = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
                    if (dr.decompileCompleted()) {
                        return dr.getDecompiledFunction().getC();
                    } else {
                        return "Error: Decompilation failed - " + dr.getErrorMessage();
                    }
                } finally {
                    decomp.dispose();
                }
            });
            sendText(exchange, 200, result);
        } catch (Exception e) {
            sendText(exchange, 500, "Error: " + e.getMessage());
        }
    }

    // ── GET /get_function_info ─────────────────────────────────────────

    private void handleGetFunctionInfo(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        if (addrStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                Function func = p.getFunctionManager().getFunctionAt(addr);
                if (func == null) func = p.getFunctionManager().getFunctionContaining(addr);
                if (func == null) return errorJson("No function at address " + addrStr).toString();

                JsonObject obj = new JsonObject();
                obj.addProperty("name", func.getName());
                obj.addProperty("entry_point", func.getEntryPoint().toString());
                obj.addProperty("return_type", func.getReturnType().getDisplayName());
                obj.addProperty("calling_convention", func.getCallingConventionName());
                obj.addProperty("stack_frame_size", func.getStackFrame().getFrameSize());
                obj.addProperty("is_thunk", func.isThunk());

                // Parameters
                JsonArray paramsArr = new JsonArray();
                for (Parameter param : func.getParameters()) {
                    JsonObject po = new JsonObject();
                    po.addProperty("name", param.getName());
                    po.addProperty("type", param.getDataType().getDisplayName());
                    po.addProperty("size", param.getLength());
                    po.addProperty("storage", param.getVariableStorage().toString());
                    paramsArr.add(po);
                }
                obj.add("parameters", paramsArr);

                // Local variables
                JsonArray locals = new JsonArray();
                for (Variable v : func.getLocalVariables()) {
                    JsonObject vo = new JsonObject();
                    vo.addProperty("name", v.getName());
                    vo.addProperty("type", v.getDataType().getDisplayName());
                    vo.addProperty("size", v.getLength());
                    vo.addProperty("storage", v.getVariableStorage().toString());
                    locals.add(vo);
                }
                obj.add("local_variables", locals);

                // Called functions
                JsonArray called = new JsonArray();
                for (Function cf : func.getCalledFunctions(new ConsoleTaskMonitor())) {
                    called.add(cf.getName());
                }
                obj.add("called_functions", called);

                // Calling functions
                JsonArray calling = new JsonArray();
                for (Function cf : func.getCallingFunctions(new ConsoleTaskMonitor())) {
                    calling.add(cf.getName());
                }
                obj.add("calling_functions", calling);

                // Potential issues - check for dangerous function calls with local buffers
                JsonArray issues = new JsonArray();
                Set<String> dangerousFuncs = Set.of("strcpy", "sprintf", "gets", "strcat", "scanf", "vsprintf");
                for (Function cf : func.getCalledFunctions(new ConsoleTaskMonitor())) {
                    if (dangerousFuncs.contains(cf.getName())) {
                        issues.add("Calls unsafe function '" + cf.getName() + "' - potential buffer overflow");
                    }
                }
                obj.add("potential_issues", issues);

                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_xrefs_to ──────────────────────────────────────────────

    private void handleGetXrefsTo(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        if (addrStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                JsonArray arr = new JsonArray();
                ReferenceManager rm = p.getReferenceManager();
                for (Reference ref : rm.getReferencesTo(addr)) {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("from_address", ref.getFromAddress().toString());
                    Function f = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    obj.addProperty("from_function", f != null ? f.getName() : "unknown");
                    obj.addProperty("ref_type", ref.getReferenceType().getName());
                    obj.addProperty("is_call", ref.getReferenceType().isCall());
                    arr.add(obj);
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_xrefs_from ────────────────────────────────────────────

    private void handleGetXrefsFrom(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        if (addrStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                Function func = p.getFunctionManager().getFunctionAt(addr);
                if (func == null) func = p.getFunctionManager().getFunctionContaining(addr);

                JsonArray arr = new JsonArray();
                Set<String> seen = new HashSet<>();
                ReferenceManager rm = p.getReferenceManager();

                if (func != null) {
                    AddressSetView body = func.getBody();
                    AddressIterator ai = body.getAddresses(true);
                    while (ai.hasNext()) {
                        Address a = ai.next();
                        for (Reference ref : rm.getReferencesFrom(a)) {
                            String key = ref.getToAddress().toString();
                            if (seen.add(key)) {
                                JsonObject obj = new JsonObject();
                                obj.addProperty("to_address", ref.getToAddress().toString());
                                Function tf = p.getFunctionManager().getFunctionAt(ref.getToAddress());
                                if (tf == null) tf = p.getFunctionManager().getFunctionContaining(ref.getToAddress());
                                obj.addProperty("to_function", tf != null ? tf.getName() : "unknown");
                                obj.addProperty("ref_type", ref.getReferenceType().getName());
                                obj.addProperty("from_address", ref.getFromAddress().toString());
                                arr.add(obj);
                            }
                        }
                    }
                } else {
                    for (Reference ref : rm.getReferencesFrom(addr)) {
                        JsonObject obj = new JsonObject();
                        obj.addProperty("to_address", ref.getToAddress().toString());
                        Function tf = p.getFunctionManager().getFunctionAt(ref.getToAddress());
                        obj.addProperty("to_function", tf != null ? tf.getName() : "unknown");
                        obj.addProperty("ref_type", ref.getReferenceType().getName());
                        obj.addProperty("from_address", ref.getFromAddress().toString());
                        arr.add(obj);
                    }
                }
                return arr.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /read_raw_bytes ────────────────────────────────────────────

    private void handleReadRawBytes(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        String lenStr = params.get("length");
        if (addrStr == null || lenStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' or 'length' parameter").toString());
            return;
        }
        int length = Math.min(parseInt(lenStr, 64), 4096);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                byte[] buffer = new byte[length];
                int bytesRead = p.getMemory().getBytes(addr, buffer);

                StringBuilder hex = new StringBuilder();
                StringBuilder ascii = new StringBuilder();
                for (int i = 0; i < bytesRead; i++) {
                    if (i > 0) hex.append(" ");
                    hex.append(String.format("%02X", buffer[i] & 0xFF));
                    char c = (char) (buffer[i] & 0xFF);
                    ascii.append(c >= 32 && c < 127 ? c : '.');
                }

                JsonObject obj = new JsonObject();
                obj.addProperty("address", addr.toString());
                obj.addProperty("length", bytesRead);
                obj.addProperty("hex", hex.toString());
                obj.addProperty("ascii", ascii.toString());
                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── POST /rename_function ──────────────────────────────────────────

    private void handleRenameVariable(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("function_address");
        String oldName = params.get("old_name");
        String newName = params.get("new_name");
        if (addrStr == null || oldName == null || newName == null) {
            sendResponse(exchange, 400,
                errorJson("Missing 'function_address', 'old_name', or 'new_name' parameter").toString());
            return;
        }
        if (!newName.matches("[a-zA-Z_][a-zA-Z0-9_]*")) {
            sendResponse(exchange, 400, errorJson("Invalid variable name: must be a valid C identifier").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();
                Function func = p.getFunctionManager().getFunctionAt(addr);
                if (func == null) func = p.getFunctionManager().getFunctionContaining(addr);
                if (func == null) return errorJson("No function at address " + addrStr).toString();

                DecompInterface decomp = new DecompInterface();
                try {
                    decomp.openProgram(p);
                    DecompileResults dr = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
                    if (dr == null || !dr.decompileCompleted()) {
                        return errorJson("Decompilation failed: " +
                            (dr == null ? "no results" : dr.getErrorMessage())).toString();
                    }
                    ghidra.program.model.pcode.HighFunction hf = dr.getHighFunction();
                    if (hf == null) return errorJson("No high function for " + func.getName()).toString();

                    ghidra.program.model.pcode.HighSymbol target = null;
                    java.util.List<String> available = new java.util.ArrayList<>();
                    java.util.Iterator<ghidra.program.model.pcode.HighSymbol> it =
                        hf.getLocalSymbolMap().getSymbols();
                    while (it.hasNext()) {
                        ghidra.program.model.pcode.HighSymbol hs = it.next();
                        available.add(hs.getName());
                        if (hs.getName().equals(oldName)) target = hs;
                    }
                    if (target == null) {
                        return errorJson("No variable named '" + oldName + "' in " + func.getName() +
                            ". Available: " + String.join(", ", available)).toString();
                    }

                    int txId = p.startTransaction("Rename variable " + oldName + " to " + newName);
                    try {
                        ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                            target, newName, null, SourceType.USER_DEFINED);
                        p.endTransaction(txId, true);
                    } catch (Exception e) {
                        p.endTransaction(txId, false);
                        throw e;
                    }

                    JsonObject obj = new JsonObject();
                    obj.addProperty("success", true);
                    obj.addProperty("function", func.getName());
                    obj.addProperty("message", "Renamed variable '" + oldName + "' to '" + newName +
                        "' in " + func.getName());
                    return obj.toString();
                } finally {
                    decomp.dispose();
                }
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    private void handleCreateFunction(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        String name = params.get("name"); // optional
        if (addrStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' parameter").toString());
            return;
        }
        if (name != null && !name.matches("[a-zA-Z_][a-zA-Z0-9_]*")) {
            sendResponse(exchange, 400, errorJson("Invalid function name: must be a valid C identifier").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                FunctionManager fm = p.getFunctionManager();
                Function existing = fm.getFunctionAt(addr);

                int txId = p.startTransaction("Create function at " + addrStr);
                try {
                    Function func = existing;
                    boolean created = false;
                    if (func == null) {
                        // Ensure there is code at the entry, then create the function.
                        if (p.getListing().getInstructionAt(addr) == null) {
                            new ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true)
                                .applyTo(p, new ConsoleTaskMonitor());
                        }
                        boolean ok = new ghidra.app.cmd.function.CreateFunctionCmd(addr)
                            .applyTo(p, new ConsoleTaskMonitor());
                        func = fm.getFunctionAt(addr);
                        if (!ok || func == null) {
                            p.endTransaction(txId, false);
                            return errorJson("Failed to create function at " + addrStr +
                                " (no disassemblable code at that address?)").toString();
                        }
                        created = true;
                    }
                    if (name != null) {
                        func.setName(name, SourceType.USER_DEFINED);
                    }
                    JsonObject obj = new JsonObject();
                    obj.addProperty("success", true);
                    obj.addProperty("created", created);
                    obj.addProperty("address", func.getEntryPoint().toString());
                    obj.addProperty("name", func.getName());
                    obj.addProperty("message", created
                        ? ("Function created at " + func.getEntryPoint() + " as " + func.getName())
                        : ("Function already existed at " + func.getEntryPoint() + " (" + func.getName() + ")"));
                    p.endTransaction(txId, true);
                    return obj.toString();
                } catch (Exception e) {
                    p.endTransaction(txId, false);
                    throw e;
                }
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    private void handleRenameFunction(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        String newName = params.get("new_name");
        if (addrStr == null || newName == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' or 'new_name' parameter").toString());
            return;
        }
        if (!newName.matches("[a-zA-Z_][a-zA-Z0-9_]*")) {
            sendResponse(exchange, 400, errorJson("Invalid function name: must be a valid C identifier").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                Function func = p.getFunctionManager().getFunctionAt(addr);
                if (func == null) func = p.getFunctionManager().getFunctionContaining(addr);
                if (func == null) return errorJson("No function at address " + addrStr).toString();

                int txId = p.startTransaction("Rename function to " + newName);
                try {
                    func.setName(newName, SourceType.USER_DEFINED);
                    p.endTransaction(txId, true);
                } catch (Exception e) {
                    p.endTransaction(txId, false);
                    throw e;
                }

                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("message", "Function renamed to " + newName);
                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── POST /add_comment ──────────────────────────────────────────────

    private void handleAddComment(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        String comment = params.get("comment");
        if (addrStr == null || comment == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' or 'comment' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                int txId = p.startTransaction("Add comment");
                try {
                    p.getListing().setComment(addr, CommentType.PLATE, comment);
                    p.endTransaction(txId, true);
                } catch (Exception e) {
                    p.endTransaction(txId, false);
                    throw e;
                }

                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("message", "Comment added at " + addr.toString());
                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── POST /define_data ──────────────────────────────────────────────

    private void handleDefineData(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        String dataType = params.get("data_type");
        if (addrStr == null || dataType == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' or 'data_type' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                DataType dt = mapDataType(dataType);
                if (dt == null && !dataType.equals("string")) {
                    return errorJson("Unknown data type: " + dataType).toString();
                }

                int txId = p.startTransaction("Define data as " + dataType);
                try {
                    // Clear existing data at address
                    Listing listing = p.getListing();
                    Data existing = listing.getDefinedDataAt(addr);
                    if (existing != null) {
                        listing.clearCodeUnits(addr, addr.add(existing.getLength() - 1), false);
                    }

                    if (dataType.equals("string")) {
                        DataUtilities.createData(p, addr, new TerminatedStringDataType(),
                            -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    } else {
                        DataUtilities.createData(p, addr, dt, dt.getLength(),
                            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    }
                    p.endTransaction(txId, true);
                } catch (Exception e) {
                    p.endTransaction(txId, false);
                    throw e;
                }

                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("message", "Data defined as " + dataType + " at " + addr.toString());
                obj.addProperty("applied_type", dataType);
                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    private DataType mapDataType(String typeName) {
        switch (typeName.toLowerCase()) {
            case "pointer": return PointerDataType.dataType;
            case "int8": return SignedByteDataType.dataType;
            case "uint8": return ByteDataType.dataType;
            case "int16": return ShortDataType.dataType;
            case "uint16": return UnsignedShortDataType.dataType;
            case "int32": return IntegerDataType.dataType;
            case "uint32": return UnsignedIntegerDataType.dataType;
            case "int64": return LongDataType.dataType;
            case "uint64": return UnsignedLongDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            default: return null;
        }
    }

    // ── POST /rename_data ──────────────────────────────────────────────

    private void handleRenameData(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        String newName = params.get("new_name");
        if (addrStr == null || newName == null) {
            sendResponse(exchange, 400, errorJson("Missing 'address' or 'new_name' parameter").toString());
            return;
        }
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();
                Address addr = parseAddress(p, addrStr);
                if (addr == null) return errorJson("Invalid address: " + addrStr).toString();

                int txId = p.startTransaction("Rename data to " + newName);
                try {
                    p.getSymbolTable().createLabel(addr, newName, SourceType.USER_DEFINED);
                    p.endTransaction(txId, true);
                } catch (Exception e) {
                    p.endTransaction(txId, false);
                    throw e;
                }

                JsonObject obj = new JsonObject();
                obj.addProperty("success", true);
                obj.addProperty("message", "Label '" + newName + "' created at " + addr.toString());
                return obj.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // EXTENDED FIRMWARE ANALYSIS ENDPOINTS
    // ══════════════════════════════════════════════════════════════════════

    // ── Shared Helpers ─────────────────────────────────────────────────

    private String detectArchitecture(Program p) {
        String proc = p.getLanguage().getProcessor().toString().toLowerCase();
        boolean bigEndian = p.getLanguage().isBigEndian();
        int addrSize = p.getAddressFactory().getDefaultAddressSpace().getSize();
        if (proc.contains("arm") && addrSize == 32) return "arm";
        if (proc.contains("aarch64")) return "aarch64";
        if (proc.contains("mips") && bigEndian) return "mips";
        if (proc.contains("mips") && !bigEndian) return "mipsel";
        if (proc.contains("xtensa")) return "xtensa";
        if (proc.contains("riscv") || proc.contains("risc-v")) return "riscv";
        if (proc.contains("x86") && addrSize == 32) return "x86";
        if (proc.contains("x86") && addrSize == 64) return "x86_64";
        return "unknown";
    }

    private double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int[] freq = new int[256];
        for (char c : s.toCharArray()) freq[c & 0xFF]++;
        double entropy = 0.0;
        double len = s.length();
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private Function resolveFunctionByNameOrAddress(Program p, String nameOrAddr) {
        // Try by name first
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            if (f.getName().equalsIgnoreCase(nameOrAddr)) return f;
        }
        // Try by address
        Address addr = parseAddress(p, nameOrAddr);
        if (addr != null) {
            Function f = p.getFunctionManager().getFunctionAt(addr);
            if (f == null) f = p.getFunctionManager().getFunctionContaining(addr);
            return f;
        }
        return null;
    }

    // ── Crypto constant signatures ─────────────────────────────────────

    private static final byte[] AES_SBOX_PREFIX = {
        0x63, 0x7C, 0x77, 0x7B, (byte)0xF2, 0x6B, 0x6F, (byte)0xC5,
        0x30, 0x01, 0x67, 0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, 0x76
    };
    private static final byte[] AES_INV_SBOX_PREFIX = {
        0x52, 0x09, 0x6A, (byte)0xD5, 0x30, 0x36, (byte)0xA5, 0x38,
        (byte)0xBF, 0x40, (byte)0xA3, (byte)0x9E, (byte)0x81, (byte)0xF3, (byte)0xD7, (byte)0xFB
    };
    private static final byte[] SHA256_INIT_PREFIX = {
        0x6A, 0x09, (byte)0xE6, 0x67
    };
    private static final byte[] SHA256_ROUND_PREFIX = {
        0x42, (byte)0x8A, 0x2F, (byte)0x98
    };
    private static final byte[] SHA1_INIT = {
        0x67, 0x45, 0x23, 0x01
    };
    private static final byte[] MD5_INIT = {
        0x01, 0x23, 0x45, 0x67
    };
    private static final byte[] MD5_T_PREFIX = {
        (byte)0xD7, 0x6A, (byte)0xA4, 0x78
    };
    private static final byte[] DES_SBOX1_PREFIX = {
        0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08
    };
    private static final byte[] CHACHA20_SIGMA = {
        0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33,
        0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B
    };
    private static final byte[] BLOWFISH_P_PREFIX = {
        0x24, 0x3F, 0x6A, (byte)0x88
    };

    // ── GET /get_interrupt_vector_table ─────────────────────────────────

    private void handleGetInterruptVectorTable(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String addrStr = params.get("address");
        int numEntries = Math.min(parseInt(params.get("num_entries"), 48), 256);
        int entrySize = parseInt(params.get("entry_size"), 4);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                Address baseAddr = (addrStr != null && !addrStr.isEmpty())
                    ? parseAddress(p, addrStr) : p.getImageBase();
                if (baseAddr == null) return errorJson("Invalid address").toString();

                String arch = detectArchitecture(p);
                boolean isCortexM = arch.equals("arm");
                Memory mem = p.getMemory();

                JsonArray vectors = new JsonArray();
                int anomalyCount = 0;
                String initialSp = null;

                for (int i = 0; i < numEntries; i++) {
                    Address entryAddr = baseAddr.add((long) i * entrySize);
                    JsonObject entry = new JsonObject();
                    entry.addProperty("index", i);

                    try {
                        long rawValue;
                        if (entrySize == 4) {
                            rawValue = Integer.toUnsignedLong(mem.getInt(entryAddr));
                        } else {
                            rawValue = mem.getLong(entryAddr);
                        }
                        entry.addProperty("raw_value", String.format("0x%08X", rawValue));

                        // ARM Cortex-M: entry 0 is initial SP
                        if (isCortexM && i == 0) {
                            initialSp = String.format("0x%08X", rawValue);
                            entry.addProperty("resolved_address", initialSp);
                            entry.addProperty("target_function", "initial_stack_pointer");
                            entry.addProperty("target_region", "RAM");
                            entry.addProperty("anomaly", (String) null);
                            vectors.add(entry);
                            continue;
                        }

                        // Clear thumb bit for ARM
                        long resolved = isCortexM ? (rawValue & ~1L) : rawValue;
                        entry.addProperty("resolved_address", String.format("0x%08X", resolved));

                        // Resolve to function/label
                        Address targetAddr = p.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(resolved);
                        Function func = p.getFunctionManager().getFunctionAt(targetAddr);
                        Symbol sym = p.getSymbolTable().getPrimarySymbol(targetAddr);
                        entry.addProperty("target_function",
                            func != null ? func.getName() :
                            (sym != null ? sym.getName() : null));

                        // Determine region
                        MemoryBlock block = mem.getBlock(targetAddr);
                        entry.addProperty("target_region",
                            block != null ? block.getName() : "unmapped");

                        // Anomaly detection
                        String anomaly = null;
                        if (rawValue == 0) {
                            anomaly = "Null vector";
                            anomalyCount++;
                        } else if (block == null) {
                            anomaly = "Vector points outside any defined memory block";
                            anomalyCount++;
                        } else if (block.isWrite() && !block.isExecute()) {
                            anomaly = "Vector points to RAM (possible hook)";
                            anomalyCount++;
                        } else if (isCortexM && (resolved & 1) != 0) {
                            anomaly = "Unaligned address";
                            anomalyCount++;
                        }
                        entry.addProperty("anomaly", anomaly);
                    } catch (Exception e) {
                        entry.addProperty("raw_value", "read_error");
                        entry.addProperty("anomaly", "Failed to read: " + e.getMessage());
                        anomalyCount++;
                    }
                    vectors.add(entry);
                }

                JsonObject result = new JsonObject();
                result.addProperty("base_address", baseAddr.toString());
                result.addProperty("architecture_hint", isCortexM ? "ARM_Cortex-M" : arch);
                result.addProperty("num_entries", numEntries);
                if (initialSp != null) result.addProperty("initial_sp", initialSp);
                result.add("vectors", vectors);
                result.addProperty("anomaly_count", anomalyCount);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_function_prologues ────────────────────────────────────

    private void handleFindFunctionPrologues(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String archOverride = params.get("architecture");
        boolean createFunctions = "true".equalsIgnoreCase(params.get("create_functions"));
        String startStr = params.get("start_address");
        String endStr = params.get("end_address");

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                String arch = (archOverride != null && !archOverride.equals("auto"))
                    ? archOverride : detectArchitecture(p);

                // Build prologue patterns for the architecture
                List<byte[]> patterns = new ArrayList<>();
                List<byte[]> masks = new ArrayList<>();
                List<String> patternNames = new ArrayList<>();

                if (arch.equals("arm")) {
                    // ARM Thumb: PUSH {r4-r7, lr} variants (B5 xx)
                    patterns.add(new byte[]{(byte)0xB5, 0x00});
                    masks.add(new byte[]{(byte)0xFF, 0x00});
                    patternNames.add("PUSH {regs, lr}");
                    // Wider PUSH: F0 B5 (PUSH {r4,r5,r6,r7,lr})
                    patterns.add(new byte[]{(byte)0xF0, (byte)0xB5});
                    masks.add(new byte[]{(byte)0xFF, (byte)0xFF});
                    patternNames.add("PUSH {r4-r7, lr}");
                    // 2D E9 - STM push wide
                    patterns.add(new byte[]{0x2D, (byte)0xE9});
                    masks.add(new byte[]{(byte)0xFF, (byte)0xFF});
                    patternNames.add("PUSH.W {regs}");
                } else if (arch.equals("x86") || arch.equals("x86_64")) {
                    patterns.add(new byte[]{0x55}); // PUSH EBP
                    masks.add(new byte[]{(byte)0xFF});
                    patternNames.add("PUSH EBP");
                } else if (arch.equals("mipsel")) {
                    // ADDIU $sp, $sp, -N (little-endian): xx FF BD 27
                    patterns.add(new byte[]{0x00, (byte)0xFF, (byte)0xBD, 0x27});
                    masks.add(new byte[]{0x00, (byte)0xFF, (byte)0xFF, (byte)0xFF});
                    patternNames.add("ADDIU $sp, $sp, -N");
                } else if (arch.equals("mips")) {
                    // ADDIU $sp, $sp, -N (big-endian): 27 BD FF xx
                    patterns.add(new byte[]{0x27, (byte)0xBD, (byte)0xFF, 0x00});
                    masks.add(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, 0x00});
                    patternNames.add("ADDIU $sp, $sp, -N");
                } else if (arch.equals("xtensa")) {
                    patterns.add(new byte[]{0x36, 0x41, 0x00});
                    masks.add(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF});
                    patternNames.add("ENTRY");
                }

                if (patterns.isEmpty()) {
                    return errorJson("No prologue patterns for architecture: " + arch).toString();
                }

                // Determine scan range
                Memory mem = p.getMemory();
                Address scanStart = null, scanEnd = null;
                if (startStr != null) scanStart = parseAddress(p, startStr);
                if (endStr != null) scanEnd = parseAddress(p, endStr);
                if (scanStart == null || scanEnd == null) {
                    for (MemoryBlock block : mem.getBlocks()) {
                        if (block.isExecute() && block.isInitialized()) {
                            if (scanStart == null || block.getStart().compareTo(scanStart) < 0)
                                scanStart = block.getStart();
                            if (scanEnd == null || block.getEnd().compareTo(scanEnd) > 0)
                                scanEnd = block.getEnd();
                        }
                    }
                }
                if (scanStart == null || scanEnd == null) {
                    return errorJson("No executable memory blocks found").toString();
                }

                JsonArray prologues = new JsonArray();
                int alreadyDefined = 0, newlyDiscovered = 0, functionsCreated = 0;
                FunctionManager fm = p.getFunctionManager();
                int txId = createFunctions ? p.startTransaction("Create functions from prologues") : -1;

                try {
                    for (int pi = 0; pi < patterns.size(); pi++) {
                        Address cursor = scanStart;
                        int found = 0;
                        while (cursor != null && cursor.compareTo(scanEnd) <= 0 && found < 500) {
                            Address hit = mem.findBytes(cursor, scanEnd, patterns.get(pi), masks.get(pi), true, new ConsoleTaskMonitor());
                            if (hit == null) break;

                            boolean isDefined = fm.getFunctionAt(hit) != null;
                            if (isDefined) {
                                alreadyDefined++;
                            } else {
                                newlyDiscovered++;
                                boolean created = false;
                                if (createFunctions) {
                                    try {
                                        ghidra.app.cmd.function.CreateFunctionCmd cmd =
                                            new ghidra.app.cmd.function.CreateFunctionCmd(hit);
                                        if (cmd.applyTo(p, new ConsoleTaskMonitor())) {
                                            functionsCreated++;
                                            created = true;
                                        }
                                    } catch (Exception ignored) {}
                                }
                                JsonObject po = new JsonObject();
                                po.addProperty("address", hit.toString());
                                po.addProperty("pattern_matched", patternNames.get(pi));
                                po.addProperty("already_defined", false);
                                po.addProperty("function_created", created);
                                byte[] hitBytes = new byte[patterns.get(pi).length];
                                try { mem.getBytes(hit, hitBytes); } catch (Exception ignored) {}
                                StringBuilder hb = new StringBuilder();
                                for (byte b : hitBytes) {
                                    if (hb.length() > 0) hb.append(" ");
                                    hb.append(String.format("%02X", b & 0xFF));
                                }
                                po.addProperty("bytes", hb.toString());
                                prologues.add(po);
                            }
                            cursor = hit.add(1);
                            found++;
                        }
                    }
                } finally {
                    if (txId >= 0) p.endTransaction(txId, true);
                }

                JsonObject result = new JsonObject();
                result.addProperty("architecture_detected", arch);
                JsonArray patternsUsed = new JsonArray();
                for (String pn : patternNames) patternsUsed.add(pn);
                result.add("patterns_used", patternsUsed);
                JsonObject range = new JsonObject();
                range.addProperty("start", scanStart.toString());
                range.addProperty("end", scanEnd.toString());
                result.add("scan_range", range);
                result.addProperty("total_found", alreadyDefined + newlyDiscovered);
                result.addProperty("already_defined", alreadyDefined);
                result.addProperty("newly_discovered", newlyDiscovered);
                result.addProperty("functions_created", functionsCreated);
                result.add("prologues", prologues);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /identify_mmio_accesses ─────────────────────────────────────

    private void handleIdentifyMmioAccesses(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String mmioStartStr = params.get("mmio_start");
        String mmioEndStr = params.get("mmio_end");
        String filterFunc = params.get("filter_function");

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                // Determine MMIO regions
                List<long[]> mmioRanges = new ArrayList<>(); // pairs of [start, end]
                List<String> mmioNames = new ArrayList<>();
                JsonArray scannedRegions = new JsonArray();

                if (mmioStartStr != null && mmioEndStr != null) {
                    Address ms = parseAddress(p, mmioStartStr);
                    Address me = parseAddress(p, mmioEndStr);
                    if (ms != null && me != null) {
                        mmioRanges.add(new long[]{ms.getOffset(), me.getOffset()});
                        mmioNames.add("user_specified");
                        JsonObject r = new JsonObject();
                        r.addProperty("start", ms.toString()); r.addProperty("end", me.toString());
                        r.addProperty("name", "user_specified");
                        scannedRegions.add(r);
                    }
                } else {
                    Set<String> peripheralNames = Set.of("periph", "apb1", "apb2", "ahb", "mmio", "sfr", "io");
                    for (MemoryBlock block : p.getMemory().getBlocks()) {
                        boolean isMMIO = block.isVolatile() ||
                            peripheralNames.contains(block.getName().toLowerCase());
                        if (isMMIO) {
                            mmioRanges.add(new long[]{block.getStart().getOffset(), block.getEnd().getOffset()});
                            mmioNames.add(block.getName());
                            JsonObject r = new JsonObject();
                            r.addProperty("start", block.getStart().toString());
                            r.addProperty("end", block.getEnd().toString());
                            r.addProperty("name", block.getName());
                            scannedRegions.add(r);
                        }
                    }
                }

                if (mmioRanges.isEmpty()) {
                    JsonObject result = new JsonObject();
                    result.add("mmio_regions_scanned", scannedRegions);
                    result.addProperty("total_accesses", 0);
                    result.add("accesses", new JsonArray());
                    result.add("functions_accessing_mmio", new JsonArray());
                    return result.toString();
                }

                JsonArray accesses = new JsonArray();
                Map<String, int[]> funcAccessMap = new LinkedHashMap<>(); // name -> [count]
                Map<String, Set<String>> funcRegionMap = new LinkedHashMap<>();
                int cap = 500;

                // Determine which functions to scan
                List<Function> funcsToScan = new ArrayList<>();
                FunctionManager fm = p.getFunctionManager();
                if (filterFunc != null && !filterFunc.isEmpty()) {
                    Function f = resolveFunctionByNameOrAddress(p, filterFunc);
                    if (f != null) funcsToScan.add(f);
                } else {
                    FunctionIterator fi = fm.getFunctions(true);
                    while (fi.hasNext()) funcsToScan.add(fi.next());
                }

                ReferenceManager rm = p.getReferenceManager();
                for (Function func : funcsToScan) {
                    if (accesses.size() >= cap) break;
                    AddressSetView body = func.getBody();
                    AddressIterator ai = body.getAddresses(true);
                    while (ai.hasNext() && accesses.size() < cap) {
                        Address instrAddr = ai.next();
                        Reference[] refs = rm.getReferencesFrom(instrAddr);
                        for (Reference ref : refs) {
                            long targetOff = ref.getToAddress().getOffset();
                            for (int ri = 0; ri < mmioRanges.size(); ri++) {
                                if (targetOff >= mmioRanges.get(ri)[0] && targetOff <= mmioRanges.get(ri)[1]) {
                                    Instruction inst = p.getListing().getInstructionAt(instrAddr);
                                    String accessType = ref.getReferenceType().isWrite() ? "write" :
                                                       ref.getReferenceType().isRead() ? "read" : "unknown";
                                    JsonObject acc = new JsonObject();
                                    acc.addProperty("instruction_address", instrAddr.toString());
                                    acc.addProperty("function", func.getName());
                                    acc.addProperty("mmio_address", ref.getToAddress().toString());
                                    acc.addProperty("mmio_region", mmioNames.get(ri));
                                    acc.addProperty("access_type", accessType);
                                    acc.addProperty("instruction", inst != null ? inst.toString() : "unknown");
                                    accesses.add(acc);

                                    funcAccessMap.computeIfAbsent(func.getName(), k -> new int[]{0})[0]++;
                                    funcRegionMap.computeIfAbsent(func.getName(), k -> new HashSet<>()).add(mmioNames.get(ri));
                                    break;
                                }
                            }
                        }
                    }
                }

                JsonArray funcsAccessing = new JsonArray();
                for (Map.Entry<String, int[]> e : funcAccessMap.entrySet()) {
                    JsonObject fo = new JsonObject();
                    fo.addProperty("name", e.getKey());
                    fo.addProperty("access_count", e.getValue()[0]);
                    JsonArray regions = new JsonArray();
                    for (String r : funcRegionMap.get(e.getKey())) regions.add(r);
                    fo.add("regions_touched", regions);
                    funcsAccessing.add(fo);
                }

                JsonObject result = new JsonObject();
                result.add("mmio_regions_scanned", scannedRegions);
                result.addProperty("total_accesses", accesses.size());
                result.add("accesses", accesses);
                result.add("functions_accessing_mmio", funcsAccessing);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_register_patterns ─────────────────────────────────────

    private void handleFindRegisterPatterns(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String targetAddrStr = params.get("target_address");
        String funcAddrStr = params.get("function_address");

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                // Determine which functions to scan
                List<Function> funcsToScan = new ArrayList<>();
                FunctionManager fm = p.getFunctionManager();
                if (funcAddrStr != null && !funcAddrStr.isEmpty()) {
                    Function f = resolveFunctionByNameOrAddress(p, funcAddrStr);
                    if (f != null) funcsToScan.add(f);
                } else {
                    FunctionIterator fi = fm.getFunctions(true);
                    while (fi.hasNext()) funcsToScan.add(fi.next());
                }

                // Determine MMIO/volatile ranges to look for
                Set<String> volatileNames = new HashSet<>();
                List<long[]> volatileRanges = new ArrayList<>();
                if (targetAddrStr != null && !targetAddrStr.isEmpty()) {
                    Address ta = parseAddress(p, targetAddrStr);
                    if (ta != null) {
                        volatileRanges.add(new long[]{ta.getOffset(), ta.getOffset()});
                    }
                } else {
                    for (MemoryBlock block : p.getMemory().getBlocks()) {
                        if (block.isVolatile()) {
                            volatileRanges.add(new long[]{block.getStart().getOffset(), block.getEnd().getOffset()});
                        }
                    }
                }

                JsonArray sequences = new JsonArray();
                ReferenceManager rm = p.getReferenceManager();
                int cap = 200;

                for (Function func : funcsToScan) {
                    if (sequences.size() >= cap) break;
                    // Get instructions in order
                    List<Instruction> instrs = new ArrayList<>();
                    Instruction inst = p.getListing().getInstructionAt(func.getEntryPoint());
                    AddressSetView body = func.getBody();
                    while (inst != null && body.contains(inst.getAddress()) && instrs.size() < 2000) {
                        instrs.add(inst);
                        inst = inst.getNext();
                    }

                    // Sliding window of 3-5 instructions looking for LDR..ORR/BIC/AND..STR
                    for (int i = 0; i < instrs.size() - 2 && sequences.size() < cap; i++) {
                        Instruction i1 = instrs.get(i);
                        String m1 = i1.getMnemonicString().toLowerCase();
                        if (!(m1.startsWith("ldr") || m1.equals("lw") || m1.startsWith("mov"))) continue;

                        // Look for a modify + store within next 4 instructions
                        for (int j = i + 1; j < Math.min(i + 4, instrs.size() - 1); j++) {
                            Instruction i2 = instrs.get(j);
                            String m2 = i2.getMnemonicString().toLowerCase();
                            boolean isModify = m2.startsWith("orr") || m2.startsWith("bic") ||
                                m2.startsWith("and") || m2.equals("ori") || m2.equals("andi") ||
                                m2.equals("or") || m2.equals("xor");
                            if (!isModify) continue;

                            for (int k = j + 1; k < Math.min(j + 3, instrs.size()); k++) {
                                Instruction i3 = instrs.get(k);
                                String m3 = i3.getMnemonicString().toLowerCase();
                                if (!(m3.startsWith("str") || m3.equals("sw") || m3.startsWith("mov"))) continue;

                                // Check if load and store reference the same MMIO address
                                Reference[] refsLoad = rm.getReferencesFrom(i1.getAddress());
                                Reference[] refsStore = rm.getReferencesFrom(i3.getAddress());
                                for (Reference rl : refsLoad) {
                                    for (Reference rs : refsStore) {
                                        if (rl.getToAddress().equals(rs.getToAddress())) {
                                            long targetOff = rl.getToAddress().getOffset();
                                            boolean inVolatile = volatileRanges.isEmpty(); // if no ranges, accept all
                                            for (long[] vr : volatileRanges) {
                                                if (targetOff >= vr[0] && targetOff <= vr[1]) {
                                                    inVolatile = true;
                                                    break;
                                                }
                                            }
                                            if (!inVolatile) continue;

                                            String op = m2.startsWith("orr") || m2.equals("ori") || m2.equals("or")
                                                ? "set_bits" : m2.startsWith("bic") ? "clear_bits" : "mask_bits";

                                            JsonObject seq = new JsonObject();
                                            seq.addProperty("function", func.getName());
                                            seq.addProperty("read_address", i1.getAddress().toString());
                                            seq.addProperty("modify_address", i2.getAddress().toString());
                                            seq.addProperty("write_address", i3.getAddress().toString());
                                            seq.addProperty("target_register", rl.getToAddress().toString());
                                            seq.addProperty("operation", op);
                                            JsonArray instrArr = new JsonArray();
                                            instrArr.add(i1.toString());
                                            instrArr.add(i2.toString());
                                            instrArr.add(i3.toString());
                                            seq.add("instructions", instrArr);
                                            sequences.add(seq);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                JsonObject result = new JsonObject();
                result.addProperty("patterns_found", sequences.size());
                result.add("rmw_sequences", sequences);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_crypto_constants ──────────────────────────────────────

    private void handleFindCryptoConstants(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String algFilter = params.getOrDefault("algorithms", "all").toLowerCase();
        Set<String> algs = algFilter.equals("all") ? null : new HashSet<>(Arrays.asList(algFilter.split(",")));

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                Memory mem = p.getMemory();
                ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
                JsonArray findings = new JsonArray();
                Set<String> algorithmsDetected = new LinkedHashSet<>();

                // Define signatures: {pattern, name, algorithm, confidence}
                Object[][] signatures = {
                    {AES_SBOX_PREFIX, "S-Box", "aes", "high"},
                    {AES_INV_SBOX_PREFIX, "Inverse S-Box", "aes", "high"},
                    {SHA256_INIT_PREFIX, "Initial Hash H0", "sha256", "medium"},
                    {SHA256_ROUND_PREFIX, "Round Constant K0", "sha256", "medium"},
                    {SHA1_INIT, "Init H0", "sha1", "medium"},
                    {MD5_INIT, "Init A", "md5", "medium"},
                    {MD5_T_PREFIX, "T-table entry 1", "md5", "medium"},
                    {DES_SBOX1_PREFIX, "S-Box 1", "des", "high"},
                    {CHACHA20_SIGMA, "Sigma constant", "chacha20", "high"},
                    {BLOWFISH_P_PREFIX, "P-array init", "blowfish", "medium"},
                };

                byte[] fullMask; // all 0xFF
                for (Object[] sig : signatures) {
                    byte[] pattern = (byte[]) sig[0];
                    String constName = (String) sig[1];
                    String algorithm = (String) sig[2];
                    String confidence = (String) sig[3];

                    if (algs != null && !algs.contains(algorithm)) continue;

                    fullMask = new byte[pattern.length];
                    Arrays.fill(fullMask, (byte) 0xFF);

                    Address cursor = mem.getMinAddress();
                    int count = 0;
                    while (cursor != null && count < 10) {
                        Address hit = mem.findBytes(cursor, pattern, fullMask, true, monitor);
                        if (hit == null) break;

                        algorithmsDetected.add(algorithm.toUpperCase());
                        JsonObject finding = new JsonObject();
                        finding.addProperty("algorithm", algorithm.toUpperCase());
                        finding.addProperty("constant_name", constName);
                        finding.addProperty("address", hit.toString());

                        MemoryBlock block = mem.getBlock(hit);
                        finding.addProperty("memory_region", block != null ? block.getName() : "unknown");

                        // Find referencing functions
                        JsonArray refFuncs = new JsonArray();
                        ReferenceManager rm = p.getReferenceManager();
                        for (Reference ref : rm.getReferencesTo(hit)) {
                            Function f = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                            if (f != null) {
                                JsonObject rf = new JsonObject();
                                rf.addProperty("name", f.getName());
                                rf.addProperty("address", f.getEntryPoint().toString());
                                rf.addProperty("ref_address", ref.getFromAddress().toString());
                                refFuncs.add(rf);
                            }
                        }
                        finding.add("referencing_functions", refFuncs);
                        finding.addProperty("confidence", confidence);
                        findings.add(finding);

                        cursor = hit.add(1);
                        count++;
                    }
                }

                JsonObject result = new JsonObject();
                result.add("crypto_findings", findings);
                JsonObject summary = new JsonObject();
                JsonArray algArr = new JsonArray();
                for (String a : algorithmsDetected) algArr.add(a);
                summary.add("algorithms_detected", algArr);
                summary.addProperty("total_findings", findings.size());
                result.add("summary", summary);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_hardcoded_credentials ─────────────────────────────────

    private void handleFindHardcodedCredentials(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        double entropyThreshold = 4.0;
        try { entropyThreshold = Double.parseDouble(params.getOrDefault("entropy_threshold", "4.0")); }
        catch (NumberFormatException ignored) {}
        boolean includeLowEntropy = !"false".equalsIgnoreCase(params.get("include_low_entropy"));
        final double et = entropyThreshold;

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                JsonArray findings = new JsonArray();
                int critical = 0, high = 0, medium = 0;

                // Low-entropy keyword patterns
                Set<String> credKeywords = Set.of("password", "passwd", "admin", "root", "secret",
                    "token", "apikey", "api_key", "credential", "default", "login", "1234");
                Set<String> pemMarkers = Set.of("-----begin", "private key", "certificate");

                // Collect auth-related function names for proximity analysis
                Set<String> authFuncNames = new HashSet<>();
                Set<String> authKeywords = Set.of("auth", "login", "verify", "check_pass",
                    "validate", "credential", "decrypt", "key", "sign", "hash", "hmac", "password");
                FunctionIterator fi = p.getFunctionManager().getFunctions(true);
                while (fi.hasNext()) {
                    Function f = fi.next();
                    String fn = f.getName().toLowerCase();
                    for (String kw : authKeywords) {
                        if (fn.contains(kw)) { authFuncNames.add(f.getName()); break; }
                    }
                }

                // Scan all defined strings
                DataIterator di = p.getListing().getDefinedData(true);
                int count = 0;
                while (di.hasNext() && count < 500) {
                    Data data = di.next();
                    if (!data.hasStringValue()) continue;
                    Object val = data.getValue();
                    if (val == null) continue;
                    String sv = val.toString();
                    if (sv.length() < 4) continue;

                    String svLower = sv.toLowerCase();
                    String type = null;
                    String severity = null;
                    String detectionMethod = null;
                    String context = null;

                    // Pattern matching
                    if (includeLowEntropy) {
                        for (String kw : credKeywords) {
                            if (svLower.contains(kw)) {
                                type = "credential_keyword";
                                severity = svLower.contains(":") ? "critical" : "medium";
                                detectionMethod = "pattern_match";
                                context = "Contains credential keyword '" + kw + "'";
                                break;
                            }
                        }
                    }

                    if (type == null) {
                        for (String pm : pemMarkers) {
                            if (svLower.contains(pm)) {
                                type = "pem_marker"; severity = "critical";
                                detectionMethod = "pattern_match";
                                context = "PEM/certificate marker found";
                                break;
                            }
                        }
                    }

                    // URL with credentials
                    if (type == null && (svLower.contains("://") && svLower.contains("@") && svLower.contains(":"))) {
                        type = "url_with_credentials"; severity = "critical";
                        detectionMethod = "pattern_match";
                        context = "URL contains embedded credentials";
                    }

                    // Connection strings
                    if (type == null && (svLower.startsWith("mysql://") || svLower.startsWith("mongodb://") ||
                        svLower.startsWith("redis://") || svLower.startsWith("postgresql://"))) {
                        type = "connection_string"; severity = "high";
                        detectionMethod = "pattern_match";
                        context = "Database connection string";
                    }

                    // Hex-encoded keys (32, 48, 64 hex chars)
                    if (type == null && sv.length() >= 32 && sv.matches("[0-9a-fA-F]+") &&
                        (sv.length() == 32 || sv.length() == 48 || sv.length() == 64 || sv.length() == 128)) {
                        type = "hex_encoded_key"; severity = "high";
                        detectionMethod = "pattern_match";
                        context = sv.length()/2 + "-byte hex string, potential crypto key";
                    }

                    // Entropy-based detection for longer strings
                    if (type == null && sv.length() >= 8) {
                        double ent = shannonEntropy(sv);
                        // Skip obvious non-secrets (paths, format strings, URLs without creds)
                        boolean benign = svLower.contains("/") || svLower.contains("%") ||
                            svLower.startsWith("http") || svLower.contains("\\");
                        if (ent >= et && !benign) {
                            type = "high_entropy_string"; severity = "medium";
                            detectionMethod = "entropy";
                            context = String.format("Entropy %.1f exceeds threshold %.1f", ent, et);
                        }
                    }

                    if (type == null) continue;

                    // Proximity analysis: check if referenced by auth functions
                    JsonArray referencedBy = new JsonArray();
                    ReferenceManager rm = p.getReferenceManager();
                    for (Reference ref : rm.getReferencesTo(data.getAddress())) {
                        Function rf = p.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (rf != null) {
                            JsonObject rfo = new JsonObject();
                            rfo.addProperty("function", rf.getName());
                            rfo.addProperty("address", rf.getEntryPoint().toString());
                            referencedBy.add(rfo);
                            if (authFuncNames.contains(rf.getName())) {
                                if ("medium".equals(severity)) severity = "high";
                                context = (context != null ? context + "; " : "") + "Referenced by auth function '" + rf.getName() + "'";
                            }
                        }
                    }

                    String displayValue = sv.length() > 64 ? sv.substring(0, 64) + "..." : sv;
                    JsonObject finding = new JsonObject();
                    finding.addProperty("address", data.getAddress().toString());
                    finding.addProperty("value", displayValue);
                    finding.addProperty("type", type);
                    finding.addProperty("entropy", Math.round(shannonEntropy(sv) * 10.0) / 10.0);
                    finding.addProperty("detection_method", detectionMethod);
                    finding.add("referenced_by", referencedBy);
                    finding.addProperty("severity", severity);
                    finding.addProperty("context", context);
                    findings.add(finding);

                    if ("critical".equals(severity)) critical++;
                    else if ("high".equals(severity)) high++;
                    else medium++;
                    count++;
                }

                JsonObject result = new JsonObject();
                result.add("findings", findings);
                JsonObject summary = new JsonObject();
                summary.addProperty("critical", critical);
                summary.addProperty("high", high);
                summary.addProperty("medium", medium);
                summary.addProperty("total", findings.size());
                result.add("summary", summary);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /trace_call_path ───────────────────────────────────────────

    private void handleTraceCallPath(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String sourceStr = params.get("source");
        String sinkStr = params.get("sink");
        if (sourceStr == null || sinkStr == null) {
            sendResponse(exchange, 400, errorJson("Missing 'source' or 'sink' parameter").toString());
            return;
        }
        int maxDepth = Math.min(parseInt(params.get("max_depth"), 10), 25);
        int maxPaths = Math.min(parseInt(params.get("max_paths"), 5), 20);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                Function sourceFunc = resolveFunctionByNameOrAddress(p, sourceStr);
                Function sinkFunc = resolveFunctionByNameOrAddress(p, sinkStr);
                if (sourceFunc == null) return errorJson("Source function not found: " + sourceStr).toString();
                if (sinkFunc == null) return errorJson("Sink function not found: " + sinkStr).toString();

                // Build call graph adjacency map
                Map<Address, Set<Address>> callGraph = new HashMap<>();
                Map<Address, String> funcNames = new HashMap<>();
                ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
                FunctionIterator fi = p.getFunctionManager().getFunctions(true);
                while (fi.hasNext()) {
                    Function f = fi.next();
                    Address addr = f.getEntryPoint();
                    funcNames.put(addr, f.getName());
                    Set<Address> callees = new HashSet<>();
                    for (Function called : f.getCalledFunctions(monitor)) {
                        callees.add(called.getEntryPoint());
                    }
                    callGraph.put(addr, callees);
                }

                // BFS/DFS to find paths
                Address sourceAddr = sourceFunc.getEntryPoint();
                Address sinkAddr = sinkFunc.getEntryPoint();
                List<List<Address>> foundPaths = new ArrayList<>();

                // DFS with path tracking
                Deque<List<Address>> stack = new ArrayDeque<>();
                List<Address> initialPath = new ArrayList<>();
                initialPath.add(sourceAddr);
                stack.push(initialPath);

                while (!stack.isEmpty() && foundPaths.size() < maxPaths) {
                    List<Address> currentPath = stack.pop();
                    Address current = currentPath.get(currentPath.size() - 1);

                    if (current.equals(sinkAddr)) {
                        foundPaths.add(currentPath);
                        continue;
                    }

                    if (currentPath.size() > maxDepth) continue;

                    Set<Address> callees = callGraph.getOrDefault(current, Collections.emptySet());
                    for (Address callee : callees) {
                        if (!currentPath.contains(callee)) { // avoid cycles
                            List<Address> newPath = new ArrayList<>(currentPath);
                            newPath.add(callee);
                            stack.push(newPath);
                        }
                    }
                }

                JsonObject result = new JsonObject();
                JsonObject src = new JsonObject();
                src.addProperty("name", sourceFunc.getName());
                src.addProperty("address", sourceAddr.toString());
                result.add("source", src);
                JsonObject snk = new JsonObject();
                snk.addProperty("name", sinkFunc.getName());
                snk.addProperty("address", sinkAddr.toString());
                result.add("sink", snk);
                result.addProperty("paths_found", foundPaths.size());
                result.addProperty("max_depth_used", maxDepth);

                JsonArray pathsArr = new JsonArray();
                for (List<Address> path : foundPaths) {
                    JsonObject po = new JsonObject();
                    po.addProperty("length", path.size());
                    JsonArray chain = new JsonArray();
                    for (Address a : path) {
                        JsonObject node = new JsonObject();
                        node.addProperty("name", funcNames.getOrDefault(a, "unknown"));
                        node.addProperty("address", a.toString());
                        chain.add(node);
                    }
                    po.add("chain", chain);
                    pathsArr.add(po);
                }
                result.add("paths", pathsArr);
                result.addProperty("search_exhausted", foundPaths.size() < maxPaths);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_dangerous_sinks ──────────────────────────────────────

    private void handleFindDangerousSinks(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String categories = params.getOrDefault("categories", "all").toLowerCase();
        Set<String> cats = categories.equals("all") ? null : new HashSet<>(Arrays.asList(categories.split(",")));

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                Map<String, String> dangerousFuncs = new LinkedHashMap<>();
                if (cats == null || cats.contains("buffer_overflow")) {
                    for (String fn : new String[]{"strcpy", "strcat", "gets", "sprintf", "vsprintf",
                            "wcscpy", "wcscat", "memcpy", "memmove"})
                        dangerousFuncs.put(fn, "buffer_overflow");
                }
                if (cats == null || cats.contains("format_string")) {
                    for (String fn : new String[]{"printf", "fprintf", "sprintf", "snprintf",
                            "vprintf", "vsprintf", "vsnprintf", "syslog"})
                        dangerousFuncs.putIfAbsent(fn, "format_string");
                }
                if (cats == null || cats.contains("command_injection")) {
                    for (String fn : new String[]{"system", "popen", "exec", "execl", "execle",
                            "execlp", "execv", "execve", "execvp", "dlopen"})
                        dangerousFuncs.put(fn, "command_injection");
                }
                if (cats == null || cats.contains("memory")) {
                    for (String fn : new String[]{"malloc", "calloc", "realloc", "free", "alloca"})
                        dangerousFuncs.put(fn, "memory");
                }

                JsonArray findingsArr = new JsonArray();
                Map<String, Integer> catCounts = new LinkedHashMap<>();
                FunctionManager fm = p.getFunctionManager();
                ReferenceManager rm = p.getReferenceManager();

                for (Map.Entry<String, String> entry : dangerousFuncs.entrySet()) {
                    String dangerousName = entry.getKey();
                    String category = entry.getValue();

                    // Find this function
                    FunctionIterator fi = fm.getFunctions(true);
                    while (fi.hasNext()) {
                        Function f = fi.next();
                        if (!f.getName().equals(dangerousName)) continue;

                        // Get all callers
                        for (Reference ref : rm.getReferencesTo(f.getEntryPoint())) {
                            if (!ref.getReferenceType().isCall()) continue;
                            Function caller = fm.getFunctionContaining(ref.getFromAddress());
                            if (caller == null) continue;

                            String riskLevel = category.equals("command_injection") ? "critical" :
                                category.equals("buffer_overflow") ? "high" : "medium";

                            JsonObject finding = new JsonObject();
                            finding.addProperty("dangerous_function", dangerousName);
                            finding.addProperty("category", category);
                            finding.addProperty("call_site_address", ref.getFromAddress().toString());
                            JsonObject callerObj = new JsonObject();
                            callerObj.addProperty("name", caller.getName());
                            callerObj.addProperty("address", caller.getEntryPoint().toString());
                            finding.add("calling_function", callerObj);
                            finding.addProperty("risk_level", riskLevel);
                            findingsArr.add(finding);

                            catCounts.merge(category, 1, Integer::sum);
                        }
                    }
                }

                JsonObject result = new JsonObject();
                result.addProperty("total_call_sites", findingsArr.size());
                JsonObject byCat = new JsonObject();
                for (Map.Entry<String, Integer> e : catCounts.entrySet())
                    byCat.addProperty(e.getKey(), e.getValue());
                result.add("by_category", byCat);
                result.add("findings", findingsArr);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_format_string_vulns ───────────────────────────────────

    private void handleFindFormatStringVulns(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        boolean includeSnprintf = !"false".equalsIgnoreCase(params.get("include_snprintf"));

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                // printf-family functions and which param index is the format string
                Map<String, Integer> printfFuncs = new LinkedHashMap<>();
                printfFuncs.put("printf", 0);
                printfFuncs.put("fprintf", 1);
                printfFuncs.put("sprintf", 1);
                printfFuncs.put("vprintf", 0);
                printfFuncs.put("vsprintf", 1);
                printfFuncs.put("syslog", 1);
                printfFuncs.put("dprintf", 1);
                if (includeSnprintf) {
                    printfFuncs.put("snprintf", 2);
                    printfFuncs.put("vsnprintf", 2);
                }

                JsonArray findingsArr = new JsonArray();
                int totalCalls = 0, vulnerableCalls = 0, safeCalls = 0;
                FunctionManager fm = p.getFunctionManager();
                ReferenceManager rm = p.getReferenceManager();

                for (Map.Entry<String, Integer> pf : printfFuncs.entrySet()) {
                    String printfName = pf.getKey();
                    int fmtArgIndex = pf.getValue();

                    FunctionIterator fi = fm.getFunctions(true);
                    while (fi.hasNext()) {
                        Function f = fi.next();
                        if (!f.getName().equals(printfName)) continue;

                        for (Reference ref : rm.getReferencesTo(f.getEntryPoint())) {
                            if (!ref.getReferenceType().isCall()) continue;
                            totalCalls++;
                            Function caller = fm.getFunctionContaining(ref.getFromAddress());
                            if (caller == null) continue;

                            // Check if the format arg references a constant string
                            // Simple heuristic: look at references near the call site
                            Address callSite = ref.getFromAddress();
                            boolean hasConstantFmt = false;

                            // Look at a few instructions before the call for string references
                            Instruction inst = p.getListing().getInstructionBefore(callSite);
                            int lookback = 0;
                            while (inst != null && lookback < 8) {
                                Reference[] instrRefs = rm.getReferencesFrom(inst.getAddress());
                                for (Reference ir : instrRefs) {
                                    Data targetData = p.getListing().getDefinedDataAt(ir.getToAddress());
                                    if (targetData != null && targetData.hasStringValue()) {
                                        String sv = targetData.getValue().toString();
                                        if (sv.contains("%")) {
                                            hasConstantFmt = true;
                                        }
                                    }
                                }
                                inst = inst.getPrevious();
                                lookback++;
                            }

                            if (hasConstantFmt) {
                                safeCalls++;
                            } else {
                                vulnerableCalls++;
                                JsonObject finding = new JsonObject();
                                finding.addProperty("printf_function", printfName);
                                finding.addProperty("call_site_address", callSite.toString());
                                finding.addProperty("calling_function", caller.getName());
                                finding.addProperty("format_arg_source", "non-constant (variable or parameter)");
                                finding.addProperty("severity", printfName.contains("snprintf") ? "medium" : "critical");
                                finding.addProperty("explanation",
                                    "No constant format string detected near call site - format arg may be user-controlled");
                                findingsArr.add(finding);
                            }
                        }
                    }
                }

                JsonObject result = new JsonObject();
                result.addProperty("total_printf_calls", totalCalls);
                result.addProperty("vulnerable_calls", vulnerableCalls);
                result.addProperty("safe_calls", safeCalls);
                result.add("findings", findingsArr);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /detect_rtos ───────────────────────────────────────────────

    private void handleDetectRtos(HttpExchange exchange) throws IOException {
        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                JsonArray evidence = new JsonArray();
                Set<String> rtosFuncsFound = new LinkedHashSet<>();

                // Define RTOS signatures: {name, strings[], function_names[]}
                Map<String, String[][]> rtosSignatures = new LinkedHashMap<>();
                rtosSignatures.put("FreeRTOS", new String[][]{
                    {"IDLE", "Tmr Svc", "Tmr Daemon", "FreeRTOS"},
                    {"vTaskStartScheduler", "xTaskCreate", "xQueueCreate", "vTaskDelay",
                     "pvPortMalloc", "xTimerCreate", "vTaskDelete", "xSemaphoreCreateMutex"}
                });
                rtosSignatures.put("Zephyr", new String[][]{
                    {"zephyr", "CONFIG_"},
                    {"k_thread_create", "k_sem_give", "k_mutex_lock", "k_msgq_put", "z_impl_"}
                });
                rtosSignatures.put("ThreadX", new String[][]{
                    {"ThreadX", "_tx_"},
                    {"tx_thread_create", "tx_byte_pool_create", "tx_semaphore_create", "tx_queue_create"}
                });
                rtosSignatures.put("VxWorks", new String[][]{
                    {"VxWorks", "Wind River"},
                    {"taskSpawn", "semBCreate", "msgQCreate", "sysInit", "usrInit", "kernelInit"}
                });
                rtosSignatures.put("Mbed OS", new String[][]{
                    {"mbed", "Mbed OS"},
                    {"osThreadNew", "osMutexNew", "osEventFlagsNew"}
                });
                rtosSignatures.put("RIOT OS", new String[][]{
                    {"RIOT", "riot"},
                    {"thread_create", "mutex_lock", "msg_send"}
                });
                rtosSignatures.put("NuttX", new String[][]{
                    {"NuttX", "nuttx"},
                    {"nxtask_create", "nxsem_wait"}
                });
                rtosSignatures.put("Contiki", new String[][]{
                    {"Contiki", "contiki"},
                    {"process_start", "etimer_set"}
                });

                Map<String, Integer> scores = new LinkedHashMap<>();

                // Check function names
                FunctionIterator fi = p.getFunctionManager().getFunctions(true);
                Set<String> allFuncNames = new HashSet<>();
                while (fi.hasNext()) allFuncNames.add(fi.next().getName());

                for (Map.Entry<String, String[][]> entry : rtosSignatures.entrySet()) {
                    String rtosName = entry.getKey();
                    String[] funcPatterns = entry.getValue()[1];
                    int score = 0;
                    for (String pattern : funcPatterns) {
                        for (String funcName : allFuncNames) {
                            if (funcName.contains(pattern)) {
                                score += 2;
                                rtosFuncsFound.add(funcName);
                                JsonObject ev = new JsonObject();
                                ev.addProperty("type", "function");
                                ev.addProperty("value", funcName);
                                // Find address
                                for (Function f : p.getFunctionManager().getFunctions(true)) {
                                    if (f.getName().equals(funcName)) {
                                        ev.addProperty("address", f.getEntryPoint().toString());
                                        break;
                                    }
                                }
                                ev.addProperty("rtos", rtosName);
                                evidence.add(ev);
                                break; // one match per pattern is enough
                            }
                        }
                    }
                    scores.put(rtosName, score);
                }

                // Check strings
                DataIterator di = p.getListing().getDefinedData(true);
                Set<String> checkedStrings = new HashSet<>();
                while (di.hasNext()) {
                    Data data = di.next();
                    if (!data.hasStringValue()) continue;
                    Object val = data.getValue();
                    if (val == null) continue;
                    String sv = val.toString();
                    if (sv.length() < 3 || sv.length() > 100) continue;

                    for (Map.Entry<String, String[][]> entry : rtosSignatures.entrySet()) {
                        String rtosName = entry.getKey();
                        for (String strPattern : entry.getValue()[0]) {
                            if (sv.contains(strPattern) && checkedStrings.add(rtosName + ":" + strPattern)) {
                                scores.merge(rtosName, 1, Integer::sum);
                                JsonObject ev = new JsonObject();
                                ev.addProperty("type", "string");
                                ev.addProperty("value", sv.length() > 50 ? sv.substring(0, 50) + "..." : sv);
                                ev.addProperty("address", data.getAddress().toString());
                                ev.addProperty("rtos", rtosName);
                                evidence.add(ev);
                            }
                        }
                    }
                }

                // Find the best match
                String detectedRtos = "unknown_bare_metal";
                int bestScore = 0;
                for (Map.Entry<String, Integer> e : scores.entrySet()) {
                    if (e.getValue() > bestScore) {
                        bestScore = e.getValue();
                        detectedRtos = e.getKey();
                    }
                }
                String confidence = bestScore >= 5 ? "high" : bestScore >= 2 ? "medium" : bestScore >= 1 ? "low" : "none";
                if (bestScore == 0) detectedRtos = "unknown_bare_metal";

                // Analysis hints
                JsonArray hints = new JsonArray();
                if (detectedRtos.equals("FreeRTOS")) {
                    hints.add("FreeRTOS detected. Look for TCB (Task Control Block) structures.");
                    hints.add("Each task has its own stack. Check xTaskCreate calls for stack sizes.");
                    hints.add("Priority inversion vulnerabilities are common - check mutex usage patterns.");
                } else if (detectedRtos.equals("unknown_bare_metal")) {
                    hints.add("No RTOS detected - likely bare-metal firmware.");
                    hints.add("Look for a main loop pattern (infinite while loop in reset handler).");
                    hints.add("Check for interrupt-driven architecture via the vector table.");
                } else {
                    hints.add(detectedRtos + " detected. Analyze task creation and IPC mechanisms.");
                }

                JsonObject result = new JsonObject();
                result.addProperty("detected_rtos", detectedRtos);
                result.addProperty("confidence", confidence);
                result.add("evidence", evidence);
                JsonArray funcsArr = new JsonArray();
                for (String fn : rtosFuncsFound) funcsArr.add(fn);
                result.add("rtos_functions_found", funcsArr);
                result.add("analysis_hints", hints);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /find_function_pointer_tables ───────────────────────────────

    private void handleFindFunctionPointerTables(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        int minEntries = Math.max(parseInt(params.get("min_entries"), 3), 2);
        String scanStartStr = params.get("scan_range_start");
        String scanEndStr = params.get("scan_range_end");

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                int ptrSize = p.getAddressFactory().getDefaultAddressSpace().getSize() / 8; // bytes
                Memory mem = p.getMemory();
                FunctionManager fm = p.getFunctionManager();

                // Collect valid code address ranges
                List<long[]> codeRanges = new ArrayList<>();
                for (MemoryBlock block : mem.getBlocks()) {
                    if (block.isExecute()) {
                        codeRanges.add(new long[]{block.getStart().getOffset(), block.getEnd().getOffset()});
                    }
                }
                if (codeRanges.isEmpty()) {
                    return errorJson("No executable memory blocks found").toString();
                }

                // Determine scan range (data regions)
                Address scanStart = null, scanEnd = null;
                if (scanStartStr != null) scanStart = parseAddress(p, scanStartStr);
                if (scanEndStr != null) scanEnd = parseAddress(p, scanEndStr);
                if (scanStart == null || scanEnd == null) {
                    for (MemoryBlock block : mem.getBlocks()) {
                        if (block.isInitialized()) {
                            if (scanStart == null || block.getStart().compareTo(scanStart) < 0)
                                scanStart = block.getStart();
                            if (scanEnd == null || block.getEnd().compareTo(scanEnd) > 0)
                                scanEnd = block.getEnd();
                        }
                    }
                }
                if (scanStart == null) return errorJson("No initialized memory to scan").toString();

                JsonArray tables = new JsonArray();
                Address cursor = scanStart;
                int tablesCap = 100;
                boolean isCortexM = detectArchitecture(p).equals("arm");

                while (cursor != null && cursor.compareTo(scanEnd) < 0 && tables.size() < tablesCap) {
                    // Align cursor
                    long off = cursor.getOffset();
                    if (off % ptrSize != 0) {
                        cursor = cursor.add(ptrSize - (off % ptrSize));
                        continue;
                    }

                    // Count consecutive code pointers
                    List<long[]> entries = new ArrayList<>(); // [rawValue, resolvedAddr]
                    Address entryAddr = cursor;
                    while (entryAddr.compareTo(scanEnd) < 0 && entries.size() < 256) {
                        try {
                            long val;
                            if (ptrSize == 4) {
                                val = Integer.toUnsignedLong(mem.getInt(entryAddr));
                            } else {
                                val = mem.getLong(entryAddr);
                            }
                            long resolved = isCortexM ? (val & ~1L) : val;
                            boolean isCodePtr = false;
                            for (long[] range : codeRanges) {
                                if (resolved >= range[0] && resolved <= range[1]) {
                                    isCodePtr = true;
                                    break;
                                }
                            }
                            if (!isCodePtr) break;
                            entries.add(new long[]{val, resolved});
                            entryAddr = entryAddr.add(ptrSize);
                        } catch (Exception e) {
                            break;
                        }
                    }

                    if (entries.size() >= minEntries) {
                        JsonObject table = new JsonObject();
                        table.addProperty("base_address", cursor.toString());
                        table.addProperty("num_entries", entries.size());
                        table.addProperty("entry_size", ptrSize);

                        MemoryBlock region = mem.getBlock(cursor);
                        table.addProperty("region", region != null ? region.getName() : "unknown");

                        JsonArray entriesArr = new JsonArray();
                        for (int i = 0; i < entries.size(); i++) {
                            JsonObject eo = new JsonObject();
                            eo.addProperty("index", i);
                            eo.addProperty("pointer", String.format("0x%08X", entries.get(i)[0]));
                            Address targetAddr = p.getAddressFactory().getDefaultAddressSpace()
                                .getAddress(entries.get(i)[1]);
                            Function tf = fm.getFunctionAt(targetAddr);
                            eo.addProperty("function", tf != null ? tf.getName() : null);
                            entriesArr.add(eo);
                        }
                        table.add("entries", entriesArr);

                        // Find xrefs to this table
                        JsonArray xrefs = new JsonArray();
                        ReferenceManager rm = p.getReferenceManager();
                        for (Reference ref : rm.getReferencesTo(cursor)) {
                            Function rf = fm.getFunctionContaining(ref.getFromAddress());
                            if (rf != null) {
                                JsonObject xo = new JsonObject();
                                xo.addProperty("from_function", rf.getName());
                                xo.addProperty("from_address", ref.getFromAddress().toString());
                                xrefs.add(xo);
                            }
                        }
                        table.add("xrefs_to_table", xrefs);
                        table.addProperty("likely_purpose", entries.size() > 16 ? "vtable" : "command_dispatch_table");

                        tables.add(table);
                        cursor = entryAddr; // skip past the table
                    } else {
                        cursor = cursor.add(ptrSize);
                    }
                }

                JsonObject result = new JsonObject();
                result.addProperty("tables_found", tables.size());
                result.add("tables", tables);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    // ── GET /get_string_clusters ───────────────────────────────────────

    private void handleGetStringClusters(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        int maxGap = parseInt(params.get("max_gap"), 64);
        int minClusterSize = parseInt(params.get("min_cluster_size"), 3);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                // Collect all strings sorted by address
                List<Data> strings = new ArrayList<>();
                DataIterator di = p.getListing().getDefinedData(true);
                while (di.hasNext()) {
                    Data data = di.next();
                    if (data.hasStringValue() && data.getValue() != null) {
                        strings.add(data);
                    }
                }

                // Cluster by proximity
                List<List<Data>> clusters = new ArrayList<>();
                List<Data> currentCluster = new ArrayList<>();

                for (int i = 0; i < strings.size(); i++) {
                    if (currentCluster.isEmpty()) {
                        currentCluster.add(strings.get(i));
                    } else {
                        Data prev = currentCluster.get(currentCluster.size() - 1);
                        Data curr = strings.get(i);
                        long prevEnd = prev.getAddress().getOffset() + prev.getLength();
                        long currStart = curr.getAddress().getOffset();
                        if (currStart - prevEnd <= maxGap) {
                            currentCluster.add(curr);
                        } else {
                            if (currentCluster.size() >= minClusterSize) {
                                clusters.add(currentCluster);
                            }
                            currentCluster = new ArrayList<>();
                            currentCluster.add(curr);
                        }
                    }
                }
                if (currentCluster.size() >= minClusterSize) {
                    clusters.add(currentCluster);
                }

                JsonArray clustersArr = new JsonArray();
                ReferenceManager rm = p.getReferenceManager();
                FunctionManager fm = p.getFunctionManager();

                for (int ci = 0; ci < clusters.size() && ci < 100; ci++) {
                    List<Data> cluster = clusters.get(ci);
                    JsonObject co = new JsonObject();
                    co.addProperty("id", ci);
                    co.addProperty("start_address", cluster.get(0).getAddress().toString());
                    Data lastData = cluster.get(cluster.size() - 1);
                    co.addProperty("end_address",
                        lastData.getAddress().add(lastData.getLength() - 1).toString());
                    co.addProperty("num_strings", cluster.size());

                    JsonArray stringsArr = new JsonArray();
                    Set<String> referencingFuncs = new LinkedHashSet<>();
                    for (Data d : cluster) {
                        JsonObject so = new JsonObject();
                        so.addProperty("address", d.getAddress().toString());
                        String sv = d.getValue().toString();
                        so.addProperty("value", sv.length() > 80 ? sv.substring(0, 80) + "..." : sv);
                        stringsArr.add(so);

                        // Find referencing functions
                        for (Reference ref : rm.getReferencesTo(d.getAddress())) {
                            Function f = fm.getFunctionContaining(ref.getFromAddress());
                            if (f != null) referencingFuncs.add(f.getName());
                        }
                    }
                    co.add("strings", stringsArr);

                    JsonArray rfArr = new JsonArray();
                    for (String fn : referencingFuncs) rfArr.add(fn);
                    co.add("referencing_functions", rfArr);

                    // Attempt to infer module name from common substrings
                    String inferred = inferModule(cluster);
                    co.addProperty("inferred_module", inferred);

                    clustersArr.add(co);
                }

                JsonObject result = new JsonObject();
                result.addProperty("clusters_found", clustersArr.size());
                result.add("clusters", clustersArr);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }

    private String inferModule(List<Data> cluster) {
        // Look for common prefixes or keywords in the cluster strings
        Map<String, Integer> wordFreq = new HashMap<>();
        for (Data d : cluster) {
            String sv = d.getValue().toString().toLowerCase();
            // Check for common firmware module indicators
            if (sv.contains("at+")) return "AT command interface";
            if (sv.contains("uart") || sv.contains("serial")) return "UART/Serial";
            if (sv.contains("wifi") || sv.contains("wlan")) return "WiFi";
            if (sv.contains("ble") || sv.contains("bluetooth")) return "Bluetooth/BLE";
            if (sv.contains("http") || sv.contains("html")) return "HTTP/Web";
            if (sv.contains("mqtt")) return "MQTT";
            if (sv.contains("gpio")) return "GPIO";
            if (sv.contains("spi")) return "SPI";
            if (sv.contains("i2c")) return "I2C";
            if (sv.contains("tcp") || sv.contains("socket")) return "TCP/Networking";
            if (sv.contains("ssl") || sv.contains("tls") || sv.contains("cert")) return "TLS/SSL";
            if (sv.contains("ota") || sv.contains("update") || sv.contains("upgrade")) return "OTA Update";
            if (sv.contains("flash") || sv.contains("erase") || sv.contains("sector")) return "Flash Storage";
            if (sv.contains("error") || sv.contains("fail") || sv.contains("assert")) return "Error Handling";
        }
        return null;
    }

    // ── GET /get_function_hashes ───────────────────────────────────────

    private void handleGetFunctionHashes(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI());
        String hashAlg = params.getOrDefault("hash_algorithm", "opcode_only");
        String filterText = params.get("filter_text");
        int offset = parseInt(params.get("offset"), 0);
        int limit = Math.min(parseInt(params.get("limit"), 200), 500);

        try {
            String json = runOnSwing(() -> {
                Program p = getActiveProgram();
                if (p == null) return errorJson("No program loaded").toString();

                List<Function> matched = new ArrayList<>();
                FunctionIterator fi = p.getFunctionManager().getFunctions(true);
                while (fi.hasNext()) {
                    Function f = fi.next();
                    if (filterText == null || f.getName().toLowerCase().contains(filterText.toLowerCase())) {
                        matched.add(f);
                    }
                }

                int total = matched.size();
                JsonArray funcsArr = new JsonArray();
                int end = Math.min(offset + limit, total);

                for (int i = offset; i < end; i++) {
                    Function f = matched.get(i);
                    StringBuilder hashInput = new StringBuilder();
                    int instrCount = 0;

                    Instruction inst = p.getListing().getInstructionAt(f.getEntryPoint());
                    AddressSetView body = f.getBody();
                    while (inst != null && body.contains(inst.getAddress())) {
                        switch (hashAlg) {
                            case "opcode_only":
                                hashInput.append(inst.getMnemonicString()).append(' ');
                                break;
                            case "structural":
                                hashInput.append(inst.getMnemonicString());
                                for (int oi = 0; oi < inst.getNumOperands(); oi++) {
                                    int opType = inst.getOperandType(oi);
                                    hashInput.append(opType);
                                }
                                hashInput.append(' ');
                                break;
                            case "exact":
                                for (byte b : inst.getBytes()) {
                                    hashInput.append(String.format("%02X", b & 0xFF));
                                }
                                break;
                            default:
                                hashInput.append(inst.getMnemonicString()).append(' ');
                        }
                        instrCount++;
                        inst = inst.getNext();
                    }

                    // SHA-256 hash
                    String hash;
                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] digest = md.digest(hashInput.toString().getBytes(StandardCharsets.UTF_8));
                        StringBuilder sb = new StringBuilder();
                        for (byte b : digest) sb.append(String.format("%02x", b & 0xFF));
                        hash = sb.toString();
                    } catch (Exception e) {
                        hash = "error";
                    }

                    JsonObject fo = new JsonObject();
                    fo.addProperty("name", f.getName());
                    fo.addProperty("address", f.getEntryPoint().toString());
                    fo.addProperty("hash", hash);
                    fo.addProperty("instruction_count", instrCount);
                    fo.addProperty("size", f.getBody().getNumAddresses());
                    funcsArr.add(fo);
                }

                JsonObject result = new JsonObject();
                result.addProperty("hash_algorithm", hashAlg);
                result.addProperty("total", total);
                result.add("functions", funcsArr);
                return result.toString();
            });
            sendResponse(exchange, 200, json);
        } catch (Exception e) {
            sendResponse(exchange, 500, errorJson(e.getMessage()).toString());
        }
    }
}
