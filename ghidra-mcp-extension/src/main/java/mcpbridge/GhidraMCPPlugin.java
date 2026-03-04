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
                    p.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, comment);
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
}
