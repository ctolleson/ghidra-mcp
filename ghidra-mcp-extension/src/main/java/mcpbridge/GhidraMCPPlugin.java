package mcpbridge;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "mcpbridge",
    category = PluginCategoryNames.COMMON,
    shortDescription = "Ghidra MCP HTTP Server",
    description = "Exposes Ghidra functionality via HTTP"
)
public class GhidraMCPPlugin extends ProgramPlugin {

    private HttpServer server;
    private static final int PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool, true, true);
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

    private void startServer() {
        try {
            // Create a simple HTTP server on localhost
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", PORT), 0);
            
            // Define endpoints
            server.createContext("/ping", new PingHandler());
            // TODO: Add /decompile, /rename contexts here later
            
            server.setExecutor(null); // creates a default executor
            server.start();
            Msg.info(this, "MCP HTTP Server started on port " + PORT);
            
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }

    private void stopServer() {
        if (server != null) {
            server.stop(0);
            Msg.info(this, "MCP HTTP Server stopped");
        }
    }

    // Handler for /ping
    static class PingHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String response = "{\"status\": \"pong\"}";
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}