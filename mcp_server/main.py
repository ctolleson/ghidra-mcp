import requests
from mcp.server.fastmcp import FastMCP

GHIDRA_HOST = "http://127.0.0.1:8080"

mcp = FastMCP("GhidraBridge")

@mcp.tool()
def ping_ghidra() -> str:
    """
    Checks if Ghidra is listening. Returns 'pong' if successful.
    """
    try:
        # We send a GET request to the /ping endpoint defined in Java
        response = requests.get(f"{GHIDRA_HOST}/ping", timeout=2)
        
        if response.status_code == 200:
            return f"Success! Ghidra says: {response.text}"
        else:
            return f"Error: Ghidra returned status {response.status_code}"
            
    except requests.exceptions.ConnectionError:
        return "FAILED: Could not connect to Ghidra. Is the Plugin active in CodeBrowser?"

if __name__ == "__main__":
    mcp.run()