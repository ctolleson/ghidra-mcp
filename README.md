## Prerequisites

1. **Ghidra 11.3.1** (Strict requirement)
* Download from the [official release page](https://github.com/NationalSecurityAgency/ghidra/releases).


2. **Java 17 or 21** (JDK)
* Required to build the extension.


3. **Gradle**
* Install via `brew install gradle` (Mac) or your package manager.


4. **Python 3.10+**
5. **Node.js / npx** (Optional, for testing with MCP Inspector).

---

## Step 1: Build the Ghidra Extension

1. Clone this repository.
2. Open `build.gradle` in a text editor.
3. **CRITICAL:** Update the `ghidraInstallDir` variable to point to your local Ghidra installation.
```groovy
// Example (Mac):
def ghidraInstallDir = "/Users/username/Desktop/ghidra_11.3.1_PUBLIC"
// Example (Windows):
// def ghidraInstallDir = "C:\\Tools\\ghidra_11.3.1_PUBLIC"

```


4. Build the project using Gradle:
```bash
gradle build

```


5. If successful, a ZIP file will be created in the `dist/` folder:
* `dist/ghidra-mcp.zip`



---

## Step 2: Install Extension in Ghidra

1. Open Ghidra.
2. From the main Project Manager window, go to **File** -> **Install Extensions**.
3. Click the green **Plus (+)** icon.
4. Navigate to your `dist/` folder and select `ghidra-mcp.zip`.
5. Click **OK**. Ensure the checkbox next to `ghidra-mcp` is checked.
6. **Restart Ghidra.**

### Activate the Plugin

Only necessary to do this if Ghidra didn't prompt you to automatically configure the new plugin.
After restarting, the plugin is installed but not yet running in your tool.

1. Open a binary in the **CodeBrowser** (Dragon icon).
2. Go to **File** -> **Configure...**.
3. Click the **Plug Icon** (top right) or "Add Plugin".
4. Scroll down to the **Utility** category (or search for `GhidraMCPPlugin`).
5. **Check the box** to enable it.
6. Look at the Console (bottom of screen). You should see:
> `[INFO] MCP HTTP Server started on port 8080`



---

## Step 3: Run the MCP Server (Python)

1. Navigate to the `mcp_server` directory (or root).
2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate
pip install mcp requests

```


3. (Optional) Edit `mcp_server/main.py` if your Ghidra is running on a different machine/port.

---

## Step 4: Verify Setup

We use the **MCP Inspector** to verify the entire pipeline is working without needing an LLM key.

1. Ensure Ghidra is running and the **port 8080** is open (`lsof -i :8080`).
2. Run the inspector:
```bash
npx @modelcontextprotocol/inspector python mcp_server/main.py

```


3. A web interface will open (usually `http://localhost:5173`).
4. Find the `ping_ghidra` tool in the list.
5. Click **Run Tool**.

**Success:** You should see a JSON result:

```json
"Success! Ghidra says: {\"status\": \"pong\"}"

```
