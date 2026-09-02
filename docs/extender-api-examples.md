# Extender API Examples and Patterns (Python / Jython)

These examples target Burp Suite's legacy **Extender API**, which is what Python extensions use
via the bundled **Jython 2.7** interpreter (i.e. Python 2.7 syntax — no f-strings, use `%` or
`.format()` for string formatting).

The API is provided by the `burp` module, which Burp injects into the Jython interpreter. You do
not import it from a file — Burp makes it available automatically.

## Basic Extension Structure

The main class implements `IBurpExtender` and must be named `BurpExtender`:

```python
from burp import IBurpExtender

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to callbacks and helpers for later use
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set the extension name
        callbacks.setExtensionName("My Extension")

        # Add your extension logic here
        callbacks.printOutput("Extension loaded successfully")
```

## Common Extension Features

The same `callbacks` object (`IBurpExtenderCallbacks`) drives most features. It's common for the
`BurpExtender` class to implement several interface roles at once (a single class can implement
`IContextMenuFactory`, `ITab`, `IHttpListener`, etc.), or to delegate to separate helper classes.

### Logging

```python
callbacks.printOutput("Extension loaded successfully")
callbacks.printError("Error occurred: " + error_message)
callbacks.issueAlert("Something worth showing in the Alerts tab")
```

### Adding Context Menu Items

Implement `IContextMenuFactory` and register it. Return a Python list of `JMenuItem`:

```python
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("My Extension")
        callbacks.registerContextMenuFactory(self)

    # IContextMenuFactory
    def createMenuItems(self, invocation):
        item = JMenuItem("Say hello", actionPerformed=self.say_hello)
        return [item]

    def say_hello(self, event):
        self._callbacks.printOutput("Hello, world!")
```

### Creating Custom Tabs

Implement `ITab` and register it with `addSuiteTab`:

```python
from burp import IBurpExtender, ITab
from javax.swing import JLabel, JPanel

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.setExtensionName("My Extension")
        callbacks.addSuiteTab(self)

    # ITab
    def getTabCaption(self):
        return "My Extension Tab"

    def getUiComponent(self):
        panel = JPanel()
        panel.add(JLabel("Hello, world!"))
        return panel
```

### Persisting Settings

The Extender API has no settings-panel builder. Persist values with `saveExtensionSetting` /
`loadExtensionSetting`, and build your own Swing UI (typically inside a custom tab) for
configuration:

```python
# Save
callbacks.saveExtensionSetting("api_key", "value")

# Load (returns None if the setting was never saved)
api_key = callbacks.loadExtensionSetting("api_key")
```

### Making HTTP Requests

Always use Burp networking so requests go through Burp's configured upstream proxy and TLS
handling:

```python
from java.net import URL

helpers = callbacks.getHelpers()

# Build a request from a URL (adds method, headers and empty line automatically)
request = helpers.buildHttpRequest(URL("https://example.com/"))

# Issue the request; this overload returns the raw response bytes
response = callbacks.makeHttpRequest("example.com", 443, True, request)

response_text = helpers.bytesToString(response)
callbacks.printOutput(response_text)
```

To build a request from individual headers/body, use `buildHttpMessage`:

```python
body = helpers.stringToBytes('{"key": "value"}')
headers = [
    "POST /api HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/json",
    "Content-Length: %d" % len(body),
    "Connection: close",
]
request = helpers.buildHttpMessage(headers, body)
response = callbacks.makeHttpRequest("example.com", 443, True, request)
```

The `makeHttpRequest(host, port, useHttps, request)` overload returns `byte[]`. The
`makeHttpRequest(IHttpService, request)` overload returns an `IHttpRequestResponse` object,
which is useful when you already have an `IHttpService` (e.g. from a Proxy message):

```python
http_service = http_request_response.getHttpService()
result = callbacks.makeHttpRequest(http_service, request)
response = result.getResponse()
```

### Intercepting HTTP Traffic

Implement `IHttpListener` (all Burp tools) and/or `IProxyListener` (Proxy tool only):

```python
from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("My Extension")
        callbacks.registerHttpListener(self)

    # IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request_text = self._helpers.bytesToString(messageInfo.getRequest())
            self._callbacks.printOutput("Request: " + request_text)
```

### Cleaning Up on Unload

Implement `IExtensionStateListener` to stop background threads and release resources:

```python
import threading
from burp import IBurpExtender, IExtensionStateListener

class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.setExtensionName("My Extension")
        callbacks.registerExtensionStateListener(self)

        self._running = True
        self._thread = threading.Thread(target=self._worker)
        self._thread.start()

    def _worker(self):
        while self._running:
            # ... do background work ...
            pass

    # IExtensionStateListener
    def extensionUnloaded(self):
        self._running = False
        self._thread.join()
```

### Providing a Parent Frame for Dialogs

The Extender API does not expose Burp's main frame directly. Get it from any Swing component you
have already registered with Burp (for example a tab's UI component):

```python
from javax.swing import SwingUtilities, JOptionPane

frame = SwingUtilities.getWindowAncestor(self.getUiComponent())
JOptionPane.showMessageDialog(frame, "Hello, world!")
```

## External AI / LLM Integrations

Burp's built-in AI service (`MontoyaApi.ai()`) is **only** available to Java Montoya extensions.
Python Extender API extensions must call an external LLM HTTP API directly through
`callbacks.makeHttpRequest()`:

```python
import json
from java.net import URL

def call_llm(self, prompt):
    helpers = self._callbacks.getHelpers()

    payload = json.dumps({"prompt": prompt})
    body = helpers.stringToBytes(payload)
    headers = [
        "POST /v1/chat/completions HTTP/1.1",
        "Host: api.example.com",
        "Content-Type: application/json",
        "Content-Length: %d" % len(body),
        "Connection: close",
    ]
    request = helpers.buildHttpMessage(headers, body)

    # Run this off the Swing event dispatch thread in real code
    response = self._callbacks.makeHttpRequest("api.example.com", 443, True, request)
    self._callbacks.printOutput("AI Response: " + helpers.bytesToString(response))
```

See `development-best-practices.md` for guidance on using external AI/LLM services safely.
