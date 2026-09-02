# Development Best Practices (Python / Jython)

Guidance for writing Python extensions against Burp's legacy Extender API.

## Python 2.7 / Jython Constraints

- Burp runs Python extensions on **Jython 2.7**, so write **Python 2.7-compatible** code.
- No f-strings — use `%` formatting or `str.format()`.
- Some standard-library modules (e.g. `ssl`, `ctypes`) don't exist or behave differently under
  Jython. Prefer doing networking through `callbacks.makeHttpRequest()`.
- Don't rely on third-party packages being installed; bundle any modules you need (see
  `bapp-store-requirements.md`).
- Always keep a reference to `callbacks` (and `callbacks.getHelpers()`) in `registerExtenderCallbacks`.

## Threading & Responsiveness

- Never perform slow operations — HTTP requests, file I/O, LLM calls — on the Swing Event
  Dispatch Thread (EDT). GUI code runs on the EDT and blocks the whole of Burp's UI while busy.
- Do slow work in a `threading.Thread` and marshal results back onto the EDT
  (e.g. with `javax.swing.SwingUtilities.invokeLater`) before touching Swing components.
- Avoid slow operations inside `IHttpListener`, `IProxyListener` and other callbacks that Burp
  invokes on hot paths.
- Protect shared state with `threading.Lock`/`RLock` when multiple threads touch the same data.

## Clean Unload

- Implement `IExtensionStateListener.extensionUnloaded()` and stop any threads you started.
- Join threads with a timeout so unloading never hangs Burp.
- Unregister listeners and remove any suite tabs (`callbacks.removeSuiteTab()`) if you added them
  dynamically.

## Networking

- Always route HTTP requests through `callbacks.makeHttpRequest()` so they respect Burp's proxy
  configuration, TLS handling and project scope.
- Work with the helpers: convert between `byte[]` and strings with
  `helpers.bytesToString()` / `helpers.stringToBytes()`; parse messages with `helpers.analyzeRequest()`.

## GUI Best Practices

- Build UI with `javax.swing` (JPanel, JButton, JTable, ...). Use `callbacks.customizeUiComponent()`
  to make components match Burp's look and feel.
- Give dialogs a parent window obtained via
  `SwingUtilities.getWindowAncestor(<component already registered with Burp>)`.

## Large Projects & Memory

- Avoid keeping long-term references to `IHttpRequestResponse` objects and other request/response
  buffers — Burp projects can be huge.
- Be careful with methods that return large results, such as `callbacks.getProxyHistory()` and
  `callbacks.getSiteMap()`.

## External AI / LLM Best Practices

Burp's built-in AI service is only available to Java Montoya extensions. If your Python extension
calls an external AI/LLM service:

- Run AI calls on a background thread, never on the EDT.
- Send only essential data to minimize cost and exposure.
- Use structured formats (JSON) for AI requests and validate the response shape before use.
- Treat AI-generated content as untrusted: escape/validate it before displaying to users or
  inserting into requests.
- Implement response caching for repeated queries.
- Make the calls through `callbacks.makeHttpRequest()` where possible so traffic follows Burp's
  proxy settings.
