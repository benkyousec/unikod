# BApp Store acceptance criteria

You can share your extensions with the community by submitting them to the BApp Store. We review all submitted BApps for security and quality, before we make a decision on whether to include them in the BApp Store.

> This template targets Python (Jython) extensions written against Burp's legacy Extender API,
> so the criteria below use the Python/`burp` module equivalents of the official requirements.

Before you submit your extension, make sure that it meets the following acceptance criteria:

1. #### It performs a unique function.

   Make sure that your extension doesn't duplicate the function of an existing extension in the BApp Store.

   If your idea isn't entirely new, you might be better off tailoring an existing BApp to suit your purposes. You can find the source code for every extension in the BApp Store on our [GitHub repository](https://github.com/PortSwigger).

2. #### It has a clear, descriptive name.

   Make sure that the name clearly describes what the extension does.

   You can also provide a one-line summary that appears in the list (web only), as well as a more detailed description.

3. #### It operates securely.

   Users may be testing sites that they don't trust, so it's important that extensions don't expose users to attack. Treat the content of HTTP messages as untrusted. Extensions should operate securely in expected usage. Data entered by a user into the GUI can generally be trusted, but if there is auto-fill from untrusted sources, don't assume the user will check the contents.

4. #### It includes all dependencies.

   A major benefit of the BApp Store is one-click installation. If your extension includes all dependencies, it is much easier for users to get started. This also avoids version mismatches, where an underlying tool is updated but the BApp is not.

   For a Python extension this means bundling every helper `.py` module and any third-party JAR
   next to your main `.py` file, rather than assuming a particular library is installed in the
   Jython environment.

5. #### It uses threads to maintain responsiveness.

   To maintain responsiveness, perform slow operations in a background thread:

   - Don't perform slow operations - such as HTTP requests - in the Swing Event Dispatch Thread. This causes Burp to appear unresponsive, as the whole GUI must wait until the slow operation completes.
   - Avoid slow operations in `IHttpListener.processHttpMessage()`, `IProxyListener.processProxyMessage()` and in context menu / GUI callbacks.
   - To avoid concurrency issues, protect shared data structures with locks, and take care when accessing objects from different threads.

   Python example: run slow work in a `threading.Thread` (see `extender-api-examples.md`).

6. #### It unloads cleanly.

   When an extension unloads, make sure that it releases all resources, particularly background threads.

   If your extension creates any threads (using `threading.Thread`, `threading.Timer`, Java's
   `Timer`, `SwingWorker`, `ExecutorService`, or similar), make sure they are terminated when the
   extension is unloaded. In Python, implement `IExtensionStateListener.extensionUnloaded()` and
   stop your threads there.

7. #### It uses Burp networking.

   When making HTTP requests, use Burp's `callbacks.makeHttpRequest()` instead of other libraries.

   This ensures that requests are routed through Burp's configured proxy settings, and that TLS certificates are handled correctly.

8. #### It supports offline working.

   Include recent definitions for extensions that contact online services.

   If your extension needs to contact online services (such as for signature updates), make sure to include recent definitions with the extension, so that it can still function when users are offline.

9. #### It can cope with large projects.

   Avoid keeping long-term references to objects and be careful with methods that can return huge results.

   Some users work with huge Burp projects. Be careful when using methods that can return huge results, such as `callbacks.getProxyHistory()` and `callbacks.getSiteMap()`.

10. #### It provides a parent for GUI elements.

    Ensure GUI elements are children of the main Burp Frame.

    When you create GUI elements such as dialogs, make sure they are children of the main Burp
    Frame. The Extender API doesn't expose the frame directly, so obtain it from a component you
    have already registered with Burp using
    `javax.swing.SwingUtilities.getWindowAncestor(component)` — see `extender-api-examples.md`.

11. #### It uses the Extender API.

    Write your extension against Burp's Extender API using the `burp` module that Burp provides
    to its bundled Jython 2.7 interpreter.

    Import the interfaces you need (for example `IBurpExtender`, `IBurpExtenderCallbacks`) from
    the `burp` module; implement `BurpExtender(IBurpExtender)` as your entry point. Don't bundle
    your own Jython runtime or copies of the Burp API JARs with the extension.

12. #### It includes appropriate testing.

    Include unit tests and integration tests to ensure your extension works correctly.

    Testing helps ensure that your extension works correctly and doesn't break when Burp is
    updated. Write unit tests for individual components using Python's `unittest` module, and
    verify the extension end-to-end inside Burp.
