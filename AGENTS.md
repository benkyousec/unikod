# Python Burp Extension Guide

This file provides guidance to pi (pi.dev) when working with code in this repository.

This is a Burp Suite Extension template project for writing extensions in **Python (Jython)** using Burp's legacy **Extender API** (currently a minimal starter project).

## Important Context

- Burp runs Python extensions on **Jython 2.7**, so all code must be **Python 2.7-compatible** (no f-strings, use `%`/`.format()` formatting).
- Python extensions use the **legacy Extender API** via the `burp` module (`IBurpExtender`, `IBurpExtenderCallbacks`, ...), *not* the Java-only Montoya API.
- The `burp` module is provided automatically by Burp's Jython environment — you don't download or import it from a file path.

## Architecture

- **Main Entry Point**: `BurpExtender.py` - defines `class BurpExtender(IBurpExtender)` implementing `registerExtenderCallbacks(callbacks)`
- **Build System**: None. Extensions are plain `.py` files loaded directly into Burp (no Gradle/Maven/JAR).
- **Runtime**: Jython 2.7 bundled with Burp Suite; standard library + Java interop only.
- **Extension Pattern**: Single-class extension that stores `callbacks` (and `callbacks.getHelpers()`) in `registerExtenderCallbacks`, then registers listeners, menu factories, tabs, etc.

## Key Development Workflow

1. Write your code in `BurpExtender.py`.
2. In Burp: **Extensions > Installed > Add > Select file** and pick the `.py` file.
3. For quick reloading during development: Ctrl/⌘ + click the **Loaded** checkbox.
4. Output/errors appear in the extension's **Output** and **Errors** tabs (`callbacks.printOutput` / `callbacks.printError`).

## Documentation Structure

- See @docs/bapp-store-requirements.md for BApp Store submission requirements (adapted for Python/Jython)
- See @docs/extender-api-examples.md for code patterns and extension structure (Extender API in Python)
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links


