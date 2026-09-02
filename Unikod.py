# -*- coding: utf-8 -*-
"""
Unikod — generate Unicode-equivalent character wordlists for fuzzing.

Load in Burp: Extensions > Installed > Add > Select file > BurpExtender.py
(Ctrl/Cmd-click the "Loaded" checkbox to reload during development.)

How it works
------------
* Type a single character (or right-click a highlighted character inside any Burp HTTP
  message editor and choose "Send ... to Unikod") and press Generate.
* Unikod derives search term(s) from the character's Unicode name — e.g. LESS-THAN SIGN
  becomes LESS-THAN — and lists every character whose name contains them, across the whole
  Unicode range (see the “Name-search core” section below for the matching rules
  (incl. cross-script letter relatives such as A -> Cyrillic А / fullwidth Ａ / a).
* The first generation builds a name index of every named code point (~1.4 s in a background
  thread); later generations reuse it (~0.15 s each).
* Results can be sorted/filtered in the table, copied (chars or \\uXXXX escapes) or saved as a
  UTF-8 wordlist (one character per line) for Intruder-style fuzzing.

Runtime: Jython 2.7 (legacy Extender API). Python 2.7 syntax only — no f-strings.
"""

import codecs
import os
import re
import threading

from burp import (IBurpExtender, IContextMenuFactory, IExtensionStateListener,
                  ITab, IContextMenuInvocation)

from javax.swing import (JButton, JCheckBox, JFileChooser, JLabel, JMenuItem,
                         JPanel, JPopupMenu, JScrollPane, JTable, JTextField,
                         RowFilter, SortOrder, RowSorter, SwingUtilities)
from javax.swing.table import AbstractTableModel, TableRowSorter
from javax.swing.event import DocumentListener, ListSelectionListener
from java.awt import (BorderLayout, FlowLayout, Font, GridBagConstraints,
                       GridBagLayout, Insets, Toolkit)
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter
from java.lang import Integer as JInteger, String as JString
from java.io import File



# =====================================================================
# Name-search core (merged from unikod_core.py so the extension ships as a
# single .py file). Pure logic: no `burp` imports, plain Python 2/3 code.
# =====================================================================
MAX_CP = 0x110000  # number of code points in the whole Unicode range

try:
    _range = xrange  # Python 2
    _unichr = unichr
except NameError:
    _range = range   # Python 3
    _unichr = None

# Suffixes stripped from the tail of a name to widen the search, as in the original script.
# e.g. "LESS-THAN SIGN" -> "LESS-THAN", "MULTIPLICATION SIGN" -> "MULTIPLICATION".
STRIP_SUFFIXES = (" SIGN", " SYMBOL", " MARK", " DIGIT")

# java.lang.Character.getType() values -> general category letters (GC).
_JAVA_TYPE_TO_GC = {
    0: "Cn", 1: "Lu", 2: "Ll", 3: "Lt", 4: "Lm", 5: "Lo",
    6: "Mn", 7: "Mc", 8: "Me", 9: "Nd", 10: "Nl", 11: "No",
    12: "Zs", 13: "Zl", 14: "Zp", 15: "Cc", 16: "Cf", 18: "Co",
    19: "Cs", 20: "Pd", 21: "Ps", 22: "Pe", 23: "Pc", 24: "Po",
    25: "Sm", 26: "Sc", 27: "Sk", 28: "So", 29: "Pi", 30: "Pf",
}


def cp_to_text(cp):
    """Python string (single code point) for a code point; None when impossible."""
    try:
        if _unichr is not None:
            return _unichr(cp)
        return chr(cp)
    except (ValueError, OverflowError):
        try:
            from java.lang import Character, String as JString
            return JString(Character.toChars(cp))  # old Jython astral fallback
        except Exception:
            return None


class NameSource(object):
    """Resolves names and categories for code points via the best available source."""

    def __init__(self):
        self._mode = None
        self._character = None
        self._unicodedata = None
        self._label = "no usable name source"
        self._detect()

    def _detect(self):
        # Preferred: java.lang.Character.getName(int) - JDK 9+. Handles every code point,
        # is fast, and reflects the running JDK's (current) Unicode data.
        try:
            from java.lang import Character, System
            if Character.getName(0x41) is not None:
                self._mode = "java"
                self._character = Character
                ver = System.getProperty("java.version") or "?"
                self._label = "java.lang.Character (JDK %s)" % ver
                return
        except Exception:
            pass
        try:
            import unicodedata
            self._mode = "unicodedata"
            self._unicodedata = unicodedata
            ver = getattr(unicodedata, "unidata_version", None) or "?"
            self._label = "unicodedata (Unicode %s)" % ver
        except Exception:
            self._mode = None

    # -- public ---------------------------------------------------------

    def is_usable(self):
        return self._mode is not None

    def label(self):
        return self._label

    def name(self, cp):
        """Uppercased official Unicode name for cp, or None if unnamed/unassigned."""
        try:
            if self._mode == "java":
                nm = self._character.getName(cp)
                if nm is None:
                    return None
                return nm.upper()
            if self._mode == "unicodedata":
                ch = cp_to_text(cp)
                if ch is None:
                    return None
                return self._unicodedata.name(ch).upper()
        except (ValueError, TypeError):
            return None
        except Exception:
            return None
        return None

    def gc(self, cp):
        """General-category letters (Lu, Nd, Sm, ...) or None when unavailable."""
        try:
            if self._mode == "java":
                return _JAVA_TYPE_TO_GC.get(self._character.getType(cp))
            if self._mode == "unicodedata":
                ch = cp_to_text(cp)
                if ch is None:
                    return None
                return self._unicodedata.category(ch)
        except Exception:
            return None
        return None


def build_entries(source, max_cp=MAX_CP, progress_cb=None, is_cancelled=None):
    """
    Scan [0, max_cp) and collect every code point that has a name.

    Returns a list of (cp, upper_name) sorted by code point. Call off the EDT.
    progress_cb(percent, scanned) is invoked periodically; is_cancelled() may abort.
    """
    entries = []
    chunk = 0x4000
    scanned = 0
    append = entries.append
    for start in _range(0, max_cp, chunk):
        if is_cancelled is not None and is_cancelled():
            return None
        end = min(start + chunk, max_cp)
        for cp in _range(start, end):
            nm = source.name(cp)
            if nm is not None:
                append((cp, nm))
        scanned = end
        if progress_cb is not None:
            progress_cb(int(100.0 * scanned / max_cp), scanned)
    return entries


def stripped_name(name):
    """Name minus one trailing classifier suffix (SIGN/SYMBOL/MARK/DIGIT)."""
    for suffix in STRIP_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def letter_core_term(name, gc):
    """
    For letters whose name ends in "LETTER X" return "LETTER X".
    This makes searching "A" also surface names ending "LETTER A" from other
    scripts/cases (e.g. CYRILLIC CAPITAL LETTER A, LATIN SMALL LETTER A).
    Returns None when not applicable.
    """
    if not (gc and gc.startswith("L")):
        return None
    parts = name.rsplit(" ", 1)
    if len(parts) == 2 and parts[0].endswith("LETTER") and parts[1]:
        return "LETTER " + parts[1]
    return None


def derive_search_terms(name, gc, loose=False):
    """
    Turn a character's (upper) name + category into an ordered, de-duplicated list of
    (term, rule) search terms, most specific first.

    * stripped name  - original script behaviour (strip SIGN/SYMBOL/MARK/DIGIT suffix)
    * letter core    - "LETTER X" term for letters, to catch cross-script/case relatives
    * loose tokens   - opt-in: each significant token of the stripped name as a term
    """
    out = []
    seen = set()

    def add(term, rule):
        if term and term not in seen:
            seen.add(term)
            out.append((term, rule))

    t1 = stripped_name(name)
    add(t1, "name")

    t2 = letter_core_term(name, gc)
    if t2:
        add(t2, "cross-script")

    if loose:
        for token in t1.split(" "):
            if len(token) >= 3:  # ignore tiny tokens ("A", "I", ...) to avoid noise
                add(token, "loose")
    return out


def match_entries(entries, term_rules):
    """
    Scan the index once, keep every (cp, name) whose name contains any search term.
    Returns [(cp, upper_name, term_index)] in index order; term_index is the FIRST
    (most specific) term that matched.
    """
    out = []
    append = out.append
    n_terms = len(term_rules)
    for cp, name in entries:
        for i in _range(n_terms):
            if term_rules[i][0] in name:
                append((cp, name, i))
                break
    return out


def cp_to_hex(cp):
    return "U+%04X" % cp


def cp_to_escape(cp):
    """Python-style escape literal for a code point."""
    if cp <= 0xFFFF:
        return "\\u%04X" % cp
    return "\\U%08X" % cp


def wordlist_filename_from_term(term):
    """Deterministic default file name, e.g. LESS-THAN -> LESS_THAN_wordlist.txt."""
    import re
    safe = re.sub("[^A-Z0-9]+", "_", term).strip("_")
    if not safe:
        safe = "characters"
    return safe + "_wordlist.txt"


def single_cp_from_editor_text(text):
    """
    Interpret text pulled out of a Burp message editor selection (chars that are the raw
    request/response bytes, 1 char == 1 byte via helpers.bytesToString) as ONE code point.

    * 1 char         -> that byte as a code point (ASCII / Latin-1 single byte, BMP)
    * 2..4 chars     -> decoded as UTF-8, accepted only if exactly one code point
    * anything else  -> None
    """
    if text is None or len(text) == 0:
        return None
    units = [ord(c) for c in text]
    if len(units) == 1:
        return units[0]
    return _utf8_single_cp(units)


def _utf8_single_cp(bs):
    """Decode bs (list of byte values) as UTF-8; return the single code point or None."""
    if not all(0 <= b <= 0xFF for b in bs):
        return None
    n = len(bs)
    if n < 2 or n > 4:
        return None
    # minimal well-formed UTF-8 decoding of exactly one code point
    b0 = bs[0]
    if b0 < 0x80:  # 1-byte: but we require >= 2 units here -> trailing garbage
        return None
    try:
        if b0 < 0xC2:
            return None
        if b0 < 0xE0:
            if n != 2:
                return None
            cp = ((b0 & 0x1F) << 6) | (bs[1] & 0x3F)
            if cp < 0x80:
                return None
        elif b0 < 0xF0:
            if n != 3:
                return None
            cp = ((b0 & 0x0F) << 12) | ((bs[1] & 0x3F) << 6) | (bs[2] & 0x3F)
            if cp < 0x800:
                return None
        elif b0 < 0xF5:
            if n != 4:
                return None
            cp = ((b0 & 0x07) << 18) | ((bs[1] & 0x3F) << 12) | \
                 ((bs[2] & 0x3F) << 6) | (bs[3] & 0x3F)
            if cp < 0x10000 or cp > 0x10FFFF:
                return None
        else:
            return None
        if not all(0x80 <= b <= 0xBF for b in bs[1:]):
            return None
        return cp
    except Exception:
        return None

_CTX_REQUEST = (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
_CTX_RESPONSE = (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
                 IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE)

_COLUMNS = ("Char", "Code point", "Unicode name", "Matched by", "Rule", "Cat.")


# --------------------------------------------------------------------------- helpers

def _js(s):
    """Python str/unicode -> java.lang.String (safe for Swing/table use)."""
    return JString(s) if s is not None else JString("")


def _py_join_lines(texts):
    return "\n".join(texts)


def _write_wordlist(path, rows):
    """Write python rows [(cp, name, term, rule, gc, charText)...] as UTF-8, one char per line."""
    with codecs.open(path, "w", "utf-8") as fh:
        for (_cp, _name, _term, _rule, _gc, char_text) in rows:
            if char_text:
                fh.write(char_text + "\n")
    return path


def _set_clipboard(text):
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)


# --------------------------------------------------------------------------- table model

class UnikodTableModel(AbstractTableModel):
    """Read-only model whose rows are java.String / java.Integer objects (sortable)."""

    def __init__(self):
        AbstractTableModel.__init__(self)
        self._rows = []  # list of [charText, cpInteger, name, matched, rule, gc]

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(_COLUMNS)

    def getColumnName(self, column):
        return _COLUMNS[column]

    def isCellEditable(self, row, column):
        return False

    def getValueAt(self, row, column):
        r = self._rows[row]
        if column == 1:
            return r[1]
        return r[column]

    # -- python-side API ---------------------------------------------------
    def set_rows(self, rows):
        self._rows = rows

    def notify_changed(self):
        self.fireTableDataChanged()


class _ListSelListener(ListSelectionListener):
    def __init__(self, owner):
        self._owner = owner

    def valueChanged(self, event):
        self._owner._on_row_selection_changed()


class _FilterDocListener(DocumentListener):
    def __init__(self, owner):
        self._owner = owner

    def insertUpdate(self, e):
        self._owner._on_filter_changed()

    def removeUpdate(self, e):
        self._owner._on_filter_changed()

    def changedUpdate(self, e):
        self._owner._on_filter_changed()


class _PopupMouseListener(MouseAdapter):
    def __init__(self, owner):
        self._owner = owner

    def mousePressed(self, e):
        self._maybe_popup(e)

    def mouseReleased(self, e):
        self._maybe_popup(e)

    def _maybe_popup(self, e):
        if e.isPopupTrigger():
            self._owner._show_table_popup(e)


# --------------------------------------------------------------------------- extension

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener):
    """Main entry point (must be named BurpExtender)."""

    # -- IBurpExtender ----------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Initialise all state FIRST: Burp's addSuiteTab() immediately calls back into
        # getUiComponent(), so attributes must already exist by then.
        self._source = NameSource()
        self._index = None
        self._index_building = False
        self._index_lock = threading.RLock()
        self._cancelled = threading.Event()
        self._threads = []
        self._busy = False
        self._unloaded = False
        self._ui = None
        self._model = None
        self._sorter = None
        self._py_rows = []       # parallel to model rows: (cp, name, matched, rule, gc, charText)
        self._last_terms = []
        self._char_text = None
        self._status_text = ""
        self._terms_text = ""

        # UI state
        self._char_field = None
        self._generate_btn = None
        self._copy_btn = None
        self._esc_btn = None
        self._save_btn = None
        self._clear_btn = None
        self._cross_cb = None
        self._loose_cb = None
        self._status_label = None
        self._terms_label = None
        self._count_label = None
        self._filter_field = None
        self._preview_label = None
        self._preview_detail = None
        self._last_saved_dir = None
        self._table = None

        self._restore_settings()

        callbacks.setExtensionName("Unikod")
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        callbacks.printOutput("Unikod loaded. Name source: %s" % self._source.label())
        if not self._source.is_usable():
            callbacks.printError("Unikod: no usable Unicode name source found!")

    # -- ITab ------------------------------------------------------------
    def getTabCaption(self):
        return "Unikod"

    def getUiComponent(self):
        if self._ui is None:
            self._ui = self._build_ui()
        return self._ui

    # -- IContextMenuFactory ----------------------------------------------
    def createMenuItems(self, invocation):
        try:
            ctx = invocation.getInvocationContext()
            if ctx not in _CTX_REQUEST and ctx not in _CTX_RESPONSE:
                return []
            bounds = invocation.getSelectionBounds()
            if bounds is None:
                return []
            messages = invocation.getSelectedMessages()
            if not messages or messages[0] is None:
                return []
            message = messages[0]
            data = message.getRequest() if ctx in _CTX_REQUEST else message.getResponse()
            if data is None:
                return []

            text = self._helpers.bytesToString(data)
            start = int(bounds[0])
            end = int(bounds[1])
            if start < 0 or end <= start or end > len(text):
                return []

            cp = single_cp_from_editor_text(text[start:end])
            if cp is None:
                return []

            char = cp_to_text(cp) or ("U+%04X" % cp)
            label = "Send %s (U+%04X) to Unikod" % (char, cp)
            item = JMenuItem(label)
            item.addActionListener(lambda _e, c=cp: self._load_and_generate(c))
            return [item]
        except Exception as exc:
            self._callbacks.printError("Unikod menu error: %s" % exc)
            return []

    # -- IExtensionStateListener -------------------------------------------
    def extensionUnloaded(self):
        self._unloaded = True
        self._cancelled.set()
        for t in self._threads:
            try:
                t.join(3)
            except Exception:
                pass
        try:
            self._callbacks.removeSuiteTab(self)
        except Exception:
            pass

    # ------------------------------------------------------------------ settings
    def _restore_settings(self):
        try:
            raw = self._callbacks.loadExtensionSetting("last_cp")
            self._last_cp = int(raw) if raw else None
        except Exception:
            self._last_cp = None
        try:
            self._last_saved_dir = self._callbacks.loadExtensionSetting("out_dir") or None
        except Exception:
            self._last_saved_dir = None

    def _remember(self):
        try:
            if self._last_cp is not None:
                self._callbacks.saveExtensionSetting("last_cp", str(self._last_cp))
        except Exception:
            pass

    # ------------------------------------------------------------------ UI build
    def _build_ui(self):
        root = JPanel(BorderLayout(8, 8))

        # --- top: input + options + status --------------------------------
        top = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.WEST
        gbc.insets = Insets(2, 4, 2, 4)

        def put(comp, x, y, w=1, weightx=0.0):
            gbc.gridx = x
            gbc.gridy = y
            gbc.gridwidth = w
            gbc.weightx = weightx
            top.add(comp, gbc)

        self._char_field = JTextField(8)
        self._generate_btn = JButton("Generate equivalents")
        self._copy_btn = JButton("Copy chars")
        self._esc_btn = JButton("Copy \\u escapes")
        self._save_btn = JButton("Save to wordlist")
        self._clear_btn = JButton("Clear")

        self._cross_cb = JCheckBox("Letters: also match names ending \u201cLETTER X\u201d (A \u2192 \u0410 Cyrillic, \uff21 fullwidth, a \u2026)", True)
        self._loose_cb = JCheckBox("Loose: also match individual name tokens (may be noisy)", False)

        put(JLabel("Character:"), 0, 0)
        put(self._char_field, 1, 0)
        put(self._generate_btn, 2, 0)
        put(JLabel("  e.g.  < 1 A ' . \u00d7"), 3, 0, w=2, weightx=1.0)

        put(self._cross_cb, 0, 1, w=5, weightx=1.0)
        put(self._loose_cb, 0, 2, w=5, weightx=1.0)

        self._terms_label = JLabel(" ")
        put(self._terms_label, 0, 3, w=5, weightx=1.0)
        self._status_label = JLabel(" ")
        put(self._status_label, 0, 4, w=5, weightx=1.0)

        # --- centre: filter + table ---------------------------------------
        centre = JPanel(BorderLayout(4, 4))
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        filter_panel.add(JLabel("Filter rows:"))
        self._filter_field = JTextField(30)
        self._filter_field.getDocument().addDocumentListener(_FilterDocListener(self))
        filter_panel.add(self._filter_field)
        self._count_label = JLabel(" ")
        filter_panel.add(self._count_label)
        centre.add(filter_panel, BorderLayout.NORTH)

        self._model = UnikodTableModel()
        table = JTable(self._model)
        table.setFillsViewportHeight(True)
        self._table = table

        self._sorter = TableRowSorter(self._model)
        table.setRowSorter(self._sorter)
        self._sorter.setSortKeys([RowSorter.SortKey(1, SortOrder.ASCENDING)])
        table.getSelectionModel().addListSelectionListener(_ListSelListener(self))
        table.addMouseListener(_PopupMouseListener(self))

        widths = [80, 110, 460, 140, 110, 60]
        for i, w in enumerate(widths):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)

        centre.add(JScrollPane(table), BorderLayout.CENTER)

        # --- bottom: preview + actions ------------------------------------
        bottom = JPanel(BorderLayout(8, 8))
        preview = JPanel(FlowLayout(FlowLayout.LEFT, 12, 4))
        self._preview_label = JLabel("")
        self._preview_label.setFont(Font("SansSerif", Font.PLAIN, 18))
        preview.add(self._preview_label)
        self._preview_detail = JLabel(" ")
        preview.add(self._preview_detail)
        bottom.add(preview, BorderLayout.CENTER)

        actions = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 8))
        actions.add(self._copy_btn)
        actions.add(self._esc_btn)
        actions.add(self._save_btn)
        actions.add(self._clear_btn)
        bottom.add(actions, BorderLayout.EAST)

        root.add(top, BorderLayout.NORTH)
        root.add(centre, BorderLayout.CENTER)
        root.add(bottom, BorderLayout.SOUTH)

        self._char_field.addActionListener(self._on_generate_clicked)
        self._generate_btn.addActionListener(self._on_generate_clicked)
        self._copy_btn.addActionListener(self._on_copy_chars)
        self._esc_btn.addActionListener(self._on_copy_escapes)
        self._save_btn.addActionListener(self._on_save)
        self._clear_btn.addActionListener(self._on_clear)

        # restore last character / sensible default
        if self._last_cp is not None:
            self._char_field.setText(cp_to_text(self._last_cp))
        else:
            self._char_field.setText("<")

        self._update_index_status()
        return root

    # ------------------------------------------------------------------ UI helpers
    def _update_index_status(self):
        if self._index is not None:
            msg = "Index ready: %d named code points (%s)" % (len(self._index), self._source.label())
        elif self._source.is_usable():
            msg = "First generation will scan the Unicode range once (~1\u20132 s). Source: %s" % self._source.label()
        else:
            msg = "No usable Unicode name source available."
        self._status_label.setText(msg)

    def _set_busy_ui(self, busy):
        self._busy = busy
        for b in (self._generate_btn, self._copy_btn, self._esc_btn,
                  self._save_btn, self._clear_btn):
            b.setEnabled(not busy)

    def _status(self, text):
        self._status_text = text
        self._status_label.setText(text)

    def _terms_line(self, rules):
        self._terms_text = "Terms: " + ", ".join("%s (%s)" % (t, r) for t, r in rules)
        self._terms_label.setText(self._terms_text)

    def _update_counts(self):
        if self._model is None:
            return
        total = self._model.getRowCount()
        shown = self._sorter.getViewRowCount() if self._sorter is not None else total
        if total:
            self._count_label.setText("%d row(s), %d shown" % (total, shown))
        else:
            self._count_label.setText(" ")

    # ------------------------------------------------------------------ events
    def _on_generate_clicked(self, _event=None):
        if self._busy or self._unloaded:
            return
        cp = self._field_codepoint()
        if cp is None:
            return
        self._last_cp = cp
        self._remember()
        self._start_search(cp)

    def _load_and_generate(self, cp):
        """Called from the HTTP-message context menu (already a single code point)."""
        if self._unloaded:
            return
        self.getUiComponent()  # make sure the panel exists before touching fields
        text = cp_to_text(cp)
        if text is not None:
            self._char_field.setText(text)
        self._last_cp = cp
        self._remember()
        if not self._busy:
            self._start_search(cp)
        else:
            self._status("Busy \u2014 generation already running for another character.")

    def _field_codepoint(self):
        text = self._char_field.getText()
        if text is None or len(text) == 0:
            self._status("Enter a single character first.")
            return None
        if len(text) == 1:
            return ord(text[0])
        # possible astral pair on JVMs where Python strings count UTF-16 units
        if len(text) == 2:
            hi = ord(text[0])
            lo = ord(text[1])
            if 0xD800 <= hi <= 0xDBFF and 0xDC00 <= lo <= 0xDFFF:
                return 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
        self._status("Please enter exactly one character.")
        return None

    # ------------------------------------------------------------------ search flow
    def _start_search(self, cp):
        name = self._source.name(cp)
        if name is None:
            self._status("No Unicode name found for U+%04X \u2014 cannot search for equivalents."
                         % cp)
            return
        gc = self._source.gc(cp)
        loose = self._loose_cb.isSelected()
        rules = derive_search_terms(name, gc, loose=loose)

        self._set_busy_ui(True)
        self._status("Generating equivalents for %s (U+%04X) \u2026" % (cp_to_text(cp), cp))
        self._terms_line(rules)

        t = threading.Thread(target=self._worker_flow, args=(cp, name, rules))
        t.setDaemon(True)
        self._threads.append(t)
        t.start()

    def _worker_flow(self, cp, name, rules):
        try:
            entries = self._ensure_index()
            if entries is None or self._cancelled.is_set():
                return
            matched = match_entries(entries, rules)
            self._edt(self._show_results, cp, name, rules, matched)
        except Exception as exc:
            self._callbacks.printError("Unikod generation error: %s" % exc)
            self._edt(self._status, "Generation failed: %s" % exc)
        finally:
            self._edt(self._set_busy_ui, False)

    def _ensure_index(self):
        with self._index_lock:
            if self._index is not None:
                return self._index
        # no cached index yet: build it (progress is reported via callbacks)
        with self._index_lock:
            if self._index is not None:
                return self._index
            if self._index_building:
                return None  # another thread is building (shouldn't happen)
            self._index_building = True
        try:
            def progress(pct, scanned):
                if not self._cancelled.is_set():
                    self._edt(self._status,
                              "Scanning Unicode names\u2026 %d%% (%d code points)" % (pct, scanned))
            entries = build_entries(self._source, progress_cb=progress,
                                         is_cancelled=self._cancelled.is_set)
        finally:
            with self._index_lock:
                self._index_building = False
        if entries is None:
            return None
        with self._index_lock:
            self._index = entries
        self._edt(self._status,
                  "Index ready: %d named code points (%s)" % (len(entries), self._source.label()))
        return entries

    def _show_results(self, cp, name, rules, matched):
        self._py_rows = []
        rows = []
        for (mcp, mname, term_idx) in matched:
            term = rules[term_idx][0]
            rule = rules[term_idx][1]
            char_text = cp_to_text(mcp) or ""
            gc = self._source.gc(mcp) or ""
            self._py_rows.append((mcp, mname, term, rule, gc, char_text))
            rows.append([_js(char_text), JInteger(mcp), _js(mname),
                         _js(term), _js(rule), _js(gc)])
        self._model.set_rows(rows)
        self._model.notify_changed()
        self._table.clearSelection()
        self._preview_reset()
        self._update_counts()
        self._status("Found %d character(s) for %s \u2014 %s" %
                     (len(matched), cp_to_text(cp), name))

    def _preview_reset(self):
        """Idle preview state: no big glyph, no details text."""
        if self._preview_label is not None:
            self._preview_label.setFont(Font("SansSerif", Font.PLAIN, 18))
            self._preview_label.setText("")
        if self._preview_detail is not None:
            self._preview_detail.setText(" ")

    def _preview_show(self, cp, name, gc, term, char_text):
        """Show a selected row's glyph (large) plus a compact detail line."""
        if self._preview_label is None:
            return
        if char_text:
            self._preview_label.setFont(Font("SansSerif", Font.PLAIN, 56))
            self._preview_label.setText(char_text)
        else:
            self._preview_label.setFont(Font("SansSerif", Font.PLAIN, 18))
            self._preview_label.setText("")
        if self._preview_detail is not None:
            self._preview_detail.setText(
                "%s  %s  [%s, matched \u201c%s\u201d]" %
                (cp_to_hex(cp), name, gc or "?", term))

    def _on_row_selection_changed(self):
        if self._table is None:
            return
        view = self._table.getSelectedRow()
        if view < 0 or view >= self._table.getRowCount():
            return
        model_row = self._table.convertRowIndexToModel(view)
        if model_row < 0 or model_row >= len(self._py_rows):
            return
        cp, mname, term, _rule, gc, char_text = self._py_rows[model_row]
        self._preview_show(cp, mname, gc, term, char_text)

    def _on_filter_changed(self):
        if self._sorter is None or self._unloaded:
            return
        pattern = self._filter_field.getText()
        if pattern:
            try:
                self._sorter.setRowFilter(RowFilter.regexFilter("(?i)" + re.escape(pattern)))
            except Exception:
                self._sorter.setRowFilter(None)
        else:
            self._sorter.setRowFilter(None)
        self._update_counts()

    # ------------------------------------------------------------------ visible rows
    def _visible_rows(self):
        """Python-side rows currently shown by the table (filtered), in view order."""
        out = []
        view_count = self._table.getRowCount()
        for view in xrange(view_count):
            model_row = self._table.convertRowIndexToModel(view)
            if 0 <= model_row < len(self._py_rows):
                out.append(self._py_rows[model_row])
        return out

    def _visible_texts(self):
        return [row[5] for row in self._visible_rows()]

    # ------------------------------------------------------------------ actions
    def _on_copy_chars(self, _event=None):
        texts = self._visible_texts()
        if not texts:
            self._status("Nothing to copy \u2014 generate a wordlist first.")
            return
        _set_clipboard(_py_join_lines(texts))
        self._status("Copied %d character(s) to the clipboard." % len(texts))

    def _on_copy_escapes(self, _event=None):
        rows = self._visible_rows()
        if not rows:
            self._status("Nothing to copy \u2014 generate a wordlist first.")
            return
        lines = [cp_to_escape(row[0]) for row in rows]
        _set_clipboard(_py_join_lines(lines))
        self._status("Copied %d \\u escape(s) to the clipboard." % len(lines))

    def _on_save(self, _event=None):
        rows = self._visible_rows()
        if not rows:
            self._status("Nothing to save \u2014 generate a wordlist first.")
            return
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Unikod wordlist (one character per line, UTF-8)")
        if self._last_saved_dir:
            try:
                chooser.setCurrentDirectory(File(self._last_saved_dir))
            except Exception:
                pass
        default_name = "characters_wordlist.txt"
        if self._last_terms:
            default_name = wordlist_filename_from_term(self._last_terms[0][0])
        chooser.setSelectedFile(File(default_name))
        parent = SwingUtilities.getWindowAncestor(self.getUiComponent())
        if chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getPath()
        try:
            _write_wordlist(path, rows)
            self._last_saved_dir = os.path.dirname(path)
            self._callbacks.saveExtensionSetting("out_dir", self._last_saved_dir or "")
            self._status("Saved %d character(s) to %s" % (len(rows), path))
        except Exception as exc:
            self._callbacks.printError("Unikod save error: %s" % exc)
            self._status("Save failed: %s" % exc)

    def _on_clear(self, _event=None):
        if self._busy:
            return
        self._model.set_rows([])
        self._model.notify_changed()
        self._py_rows = []
        self._preview_reset()
        self._update_counts()
        self._status("Cleared.")

    # ------------------------------------------------------------------ table popup
    def _show_table_popup(self, event):
        if self._busy or self._table is None:
            return
        row = self._table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        self._table.setRowSelectionInterval(row, row)
        model_row = self._table.convertRowIndexToModel(row)
        if model_row < 0 or model_row >= len(self._py_rows):
            return
        cp, name, term, _rule, _gc, char_text = self._py_rows[model_row]

        popup = JPopupMenu()
        item_copy = JMenuItem("Copy character")
        item_copy.addActionListener(lambda _e: self._popup_copy_char(char_text))
        popup.add(item_copy)

        item_line = JMenuItem("Copy \u201c%s U+%04X %s\u201d" % (char_text or "?", cp, name))
        item_line.addActionListener(lambda _e: self._popup_copy_line(cp, name))
        popup.add(item_line)

        item_use = JMenuItem("Use U+%04X as new search character" % cp)
        item_use.addActionListener(lambda _e: self._load_and_generate(cp))
        popup.add(item_use)

        popup.show(self._table, event.getX(), event.getY())

    def _popup_copy_char(self, char_text):
        if char_text:
            _set_clipboard(char_text)
            self._status("Copied character to the clipboard.")

    def _popup_copy_line(self, cp, name):
        _set_clipboard("%s  U+%04X  %s" % (cp_to_text(cp) or "", cp, name))
        self._status("Copied row to the clipboard.")

    # ------------------------------------------------------------------ misc
    def _edt(self, fn, *args):
        if self._unloaded:
            return

        def _run():
            try:
                if not self._unloaded:
                    fn(*args)
            except Exception as exc:
                self._callbacks.printError("Unikod UI error in %s: %s" % (getattr(fn, "__name__", "?"), exc))

        try:
            SwingUtilities.invokeLater(_run)
        except Exception:
            pass
