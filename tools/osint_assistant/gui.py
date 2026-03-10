"""
gui.py — Multi-engine OSINT Research Assistant GUI.

Features:
  • Query entry with engine selection checkboxes
  • Max-results spinner and proxy configuration
  • Live progress bar and activity log
  • Sortable results table (Rank, Score, Title, URL, Snippet, Engine)
  • Double-click a row to open the URL in the system browser
  • Cancel button to stop an in-progress search
"""

from __future__ import annotations

import queue
import threading
import time
import webbrowser
from typing import List, Optional

import tkinter as tk
from tkinter import messagebox, ttk

from .dispatcher import Dispatcher, DEFAULT_ENGINES
from .models import SearchResult


class OSINTApp(tk.Tk):
    """Main OSINT Research Assistant window."""

    # Table column definitions
    COL_RANK = "Rank"
    COL_SCORE = "Score"
    COL_ENGINE = "Engine"
    COL_TITLE = "Title"
    COL_URL = "URL"
    COL_SNIPPET = "Snippet"

    COLUMNS = (COL_RANK, COL_SCORE, COL_ENGINE, COL_TITLE, COL_URL, COL_SNIPPET)
    COL_WIDTHS = {
        COL_RANK: 50,
        COL_SCORE: 60,
        COL_ENGINE: 80,
        COL_TITLE: 240,
        COL_URL: 300,
        COL_SNIPPET: 360,
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("FIR — OSINT Research Assistant")
        self.geometry("1400x820")
        self.resizable(True, True)
        self.configure(bg="#1e1e2e")

        self._results: List[SearchResult] = []
        self._sort_col: str = self.COL_RANK
        self._sort_asc: bool = True
        self._search_thread: Optional[threading.Thread] = None
        self._queue: queue.Queue = queue.Queue()
        self._cancelled: bool = False
        self._dispatcher: Optional[Dispatcher] = None
        self._proxy_list: List[str] = []

        # Engine toggle vars (one BooleanVar per engine)
        self._engine_vars = {name: tk.BooleanVar(value=True) for name in DEFAULT_ENGINES}

        self._build_ui()
        self._poll_queue()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#1e1e2e")
        style.configure(
            "TLabel",
            background="#1e1e2e",
            foreground="#cdd6f4",
            font=("Helvetica", 11),
        )
        style.configure(
            "TCheckbutton",
            background="#1e1e2e",
            foreground="#cdd6f4",
            font=("Helvetica", 10),
        )
        style.configure(
            "TButton",
            background="#89b4fa",
            foreground="#1e1e2e",
            font=("Helvetica", 11, "bold"),
            padding=6,
        )
        style.map("TButton", background=[("active", "#74c7ec")])
        style.configure(
            "Treeview",
            background="#181825",
            foreground="#cdd6f4",
            fieldbackground="#181825",
            rowheight=24,
            font=("Helvetica", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#313244",
            foreground="#cba6f7",
            font=("Helvetica", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#45475a")])
        style.configure(
            "green.Horizontal.TProgressbar",
            troughcolor="#313244",
            background="#a6e3a1",
        )

        # ── Top bar: query entry + controls ───────────────────────────
        top = ttk.Frame(self, padding=(12, 10))
        top.pack(fill=tk.X)

        ttk.Label(top, text="Query:").pack(side=tk.LEFT)
        self._query_var = tk.StringVar()
        self._query_entry = ttk.Entry(
            top, textvariable=self._query_var, width=50, font=("Helvetica", 12)
        )
        self._query_entry.pack(side=tk.LEFT, padx=(8, 12))
        self._query_entry.bind("<Return>", lambda _e: self._start_search())

        ttk.Label(top, text="Max results:").pack(side=tk.LEFT)
        self._max_var = tk.StringVar(value="200")
        ttk.Spinbox(
            top, from_=50, to=500, increment=50,
            textvariable=self._max_var, width=5, font=("Helvetica", 11),
        ).pack(side=tk.LEFT, padx=(4, 16))

        ttk.Label(top, text="Variations/engine:").pack(side=tk.LEFT)
        self._var_count_var = tk.StringVar(value="20")
        ttk.Spinbox(
            top, from_=1, to=20, increment=1,
            textvariable=self._var_count_var, width=4, font=("Helvetica", 11),
        ).pack(side=tk.LEFT, padx=(4, 16))

        ttk.Button(top, text="⚙ Proxies", command=self._show_proxy_dialog).pack(
            side=tk.LEFT, padx=(0, 8)
        )

        self._search_btn = ttk.Button(top, text="🔍 Search", command=self._start_search)
        self._search_btn.pack(side=tk.LEFT)

        self._cancel_btn = ttk.Button(
            top, text="✖ Cancel", command=self._cancel_search, state=tk.DISABLED
        )
        self._cancel_btn.pack(side=tk.LEFT, padx=(8, 0))

        # ── Engine selection row ───────────────────────────────────────
        eng_frame = ttk.Frame(self, padding=(12, 0, 12, 6))
        eng_frame.pack(fill=tk.X)
        ttk.Label(eng_frame, text="Engines:", font=("Helvetica", 10, "bold")).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        for name, var in self._engine_vars.items():
            ttk.Checkbutton(
                eng_frame, text=name.upper(), variable=var
            ).pack(side=tk.LEFT, padx=6)

        # ── Progress bar ───────────────────────────────────────────────
        prog_frame = ttk.Frame(self, padding=(12, 0, 12, 4))
        prog_frame.pack(fill=tk.X)
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(
            prog_frame,
            variable=self._progress_var,
            maximum=200,
            mode="determinate",
            style="green.Horizontal.TProgressbar",
        )
        self._progress_bar.pack(fill=tk.X)
        self._status_var = tk.StringVar(value="Ready.")
        ttk.Label(prog_frame, textvariable=self._status_var,
                  font=("Helvetica", 9)).pack(anchor=tk.W)

        # ── Results table ──────────────────────────────────────────────
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 0))

        scroll_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        scroll_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)

        self._tree = ttk.Treeview(
            table_frame,
            columns=self.COLUMNS,
            show="headings",
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            selectmode="browse",
        )
        scroll_y.config(command=self._tree.yview)
        scroll_x.config(command=self._tree.xview)

        for col in self.COLUMNS:
            self._tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            self._tree.column(
                col, width=self.COL_WIDTHS[col], minwidth=40, stretch=True
            )

        self._tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self._tree.bind("<Double-1>", self._on_row_double_click)

        # ── Log panel ──────────────────────────────────────────────────
        log_frame = ttk.Frame(self)
        log_frame.pack(fill=tk.X, padx=12, pady=(6, 8))

        ttk.Label(log_frame, text="Activity log:",
                  font=("Helvetica", 9, "bold")).pack(anchor=tk.W)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL)
        self._log_text = tk.Text(
            log_frame,
            height=6,
            bg="#11111b",
            fg="#a6e3a1",
            font=("Courier", 9),
            state=tk.DISABLED,
            yscrollcommand=log_scroll.set,
            wrap=tk.WORD,
        )
        log_scroll.config(command=self._log_text.yview)
        self._log_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # ------------------------------------------------------------------
    # Proxy dialog
    # ------------------------------------------------------------------
    def _show_proxy_dialog(self) -> None:
        dlg = tk.Toplevel(self)
        dlg.title("Proxy Configuration")
        dlg.geometry("480x300")
        dlg.configure(bg="#1e1e2e")
        dlg.grab_set()

        tk.Label(
            dlg,
            text=(
                "Enter proxies (one per line).\n"
                "Formats: http://host:port  |  socks5://user:pass@host:port"
            ),
            bg="#1e1e2e", fg="#cdd6f4", font=("Helvetica", 10), justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=12, pady=(10, 4))

        txt = tk.Text(dlg, height=8, bg="#181825", fg="#cdd6f4",
                      font=("Courier", 10), insertbackground="#cdd6f4")
        txt.pack(fill=tk.BOTH, expand=True, padx=12)
        txt.insert("1.0", "\n".join(self._proxy_list))

        def _save() -> None:
            raw = txt.get("1.0", tk.END).strip()
            self._proxy_list = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            self._log(f"Proxy list updated: {len(self._proxy_list)} proxies configured.")
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=8)
        ttk.Button(btn_frame, text="Save", command=_save).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # Search lifecycle
    # ------------------------------------------------------------------
    def _start_search(self) -> None:
        query = self._query_var.get().strip()
        if not query:
            messagebox.showwarning("No query", "Please enter a search query.")
            return
        if self._search_thread and self._search_thread.is_alive():
            messagebox.showinfo("Busy", "A search is already running.")
            return

        selected_engines = [
            name for name, var in self._engine_vars.items() if var.get()
        ]
        if not selected_engines:
            messagebox.showwarning("No engines", "Select at least one search engine.")
            return

        try:
            max_results = max(50, min(500, int(self._max_var.get())))
        except ValueError:
            max_results = 200
        self._max_var.set(str(max_results))

        try:
            max_variations = max(1, min(20, int(self._var_count_var.get())))
        except ValueError:
            max_variations = 20
        self._var_count_var.set(str(max_variations))

        self._clear_results()
        self._progress_var.set(0)
        self._progress_bar.config(maximum=max_results)
        self._status_var.set("Starting OSINT search …")
        self._search_btn.config(state=tk.DISABLED)
        self._cancel_btn.config(state=tk.NORMAL)
        self._cancelled = False

        self._search_thread = threading.Thread(
            target=self._run_search,
            args=(query, max_results, max_variations, selected_engines,
                  list(self._proxy_list)),
            daemon=True,
        )
        self._search_thread.start()

    def _cancel_search(self) -> None:
        self._cancelled = True
        if self._dispatcher:
            self._dispatcher.cancel()
        self._log("⚠ Cancellation requested …")

    def _run_search(
        self,
        query: str,
        max_results: int,
        max_variations: int,
        engines: List[str],
        proxies: List[str],
    ) -> None:
        def _log(msg: str) -> None:
            self._queue.put(("log", msg))

        def _progress(collected: int, total: int) -> None:
            self._queue.put(("progress", collected, total))

        self._dispatcher = Dispatcher(
            engines=engines,
            max_workers=len(engines),
            max_variations=max_variations,
            results_per_variation=10,
            proxies=proxies or None,
            log_cb=_log,
            progress_cb=_progress,
        )

        try:
            results = self._dispatcher.search(query, target_results=max_results)
            self._queue.put(("done", results))
        except InterruptedError:
            self._queue.put(("cancelled",))
        except Exception as exc:
            self._queue.put(("error", str(exc)))
        finally:
            self._dispatcher = None

    # ------------------------------------------------------------------
    # Queue polling (main thread)
    # ------------------------------------------------------------------
    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, collected, total = msg
                    self._progress_var.set(min(collected, total))
                    self._status_var.set(
                        f"Collected {collected} / {total} results …"
                    )
                elif kind == "log":
                    self._log(msg[1])
                elif kind == "done":
                    self._on_search_done(msg[1])
                elif kind == "cancelled":
                    self._status_var.set("Search cancelled.")
                    self._log("Search cancelled.")
                    self._reset_buttons()
                elif kind == "error":
                    self._status_var.set(f"Error: {msg[1]}")
                    self._log(f"⛔ Error: {msg[1]}")
                    self._reset_buttons()
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _on_search_done(self, results: List[SearchResult]) -> None:
        self._results = results
        self._populate_table(results)
        self._status_var.set(
            f"Done — {len(results)} unique results (sorted by relevancy)."
        )
        self._log(f"✅ Search complete. {len(results)} unique results returned.")
        self._reset_buttons()

    def _reset_buttons(self) -> None:
        self._search_btn.config(state=tk.NORMAL)
        self._cancel_btn.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Table helpers
    # ------------------------------------------------------------------
    def _clear_results(self) -> None:
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._results = []

    def _populate_table(self, results: List[SearchResult]) -> None:
        self._clear_results()
        for r in results:
            self._tree.insert(
                "", tk.END,
                values=(
                    r.rank,
                    f"{r.score:.4f}",
                    r.engine,
                    r.title,
                    r.url,
                    r.snippet,
                ),
            )

    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        numeric_cols = {self.COL_RANK, self.COL_SCORE}
        reverse = not self._sort_asc

        def _key(r: SearchResult):
            if col == self.COL_RANK:
                return r.rank
            if col == self.COL_SCORE:
                return r.score
            if col == self.COL_ENGINE:
                return r.engine.lower()
            if col == self.COL_TITLE:
                return r.title.lower()
            if col == self.COL_URL:
                return r.url.lower()
            if col == self.COL_SNIPPET:
                return r.snippet.lower()
            return 0

        sorted_results = sorted(self._results, key=_key, reverse=reverse)
        self._populate_table(sorted_results)
        arrow = " ▲" if self._sort_asc else " ▼"
        for c in self.COLUMNS:
            self._tree.heading(c, text=c + (arrow if c == col else ""))

    def _on_row_double_click(self, event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        values = self._tree.item(sel[0], "values")
        # COL_URL is index 4
        if values and len(values) >= 5:
            url = values[4]
            if url.startswith("http"):
                webbrowser.open(url)

    # ------------------------------------------------------------------
    # Log helper
    # ------------------------------------------------------------------
    def _log(self, message: str) -> None:
        self._log_text.config(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        self._log_text.insert(tk.END, f"[{ts}] {message}\n")
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)


def main() -> None:
    app = OSINTApp()
    app.mainloop()


if __name__ == "__main__":
    main()
