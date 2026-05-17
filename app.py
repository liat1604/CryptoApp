import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk

from ciphers import (
    vigenere_cipher,
    vernam_cipher,
    columnar_transposition,
    orbit_cipher_with_integrity,
)


# TOOLTIP
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, e=None):
        if self.tip:
            return
        x = self.widget.winfo_rootx() + 15
        y = self.widget.winfo_rooty() + 25
        self.tip = tw = tk.Toplevel(self.widget)
        tw.overrideredirect(True)
        tw.geometry(f"+{x}+{y}")
        tk.Label(
            tw, text=self.text, bg="#333", fg="white",
            relief="solid", borderwidth=1, padx=6, pady=4,
            font=("Segoe UI", 9),
        ).pack()

    def hide(self, e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


 
# MAIN APPLICATION
class FileEncryptorApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.option_add("*TCombobox*Listbox.selectBackground", "#2563EB")
        self.root.option_add("*TCombobox*Listbox.selectForeground", "white")
        self.root.title("CryptoApp")
        self.root.geometry("1250x750")
        self.root.minsize(1150, 700)
        self.dark = False
        self.key_placeholder_active = True
        self.input_path = ""
        self.output_path = ""
        self.setup_light()
        self.setup_styles()
        self.build()
    # THEMES
    def setup_light(self):
        self.BG = "#F3F5F9"
        self.CARD = "#FAFBFC"
        self.TEXT = "#1F2937"
        self.MUTED = "#6B7280"
        # Softer, more professional blues
        self.ACCENT = "#1E40AF"
        self.ACCENT_HOVER = "#1D4ED8"
        # Softer preview blue
        self.PREVIEW_BG = "#F1F5FB"
        self.SUCCESS = "#16A34A"
        self.WARNING = "#D97706"
        self.ERROR = "#DC2626"
        self.PANEL_BORDER = "#D6DEE8"
    def setup_dark(self):
        self.BG = "#1E1E1E"
        self.CARD = "#2A2D2E"
        self.TEXT = "#E1E1E1"
        self.MUTED = "#A3A3A3"
        self.ACCENT = "#3B82F6"
        self.ACCENT_HOVER = "#2563EB"
        self.SUCCESS = "#22C55E"
        self.WARNING = "#F59E0B"
        self.ERROR = "#F87171"
        self.PREVIEW_BG = "#1F2937"
        self.PANEL_BORDER = "#3A3D3E"
    # STYLES
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        self.root.configure(bg=self.BG)
        style.configure("TFrame", background=self.BG)
        style.configure("Card.TFrame", background=self.CARD)
        style.configure("TLabel", background=self.BG, foreground=self.TEXT)
        style.configure(
            "Header.TLabel",
            background=self.CARD,
            foreground=self.TEXT,
            font=("Segoe UI", 10, "bold")
        )
        style.configure(
            "CardTitle.TLabel",
            background=self.CARD,
            foreground=self.TEXT,
            font=("Segoe UI", 14, "bold")
        )

        style.configure(
            "Hint.TLabel",
            background=self.CARD,
            foreground=self.MUTED,
            font=("Segoe UI", 9)
        )

        style.configure(
            "TLabelframe",
            background=self.CARD
        )

        style.configure(
            "TLabelframe.Label",
            background=self.CARD,
            foreground=self.TEXT
        )
        style.configure("Title.TLabel", font=("Segoe UI", 26, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 11), foreground=self.MUTED)

        style.configure("CardTitle.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Hint.TLabel", font=("Segoe UI", 9), foreground=self.MUTED)

        field_bg = "#111827" if self.dark else "#F3F4F6"
        field_fg = "#F9FAFB" if self.dark else self.TEXT
        style.configure(
            "TEntry",
            fieldbackground=field_bg,
            foreground=field_fg,
            insertcolor=field_fg,
            padding=7
        )
        style.configure(
            "TCombobox",
            fieldbackground=field_bg,
            background=field_bg,
            foreground=field_fg,
            selectbackground=field_bg,
            selectforeground=field_fg,
            arrowcolor=field_fg,
            padding=7
        )
        style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", field_bg),
                ("focus", field_bg)
            ],
            foreground=[
                ("readonly", field_fg),
                ("focus", field_fg)
            ],
            selectbackground=[
                ("readonly", field_bg),
                ("focus", field_bg)
            ],
            selectforeground=[
                ("readonly", field_fg),
                ("focus", field_fg)
            ]
        )
        style.configure("Accent.TButton",
                        background=self.ACCENT, foreground="white",
                        font=("Segoe UI", 12, "bold"), padding=12)
        style.map("Accent.TButton",
                  background=[("active", self.ACCENT_HOVER), ("pressed", self.ACCENT_HOVER)])

        sec_bg = "#E5E7EB" if not self.dark else "#555"
        sec_fg = "#111827" if not self.dark else "#EEE"
        style.configure("Secondary.TButton", background=sec_bg, foreground=sec_fg)

        style.configure("TProgressbar",
                        troughcolor="#E5E7EB" if not self.dark else "#444",
                        background=self.ACCENT)

        # CHECKBUTTON / RADIOBUTTON CLEANUP        
        style.configure(
            "TRadiobutton",
            background=self.CARD,
            foreground=self.TEXT,
            indicatorcolor=self.ACCENT,
            indicatordiameter=14,
            font=("Segoe UI", 10)
        )
        style.map(
            "TRadiobutton",
            background=[("active", self.CARD)],
            foreground=[("active", self.TEXT)]
        )
        style.configure(
            "TCheckbutton",
            background=self.CARD,
            foreground=self.TEXT,
            indicatorcolor=self.ACCENT,
            font=("Segoe UI", 10)
        )
        style.map(
            "TCheckbutton",
            background=[("active", self.CARD)],
            foreground=[("active", self.TEXT)]
        )  

        # NOTEBOOK / PREVIEW TABS
        tab_bg = "#374151" if self.dark else "#DCE6F7"
        tab_active = "#4B5563" if self.dark else "#C9D9F2"

        style.configure(
            "TNotebook",
            background=self.CARD,
            borderwidth=0
        )
        style.configure(
            "TNotebook.Tab",
            background=tab_bg,
            foreground=self.TEXT,
            padding=(14, 8),
            font=("Segoe UI", 10, "bold")
        )
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", self.ACCENT),
                ("active", tab_active),
                ("!selected", tab_bg)
            ],
            foreground=[
                ("selected", "white"),
                ("active", self.TEXT),
                ("!selected", self.TEXT)
            ]
        )
     
    # DARK MODE TOGGLE
    def toggle_dark(self):
        self.dark = not self.dark
        if self.dark:
            self.setup_dark()
        else:
            self.setup_light()

        self.setup_styles()
        self.build()

     
    # BUILD UI
     

    def build(self):
        for w in self.root.winfo_children():
            w.destroy()

        main = ttk.Frame(self.root, padding=22)
        main.pack(fill="both", expand=True)

        # HEADER --------------------------------------------
        header = ttk.Frame(main)
        header.pack(fill="x", pady=(0, 20))
        # LOGO -----------------------------------
        logo = tk.Label(
            header,
            text="🔐",
            bg=self.BG,
            fg=self.ACCENT,
            font=("Segoe UI Emoji", 34)
        )

        logo.pack(side="left", padx=(0, 12))

        title_box = ttk.Frame(header)
        title_box.pack(side="left", padx=(0, 15))

        ttk.Label(title_box, text="CryptoApp", style="Title.TLabel").pack(anchor="w")
        ttk.Label(title_box,
                  text="Secure file encryption using classical and custom cryptographic algorithms.",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(4, 0))

        ttk.Button(header,
                   text="🌙 Dark Mode" if not self.dark else "☀️ Light Mode",
                   style="Secondary.TButton",
                   command=self.toggle_dark).pack(side="right")

        # ---------------------------------------------------
        # MAIN LAYOUT (LEFT + RIGHT)
        # ---------------------------------------------------

        layout = ttk.Frame(main)
        layout.pack(fill="both", expand=True)

        layout.columnconfigure(0, weight=5)
        layout.columnconfigure(1, weight=3)
        layout.rowconfigure(0, weight=1)

        # LEFT PANEL ----------------------------------------
        left = tk.Frame(layout, bg=self.CARD,
                        highlightthickness=1, highlightbackground=self.PANEL_BORDER)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 15))

        lf = ttk.Frame(left, style="Card.TFrame", padding=25)
        lf.pack(fill="both", expand=True)

        ttk.Label(lf, text="Cipher Operations Panel", style="CardTitle.TLabel")\
            .grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 20))

        lf.columnconfigure(1, weight=1)

        # INPUT FILE ----------------------------------------
        ttk.Label(lf, text="Input File:", style="Header.TLabel")\
            .grid(row=1, column=0, sticky="w", pady=10)

        self.input_box = ttk.Entry(lf)
        self.input_box.grid(row=1, column=1, sticky="ew", padx=10)

        ttk.Button(lf, text="Browse", style="Secondary.TButton",
                   command=self.pick_input)\
            .grid(row=1, column=2, sticky="ew")

        # OUTPUT FILE ---------------------------------------
        ttk.Label(lf, text="Output File:", style="Header.TLabel")\
            .grid(row=2, column=0, sticky="w", pady=10)

        self.output_box = ttk.Entry(lf)
        self.output_box.grid(row=2, column=1, sticky="ew", padx=10)

        ttk.Button(lf, text="Save As", style="Secondary.TButton",
                   command=self.pick_output)\
            .grid(row=2, column=2, sticky="ew")

        ttk.Separator(lf).grid(row=3, column=0, columnspan=3, sticky="ew", pady=15)

        # ALGORITHM ----------------------------------------
        ttk.Label(lf, text="Cipher Algorithm:", style="Header.TLabel")\
            .grid(row=4, column=0, sticky="w", pady=10)

        algo_info = tk.Label(lf, text="❓", bg=self.CARD, fg=self.ACCENT, cursor="hand2")
        algo_info.grid(row=4, column=2, sticky="w")
        ToolTip(algo_info, "Click for algorithm descriptions")
        algo_info.bind("<Button-1>", lambda e: self.help_algo())

        self.algo_var = tk.StringVar()
        self.algo_combo = ttk.Combobox(lf, textvariable=self.algo_var, state="readonly")
        self.algo_combo["values"] = [
            "Vigenère Cipher (Polyalphabetic)",
            "Vernam Cipher (XOR Stream)",
            "Columnar Transposition",
            "Orbit Cipher (Custom Multi-Layer)",
        ]
        self.algo_combo.current(0)
        self.algo_combo.grid(row=4, column=1, sticky="ew", padx=10)
        ttk.Label(
            lf,
            text="Example key: secret123",
            style="Hint.TLabel"
        ).grid(row=6, column=0, columnspan=3, sticky="w", padx=10, pady=(0, 8))

        self.algo_combo.bind("<<ComboboxSelected>>", self.update_algo_hint)

        self.algo_hint = ttk.Label(lf, text="Vigenère uses a text key to shift bytes.",
                                   style="Hint.TLabel")
        self.algo_hint.grid(row=5, column=0, columnspan=3, sticky="w", padx=10)

        # KEY ----------------------------------------------
        ttk.Label(lf, text="Key:", style="Header.TLabel")\
            .grid(row=7, column=0, sticky="w", pady=10)

        key_info = tk.Label(lf, text="❓", bg=self.CARD, fg=self.ACCENT, cursor="hand2")
        key_info.grid(row=7, column=2, sticky="w")
        ToolTip(key_info, "Click for key requirements")
        key_info.bind("<Button-1>", lambda e: self.help_key())

        self.key_entry = ttk.Entry(lf, show="*")
        self.key_entry.grid(row=7, column=1, sticky="ew", padx=10)


        # Show / Hide key
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(lf, text="Show", variable=self.show_key_var,
                        command=self.toggle_key_visibility)\
            .grid(row=7, column=3, sticky="w")

        # MODE ----------------------------------------------
        ttk.Label(lf, text="Mode:", style="Header.TLabel")\
            .grid(row=8, column=0, sticky="w", pady=10)

        self.mode = tk.StringVar(value="Encrypt")
        modf = ttk.Frame(lf, style="Card.TFrame")
        modf.grid(row=8, column=1, sticky="w", padx=10)

        ttk.Radiobutton(modf, text="Encrypt", variable=self.mode, value="Encrypt",
                        command=self.update_mode).pack(side="left", padx=10)
        ttk.Radiobutton(modf, text="Decrypt", variable=self.mode, value="Decrypt",
                        command=self.update_mode).pack(side="left")

        # BUTTON --------------------------------------------
        self.process_btn = ttk.Button(lf, text="Encrypt File",
                                      style="Accent.TButton",
                                      command=self.process_file)
        self.process_btn.grid(row=9, column=0, columnspan=4,
                              sticky="ew", pady=(20, 10))

        # PROGRESS ------------------------------------------
        self.progress = ttk.Progressbar(lf, mode="indeterminate")
        self.progress.grid(row=10, column=0, columnspan=4, sticky="ew")

        # STATUS --------------------------------------------
        self.status_label = ttk.Label(lf,
                                      text="Ready. Select a file and enter a key.",
                                      style="Hint.TLabel",
                                      foreground=self.ACCENT)
        self.status_label.grid(row=11, column=0, columnspan=4, pady=(12, 0))

        ttk.Label(main,
                  text="Supports text files, images, PDFs, and binary files.",
                  style="Subtitle.TLabel").pack(pady=(20, 0))

        # ---------------------------------------------------
        # TABBED PREVIEW PANEL (RIGHT SIDE)
        # ---------------------------------------------------

        right = tk.Frame(layout, bg=self.CARD,
                         highlightthickness=1, highlightbackground=self.PANEL_BORDER)
        right.grid(row=0, column=1, sticky="nsew")

        right_inner = ttk.Frame(right, style="Card.TFrame", padding=15)
        right_inner.pack(fill="both", expand=True)

        ttk.Label(right_inner, text="File Preview", style="CardTitle.TLabel")\
            .pack(anchor="w", pady=(0, 10))

        # TAB CONTROL ---------------------------------------
        self.tabs = ttk.Notebook(right_inner)
        self.tabs.pack(fill="both", expand=True)

        self.input_tab = tk.Frame(self.tabs, bg=self.PREVIEW_BG)
        self.output_tab = tk.Frame(self.tabs, bg=self.PREVIEW_BG)

        self.tabs.add(self.input_tab, text="Input Preview")
        self.tabs.add(self.output_tab, text="Output Preview")

        # INPUT PREVIEW AREA --------------------------------
        self.input_preview = tk.Text(
            self.input_tab, wrap="word",
            bg=self.PREVIEW_BG, fg=self.TEXT,
            relief="flat", highlightthickness=0,bd=0, 
            state="disabled",takefocus=0
        )
        self.input_preview.pack(fill="both", expand=True)

        # OUTPUT PREVIEW AREA -------------------------------
        self.output_preview = tk.Text(
            self.output_tab, wrap="word",
            bg=self.PREVIEW_BG, fg=self.TEXT,
            relief="flat", highlightthickness=0,bd=0, 
            state="disabled",takefocus=0
        )
        self.output_preview.pack(fill="both", expand=True)

        # Default messages
        self.set_input_preview("No file selected.")
        self.set_output_preview("Output will appear after encryption/decryption.")

    # =======================================================
    # PREVIEW HELPERS
    # =======================================================

    def set_input_preview(self, text):
        self.input_preview.config(state="normal")
        self.input_preview.delete("1.0", "end")
        self.input_preview.insert("1.0", text)
        self.input_preview.config(state="disabled")

    def set_output_preview(self, text):
        self.output_preview.config(state="normal")
        self.output_preview.delete("1.0", "end")
        self.output_preview.insert("1.0", text)
        self.output_preview.config(state="disabled")

    def preview_file(self, path, is_output=False):
        ext = os.path.splitext(path)[1].lower()

        if ext in [".txt", ".py", ".md", ".json", ".csv", ".ini"]:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    data = f.read()
            except:
                data = "Error reading text file."
        elif ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp"]:
            data = "Image preview unavailable (PIL not installed)."
        else:
            data = "Preview unavailable for this file type."

        if is_output:
            self.set_output_preview(data)
        else:
            self.set_input_preview(data)

    # =======================================================
    # FILE PICKING
    # =======================================================

    def pick_input(self):
        f = filedialog.askopenfilename()
        if not f:
            return
        self.input_path = f
        self.input_box.delete(0, "end")
        self.input_box.insert(0, f)
        self.preview_file(f, is_output=False)

        base, ext = os.path.splitext(f)
        suggested = f"{base}_encrypt{ext}"
        self.output_box.delete(0, "end")
        self.output_box.insert(0, suggested)

    def pick_output(self):
        f = filedialog.asksaveasfilename()
        if not f:
            return
        self.output_path = f
        self.output_box.delete(0, "end")
        self.output_box.insert(0, f)

    # =======================================================
    # KEY PLACEHOLDER
    # =======================================================



    # =======================================================
    # KEY VISIBILITY
    # =======================================================

    def toggle_key_visibility(self):
        if self.show_key_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")

    # =======================================================
    # ALGORITHM HINT
    # =======================================================

    def update_algo_hint(self, e=None):
        a = self.algo_var.get()
        if a.startswith("Vigen"):
            msg = "Vigenère: byte shifts using repeating key."
        elif a.startswith("Vernam"):
            msg = "Vernam: XOR stream cipher."
        elif a.startswith("Columnar"):
            msg = "Columnar: rearranges bytes by key order."
        else:
            msg = "Orbit: multi-layer cipher with S-box + integrity check."
        self.algo_hint.config(text=msg)
        self.apply_key_placeholder()

    # =======================================================
    # MODE UPDATE
    # =======================================================

    def update_mode(self):
        m = self.mode.get()
        self.process_btn.config(text=f"{m} File")

        if self.input_path:
            b, e = os.path.splitext(self.input_path)
            self.output_box.delete(0, "end")
            self.output_box.insert(0, f"{b}_{m.lower()}{e}")

    # =======================================================
    # POPUP HELP WINDOWS
    # =======================================================

    def help_algo(self):
        self.popup("Algorithm Help",
                   "VIGENÈRE: shifts bytes using repeated key.\n"
                   "VERNAM: XOR stream cipher.\n"
                   "COLUMNAR: rearranges byte positions.\n"
                   "ORBIT: key expansion + S-box + rotation + integrity check.")

    def help_key(self):
        self.popup("Key Help",
                   "Keys must be at least:\n"
                   "- Vigenère: 1+ chars\n"
                   "- Vernam: 1+ chars\n"
                   "- Columnar: 2+ chars\n"
                   "- Orbit: recommended 6+ chars")

    def popup(self, title, text):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("380x280")
        win.configure(bg=self.CARD)

        tk.Label(win, text=title, bg=self.CARD, fg=self.TEXT,
                 font=("Segoe UI", 14, "bold")).pack(pady=10)

        box = tk.Text(win, wrap="word", bg=self.CARD, fg=self.TEXT,
                      relief="flat")
        box.insert("1.0", text)
        box.config(state="disabled")
        box.pack(fill="both", expand=True, padx=10, pady=5)

    # =======================================================
    # STATUS
    # =======================================================

    def set_status(self, text, color=None):
        if not color:
            color = self.ACCENT
        self.status_label.config(text=text, foreground=color)
        self.root.update_idletasks()

    # =======================================================
    # PROCESS ENCRYPT/DECRYPT
    # =======================================================

    def process_file(self):
        inp = self.input_box.get().strip()
        outp = self.output_box.get().strip()
        key = self.key_entry.get().strip()
        algo = self.algo_var.get()
        mode = self.mode.get()


        if not inp:
            messagebox.showerror("Missing Input File", "Select an input file.")
            return
        if not outp:
            messagebox.showerror("Missing Output File", "Select an output file.")
            return
        if not os.path.exists(inp):
            messagebox.showerror("File Not Found",
                                 "The selected input file does not exist.")
            return
        if not key:
            messagebox.showerror("Missing Key", "Enter a valid key.")
            return

        try:
            self.progress.start()
            self.process_btn.config(state="disabled")
            self.set_status("Reading file...", self.WARNING)

            with open(inp, "rb") as f:
                data = f.read()

            self.set_status("Processing...", self.WARNING)

            enc = (mode == "Encrypt")

            if algo.startswith("Vigen"):
                processed = vigenere_cipher(data, key, enc)
            elif algo.startswith("Vernam"):
                processed = vernam_cipher(data, key)
            elif algo.startswith("Columnar"):
                processed = columnar_transposition(data, key, enc)
            else:
                processed = orbit_cipher_with_integrity(data, key, enc)

            self.set_status("Saving...", self.WARNING)

            with open(outp, "wb") as f:
                f.write(processed)

            self.set_status(f"{mode}ion complete.", self.SUCCESS)

            # Preview output file automatically
            self.preview_file(outp, is_output=True)

            messagebox.showinfo(
                "Success",
                f"File successfully {mode.lower()}ed!\nSaved to:\n{outp}"
            )

        except Exception as e:
            self.set_status("An error occurred.", self.ERROR)
            messagebox.showerror("Error", str(e))

        finally:
            self.progress.stop()
            self.process_btn.config(state="normal")
