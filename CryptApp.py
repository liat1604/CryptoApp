import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os


# ==================== ENCRYPTION/DECRYPTION FUNCTIONS ====================

def vigenere_cipher(data: bytes, key: str, encrypt: bool = True) -> bytes:
    if not key:
        return data

    key_bytes = key.encode("utf-8")
    result = bytearray(len(data))

    for i in range(len(data)):
        k = key_bytes[i % len(key_bytes)]
        result[i] = (data[i] + k) % 256 if encrypt else (data[i] - k) % 256

    return bytes(result)


def vernam_cipher(data: bytes, key: str) -> bytes:
    if not key:
        return data

    key_bytes = key.encode("utf-8")
    result = bytearray(len(data))

    for i in range(len(data)):
        result[i] = data[i] ^ key_bytes[i % len(key_bytes)]

    return bytes(result)


def columnar_transposition(data: bytes, key: str, encrypt: bool = True) -> bytes:
    if not key or len(key) < 2:
        return data

    cols = len(key)
    col_order = sorted(range(len(key)), key=lambda i: key[i])

    def pad_data(d, c):
        pad_len = (c - len(d) % c) % c
        return d + b"\x00" * pad_len

    if encrypt:
        header = len(data).to_bytes(8, "big")
        to_grid = header + data
        padded = pad_data(to_grid, cols)
        rows = len(padded) // cols

        result = bytearray()
        for c in col_order:
            for r in range(rows):
                result.append(padded[r * cols + c])

        return bytes(result)

    padded_len = len(data)

    if padded_len % cols != 0:
        raise ValueError("Invalid data length for Columnar decryption.")

    rows = padded_len // cols
    grid = bytearray(padded_len)

    idx = 0
    for c in col_order:
        for r in range(rows):
            grid[r * cols + c] = data[idx]
            idx += 1

    if len(grid) < 8:
        raise ValueError("Invalid data: missing length header.")

    original_len = int.from_bytes(grid[:8], "big")

    if original_len > len(grid) - 8:
        raise ValueError("Invalid original length in file.")

    return bytes(grid[8:8 + original_len])


# ======= UNIQUE OWN ALGORITHM =======

def rotate_left(b, n):
    return ((b << n) | (b >> (8 - n))) & 255


def rotate_right(b, n):
    return ((b >> n) | (b << (8 - n))) & 255


def own_orbit_shuffle(data: bytes, key: str, encrypt=True) -> bytes:
    if not key:
        return data

    key_bytes = key.encode("utf-8")
    key_len = len(key_bytes)

    result = bytearray(len(data))
    feedback = (sum(key_bytes) + key_len * 17) % 256

    if encrypt:
        for i, byte in enumerate(data):
            k = key_bytes[i % key_len]
            orbit = (k + feedback + i * 13 + key_len) % 256
            rot = (orbit % 7) + 1

            x = (byte + orbit) % 256
            x = rotate_left(x, rot)
            x = (x + feedback + k) % 256

            result[i] = x
            feedback = x
    else:
        for i, byte in enumerate(data):
            k = key_bytes[i % key_len]
            orbit = (k + feedback + i * 13 + key_len) % 256
            rot = (orbit % 7) + 1

            x = (byte - feedback - k) % 256
            x = rotate_right(x, rot)
            x = (x - orbit) % 256

            result[i] = x
            feedback = byte

    return bytes(result)


# ==================== GUI ====================

class FileEncryptorApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Encryptor")
        self.root.geometry("950x650")
        self.root.minsize(900, 600)

        self.setup_styles()
        self.build_gui()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        BG = "#F8FAFC"
        CARD = "#FFFFFF"
        TEXT = "#1F2937"
        MUTED = "#6B7280"
        ACCENT = "#2563EB"
        BORDER = "#E5E7EB"

        self.root.configure(bg=BG)

        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)

        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", foreground=MUTED)
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))

        style.configure("TLabelframe", background=CARD, bordercolor=BORDER)
        style.configure("TLabelframe.Label", background=CARD)

        style.configure("TEntry", fieldbackground=CARD, padding=6)

        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="white",
            font=("Segoe UI", 12, "bold"),
            padding=12
        )

    def build_gui(self):
        main = ttk.Frame(self.root, padding=24)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="File Encryption Tool", style="Title.TLabel").pack(anchor="w")
        ttk.Label(main, text="Encrypt or decrypt any file type.", style="Subtitle.TLabel").pack(anchor="w", pady=(0, 20))

        file_frame = ttk.LabelFrame(main, text="Files", padding=16)
        file_frame.pack(fill="x", pady=8)

        ttk.Label(file_frame, text="Input File:", style="Header.TLabel").grid(row=0, column=0)

        self.input_entry = ttk.Entry(file_frame)
        self.input_entry.grid(row=0, column=1, sticky="ew", padx=10)

        ttk.Button(file_frame, text="Browse", command=self.browse_input).grid(row=0, column=2)

        ttk.Label(file_frame, text="Output File:", style="Header.TLabel").grid(row=1, column=0)

        self.output_entry = ttk.Entry(file_frame)
        self.output_entry.grid(row=1, column=1, sticky="ew", padx=10)

        ttk.Button(file_frame, text="Save As", command=self.browse_output).grid(row=1, column=2)

        file_frame.columnconfigure(1, weight=1)

        settings_frame = ttk.LabelFrame(main, text="Settings", padding=16)
        settings_frame.pack(fill="x", pady=8)

        self.algo_var = tk.StringVar()

        self.algo_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.algo_var,
            state="readonly"
        )

        self.algo_combo["values"] = [
            "Vigenère Cipher (Polyalphabetic)",
            "Vernam Cipher (XOR Stream)",
            "Columnar Transposition",
            "Own Algorithm (Orbit Shuffle)"
        ]

        self.algo_combo.current(0)
        self.algo_combo.pack(fill="x", pady=5)

        self.key_entry = ttk.Entry(settings_frame, show="*")
        self.key_entry.pack(fill="x", pady=5)

        self.mode_var = tk.StringVar(value="Encrypt")

        ttk.Radiobutton(settings_frame, text="Encrypt", variable=self.mode_var, value="Encrypt").pack(side="left")
        ttk.Radiobutton(settings_frame, text="Decrypt", variable=self.mode_var, value="Decrypt").pack(side="left")

        ttk.Button(main, text="Process File", style="Accent.TButton", command=self.process_file).pack(fill="x", pady=20)

    def browse_input(self):
        f = filedialog.askopenfilename()
        if f:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, f)

    def browse_output(self):
        f = filedialog.asksaveasfilename()
        if f:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, f)

    def process_file(self):
        try:
            with open(self.input_entry.get(), "rb") as f:
                data = f.read()

            key = self.key_entry.get()
            algo = self.algo_var.get()
            encrypt = self.mode_var.get() == "Encrypt"

            if algo == "Own Algorithm (Orbit Shuffle)":
                result = own_orbit_shuffle(data, key, encrypt)
            elif algo.startswith("Vigenère"):
                result = vigenere_cipher(data, key, encrypt)
            elif algo.startswith("Vernam"):
                result = vernam_cipher(data, key)
            else:
                result = columnar_transposition(data, key, encrypt)

            with open(self.output_entry.get(), "wb") as f:
                f.write(result)

            messagebox.showinfo("Success", "Done!")

        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    app = FileEncryptorApp()
    app.root.mainloop()