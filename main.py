# FileEncryptor.py
# Project: File Encryption/Decryption Application
# Language: Python 3 (uses only built-in tkinter - no extra installations required)
# Author: Generated for the assignment (ready for submission)
# Date: April 2026
# Description: GUI application to encrypt/decrypt ANY file type (text, images, PDFs, executables, etc.)
#              using byte-level operations for full binary compatibility.
#              All algorithms are fully reversible and use variables for keys/shifts/columns.

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# ==================== ENCRYPTION/DECRYPTION FUNCTIONS ====================

def vigenere_cipher(data: bytes, key: str, encrypt: bool = True) -> bytes:
    """Vigenère – polyalphabetic substitution (adapted for bytes)."""
    if not key:
        return data
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    result = bytearray(len(data))
    for i in range(len(data)):
        k = key_bytes[i % key_len]
        if encrypt:
            result[i] = (data[i] + k) % 256
        else:
            result[i] = (data[i] - k) % 256
    return bytes(result)


def vernam_cipher(data: bytes, key: str) -> bytes:
    """Vernam (one-time-pad style stream cipher using repeating key via XOR)."""
    if not key:
        return data
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    result = bytearray(len(data))
    for i in range(len(data)):
        k = key_bytes[i % key_len]
        result[i] = data[i] ^ k
    return bytes(result)
    # Note: encryption and decryption are identical (XOR property)


def columnar_transposition(data: bytes, key: str, encrypt: bool = True) -> bytes:
    """Columnar Transposition (binary-safe with length header + padding)."""
    if not key or len(key) < 2:
        return data
    cols = len(key)

    def get_column_order(k):
        return sorted(range(len(k)), key=lambda i: k[i])

    def pad_data(d, c):
        pad_len = (c - len(d) % c) % c
        return d + b'\x00' * pad_len

    col_order = get_column_order(key)

    if encrypt:
        # Prepend original length (8 bytes) so decryption knows exact size
        header = len(data).to_bytes(8, 'big')
        to_grid = header + data
        padded = pad_data(to_grid, cols)
        rows = len(padded) // cols
        result = bytearray()
        for c in col_order:
            for r in range(rows):
                result.append(padded[r * cols + c])
        return bytes(result)
    else:
        # Decrypt: input is already padded + transposed
        padded_len = len(data)
        if padded_len % cols != 0:
            raise ValueError("Invalid data length for Columnar decryption (not multiple of columns)")
        rows = padded_len // cols
        grid = bytearray(padded_len)
        idx = 0
        for c in col_order:
            for r in range(rows):
                grid[r * cols + c] = data[idx]
                idx += 1
        if len(grid) < 8:
            raise ValueError("Invalid data (too short for header)")
        orig_len = int.from_bytes(grid[:8], 'big')
        if orig_len > len(grid) - 8:
            raise ValueError("Invalid original length in header")
        return bytes(grid[8:8 + orig_len])


def own_caesar_cipher(data: bytes, shift: int, encrypt: bool = True) -> bytes:
    """Own algorithm: Byte-level Caesar cipher with variable shift (mod 256)."""
    shift = shift % 256
    if not encrypt:
        shift = -shift % 256
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b + shift) % 256
    return bytes(result)


# ==================== GUI ====================

class FileEncryptorApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Encryptor - Encryption/Decryption Tool")
        self.root.geometry("700x420")
        self.root.resizable(False, False)

        # Input file
        tk.Label(self.root, text="Input File:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.input_entry = tk.Entry(self.root, width=60)
        self.input_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.root, text="Browse", command=self.browse_input).grid(row=0, column=2, padx=10)

        # Output file
        tk.Label(self.root, text="Output File:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.output_entry = tk.Entry(self.root, width=60)
        self.output_entry.grid(row=1, column=1, padx=10, pady=10)
        tk.Button(self.root, text="Browse", command=self.browse_output).grid(row=1, column=2, padx=10)

        # Algorithm
        tk.Label(self.root, text="Algorithm:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="w", padx=10, pady=10)
        self.algo_var = tk.StringVar()
        self.algo_combo = ttk.Combobox(self.root, textvariable=self.algo_var, state="readonly", width=57)
        self.algo_combo['values'] = [
            "Vigenère Cipher (Polyalphabetic)",
            "Vernam Cipher (XOR Stream)",
            "Columnar Transposition",
            "Own Algorithm (Byte Caesar)"
        ]
        self.algo_combo.grid(row=2, column=1, columnspan=2, padx=10, pady=10)
        self.algo_combo.current(0)

        # Key / Shift
        self.key_label = tk.Label(self.root, text="Key (or Shift for Own Algorithm):", font=("Arial", 10, "bold"))
        self.key_label.grid(row=3, column=0, sticky="w", padx=10, pady=10)
        self.key_entry = tk.Entry(self.root, width=60, show="*")  # masked for security
        self.key_entry.grid(row=3, column=1, padx=10, pady=10)

        # Mode
        tk.Label(self.root, text="Mode:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky="w", padx=10, pady=10)
        self.mode_var = tk.StringVar(value="Encrypt")
        tk.Radiobutton(self.root, text="Encrypt", variable=self.mode_var, value="Encrypt").grid(row=4, column=1, sticky="w", padx=10)
        tk.Radiobutton(self.root, text="Decrypt", variable=self.mode_var, value="Decrypt").grid(row=4, column=1, padx=120)

        # Process button
        self.process_btn = tk.Button(self.root, text="PROCESS FILE", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", height=2, command=self.process_file)
        self.process_btn.grid(row=5, column=0, columnspan=3, pady=20, padx=10, sticky="ew")

        # Status
        self.status_label = tk.Label(self.root, text="Ready - Select file and algorithm", fg="blue", font=("Arial", 9))
        self.status_label.grid(row=6, column=0, columnspan=3, pady=10)

        # Footer info
        tk.Label(self.root, text="Handles ALL file types • Byte-level • Educational project", fg="gray").grid(row=7, column=0, columnspan=3, pady=5)

    def browse_input(self):
        filename = filedialog.askopenfilename(title="Select file to encrypt/decrypt")
        if filename:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, filename)
            # Auto-suggest output name
            if not self.output_entry.get():
                import os
                base, ext = os.path.splitext(filename)
                mode = self.mode_var.get().lower()
                suggested = f"{base}_{mode}{ext}"
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, suggested)

    def browse_output(self):
        filename = filedialog.asksaveasfilename(title="Save output as", defaultextension=".enc")
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)

    def process_file(self):
        input_path = self.input_entry.get().strip()
        output_path = self.output_entry.get().strip()
        algo = self.algo_var.get()
        key_str = self.key_entry.get().strip()
        mode = self.mode_var.get()
        encrypt = (mode == "Encrypt")

        if not input_path or not output_path:
            messagebox.showerror("Error", "Please select both input and output files.")
            return
        if not key_str and algo != "Columnar Transposition":  # Columnar needs key too
            messagebox.showerror("Error", "Key/Shift is required for this algorithm.")
            return

        try:
            self.status_label.config(text="Reading file...", fg="orange")
            self.root.update()

            with open(input_path, 'rb') as f:
                data = f.read()

            self.status_label.config(text="Processing...", fg="orange")
            self.root.update()

            if algo == "Vigenère Cipher (Polyalphabetic)":
                processed = vigenere_cipher(data, key_str, encrypt)
            elif algo == "Vernam Cipher (XOR Stream)":
                processed = vernam_cipher(data, key_str)  # symmetric
            elif algo == "Columnar Transposition":
                processed = columnar_transposition(data, key_str, encrypt)
            elif algo == "Own Algorithm (Byte Caesar)":
                try:
                    shift = int(key_str)
                except ValueError:
                    raise ValueError("Own Algorithm requires an integer shift value (e.g. 13)")
                processed = own_caesar_cipher(data, shift, encrypt)
            else:
                raise ValueError("Unknown algorithm")

            with open(output_path, 'wb') as f:
                f.write(processed)

            self.status_label.config(text=f"✅ {mode}ion completed successfully!", fg="green")
            messagebox.showinfo("Success", f"File successfully {mode.lower()}ed!\nSaved to:\n{output_path}\n\nSize: {len(processed):,} bytes")

        except Exception as e:
            self.status_label.config(text="❌ Error occurred", fg="red")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")


if __name__ == "__main__":
    app = FileEncryptorApp()
    app.root.mainloop()