import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

from scanner import scan_directory, load_signatures, write_report  # reuse your logic

class MalwareScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Malware Scanner")
        self.root.geometry("800x500")

        self.selected_folder = tk.StringVar()

        self.setup_widgets()

    def setup_widgets(self):
        # Folder selection
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Target Folder:").pack(side=tk.LEFT, padx=5)
        tk.Entry(frame, textvariable=self.selected_folder, width=60).pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Browse", command=self.browse_folder).pack(side=tk.LEFT)

        # Start scan button
        tk.Button(self.root, text="Start Scan", command=self.start_scan, bg="#4CAF50", fg="white").pack(pady=10)

        # Treeview for results
        columns = ("path", "score", "reasons")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=250 if col == "path" else 150)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Save report button
        tk.Button(self.root, text="Save Report", command=self.save_report).pack(pady=10)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder.set(folder)

    def start_scan(self):
        folder = self.selected_folder.get()
        if not folder:
            messagebox.showerror("Error", "Please select a folder to scan.")
            return

        self.tree.delete(*self.tree.get_children())

        sigs = load_signatures("signatures/suspicious_strings.txt")
        results = scan_directory(folder, sigs)

        if not results:
            messagebox.showinfo("Done", "No suspicious files found.")
            return

        for r in results:
            self.tree.insert("", tk.END, values=(r["path"], r["score"], ", ".join(r["reasons"])))

        self.last_results = results
        messagebox.showinfo("Done", f"Scan complete. {len(results)} suspicious file(s) found.")

    def save_report(self):
        print("[DEBUG] Scan button pressed.")
        if not hasattr(self, 'last_results') or not self.last_results:
            messagebox.showwarning("No Results", "Nothing to save yet.")
            return

        write_report(self.last_results)
        messagebox.showinfo("Saved", "Scan report saved successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareScannerGUI(root)
    root.mainloop()
