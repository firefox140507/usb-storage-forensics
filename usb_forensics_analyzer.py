"""
USB Storage Forensics and File Integrity Analyzer
Educational project: file metadata collection, SHA-256 hashing,
duplicate-content detection, CSV export, and hash verification.

This tool reads files selected by the user. It does not acquire a forensic
image, write-block a USB device, or guarantee forensic soundness. For formal
forensic work, use an appropriate hardware/software write blocker and a
verified forensic image.
"""
import csv
import hashlib
import os
import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "USB Storage Forensics & File Integrity Analyzer"
CHUNK_SIZE = 1024 * 1024  # 1 MiB


def format_time(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "Unavailable"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(root):
    """Yield regular files without following directory symlinks."""
    for current, dirs, filenames in os.walk(root, followlinks=False):
        # Avoid traversing directory symlinks/junctions where possible.
        dirs[:] = [
            name for name in dirs
            if not (Path(current) / name).is_symlink()
        ]
        for name in filenames:
            path = Path(current) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                yield path
            except OSError:
                continue


class ForensicsApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1180x690")
        self.root.minsize(900, 520)

        self.folder_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Choose a USB drive folder or an evidence-copy folder to begin.")
        self.records = []
        self.events = queue.Queue()
        self.busy = False

        self._build_ui()
        self.root.after(100, self._process_events)

    def _build_ui(self):
        header = ttk.Frame(self.root, padding=(14, 12))
        header.pack(fill="x")

        ttk.Label(
            header, text=APP_TITLE, font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Metadata collection • SHA-256 integrity hashes • Duplicate detection • CSV reporting",
            font=("Segoe UI", 9)
        ).pack(anchor="w", pady=(3, 10))

        folder_frame = ttk.LabelFrame(self.root, text="Evidence source", padding=10)
        folder_frame.pack(fill="x", padx=14, pady=(0, 10))
        ttk.Entry(folder_frame, textvariable=self.folder_var).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ttk.Button(folder_frame, text="Browse…", command=self.choose_folder).pack(side="left", padx=3)
        self.scan_btn = ttk.Button(folder_frame, text="Scan and Hash", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=3)

        controls = ttk.Frame(self.root, padding=(14, 0, 14, 8))
        controls.pack(fill="x")
        self.export_btn = ttk.Button(
            controls, text="Export CSV Report", command=self.export_csv, state="disabled"
        )
        self.export_btn.pack(side="left", padx=(0, 6))
        self.verify_btn = ttk.Button(
            controls, text="Verify Current Files", command=self.start_verify, state="disabled"
        )
        self.verify_btn.pack(side="left", padx=6)
        self.duplicates_btn = ttk.Button(
            controls, text="Show Duplicates", command=self.show_duplicates, state="disabled"
        )
        self.duplicates_btn.pack(side="left", padx=6)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=14, pady=(0, 8))

        summary = ttk.Frame(self.root, padding=(14, 0, 14, 8))
        summary.pack(fill="x")
        self.summary_var = tk.StringVar(value="Files: 0    Total size: 0 bytes    Duplicate groups: 0")
        ttk.Label(summary, textvariable=self.summary_var, font=("Segoe UI", 10, "bold")).pack(anchor="w")

        table_frame = ttk.Frame(self.root, padding=(14, 0, 14, 8))
        table_frame.pack(fill="both", expand=True)
        columns = ("name", "size", "modified", "sha256", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("name", text="File path")
        self.tree.heading("size", text="Size (bytes)")
        self.tree.heading("modified", text="Modified time")
        self.tree.heading("sha256", text="SHA-256")
        self.tree.heading("status", text="Verification status")
        self.tree.column("name", width=340, minwidth=180)
        self.tree.column("size", width=105, anchor="e")
        self.tree.column("modified", width=155)
        self.tree.column("sha256", width=320, minwidth=200)
        self.tree.column("status", width=140)
        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        footer = ttk.Frame(self.root, padding=(14, 4, 14, 12))
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status_var, wraplength=1080).pack(anchor="w")

    def choose_folder(self):
        folder = filedialog.askdirectory(title="Select USB folder or evidence-copy folder")
        if folder:
            self.folder_var.set(folder)

    def start_scan(self):
        if self.busy:
            return
        folder = Path(self.folder_var.get().strip())
        if not folder.exists() or not folder.is_dir():
            messagebox.showerror("Invalid folder", "Select an existing folder or mounted USB drive.")
            return
        if not messagebox.askyesno(
            "Confirm source",
            "The program will read files to calculate hashes. For formal forensic work, use a write blocker and a verified evidence copy.\n\nContinue?"
        ):
            return

        self.busy = True
        self.records = []
        self._clear_table()
        self._set_busy(True, "Scanning files and calculating SHA-256 hashes…")
        threading.Thread(target=self._scan_worker, args=(folder,), daemon=True).start()

    def _scan_worker(self, folder):
        results = []
        errors = 0
        total_bytes = 0
        try:
            for path in collect_files(folder):
                try:
                    stat = path.stat()
                    digest = sha256_file(path)
                    record = {
                        "file_path": str(path),
                        "file_name": path.name,
                        "size_bytes": stat.st_size,
                        "created_time": format_time(stat.st_ctime),
                        "modified_time": format_time(stat.st_mtime),
                        "sha256": digest,
                        "verification_status": "Not yet verified",
                        "error": ""
                    }
                    results.append(record)
                    total_bytes += stat.st_size
                    self.events.put(("row", record))
                except (OSError, PermissionError) as exc:
                    errors += 1
                    self.events.put(("status", f"Skipped unreadable file: {path} ({exc})"))
            self.events.put(("scan_done", results, total_bytes, errors))
        except Exception as exc:
            self.events.put(("fatal", str(exc)))

    def start_verify(self):
        if self.busy or not self.records:
            return
        self.busy = True
        self._set_busy(True, "Recalculating hashes to verify current file integrity…")
        snapshot = [record.copy() for record in self.records]
        threading.Thread(target=self._verify_worker, args=(snapshot,), daemon=True).start()

    def _verify_worker(self, snapshot):
        updated = []
        for old in snapshot:
            path = Path(old["file_path"])
            record = old.copy()
            try:
                if not path.exists() or not path.is_file():
                    record["verification_status"] = "MISSING"
                else:
                    current_hash = sha256_file(path)
                    stat = path.stat()
                    if current_hash == old["sha256"] and stat.st_size == old["size_bytes"]:
                        record["verification_status"] = "MATCH"
                    else:
                        record["verification_status"] = "CHANGED"
                    record["current_sha256"] = current_hash
            except OSError as exc:
                record["verification_status"] = "UNREADABLE"
                record["error"] = str(exc)
            updated.append(record)
            self.events.put(("verify_row", record))
        self.events.put(("verify_done", updated))

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "row":
                    self._insert_or_update(event[1])
                elif kind == "status":
                    self.status_var.set(event[1])
                elif kind == "scan_done":
                    _, results, total_bytes, errors = event
                    self.records = results
                    self._set_busy(False)
                    groups = self._duplicate_groups()
                    self.summary_var.set(
                        f"Files: {len(results)}    Total size: {total_bytes:,} bytes    "
                        f"Duplicate groups: {len(groups)}    Skipped/unreadable: {errors}"
                    )
                    self.export_btn.configure(state="normal" if results else "disabled")
                    self.verify_btn.configure(state="normal" if results else "disabled")
                    self.duplicates_btn.configure(state="normal" if results else "disabled")
                    self.status_var.set(
                        f"Scan complete. {len(results)} files hashed; {errors} file(s) skipped or unreadable."
                    )
                    messagebox.showinfo(
                        "Scan complete",
                        f"Files hashed: {len(results)}\nTotal size: {total_bytes:,} bytes\n"
                        f"Duplicate groups: {len(groups)}\nSkipped/unreadable: {errors}"
                    )
                elif kind == "verify_row":
                    self._insert_or_update(event[1])
                elif kind == "verify_done":
                    self.records = event[1]
                    self._set_busy(False)
                    counts = {}
                    for rec in self.records:
                        status = rec.get("verification_status", "Unknown")
                        counts[status] = counts.get(status, 0) + 1
                    self.summary_var.set(
                        "Verification: " + "    ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
                    )
                    self.status_var.set("Verification complete. MATCH means the current hash equals the scan hash.")
                    messagebox.showinfo("Verification complete", self.status_var.get())
                elif kind == "fatal":
                    self._set_busy(False)
                    messagebox.showerror("Operation failed", event[1])
                    self.status_var.set("Operation failed.")
        except queue.Empty:
            pass
        self.root.after(100, self._process_events)

    def _insert_or_update(self, record):
        path = record["file_path"]
        values = (
            path,
            f'{record.get("size_bytes", 0):,}',
            record.get("modified_time", ""),
            record.get("current_sha256", record.get("sha256", "")),
            record.get("verification_status", "")
        )
        if self.tree.exists(path):
            self.tree.item(path, values=values)
        else:
            self.tree.insert("", "end", iid=path, values=values)

    def _clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _set_busy(self, busy, message=None):
        self.busy = busy
        self.scan_btn.configure(state="disabled" if busy else "normal")
        self.progress.start(10) if busy else self.progress.stop()
        if message:
            self.status_var.set(message)
        if not busy:
            self.scan_btn.configure(state="normal")

    def _duplicate_groups(self):
        by_hash = {}
        for rec in self.records:
            key = (rec["size_bytes"], rec["sha256"])
            by_hash.setdefault(key, []).append(rec)
        return [items for items in by_hash.values() if len(items) > 1]

    def show_duplicates(self):
        groups = self._duplicate_groups()
        win = tk.Toplevel(self.root)
        win.title("Duplicate file content")
        win.geometry("850x400")
        text = tk.Text(win, wrap="word")
        scroll = ttk.Scrollbar(win, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll.pack(side="right", fill="y", padx=(0, 10), pady=10)
        if not groups:
            text.insert("end", "No duplicate-content groups were found in the scanned files.\n")
        else:
            for index, group in enumerate(groups, 1):
                text.insert("end", f"Group {index} — {len(group)} files, {group[0]['size_bytes']} bytes\n")
                text.insert("end", f"SHA-256: {group[0]['sha256']}\n")
                for rec in group:
                    text.insert("end", f"  • {rec['file_path']}\n")
                text.insert("end", "\n")
        text.configure(state="disabled")

    def export_csv(self):
        if not self.records:
            return
        filename = filedialog.asksaveasfilename(
            title="Save forensic report",
            defaultextension=".csv",
            filetypes=[("CSV report", "*.csv")],
            initialfile="usb_forensic_report.csv"
        )
        if not filename:
            return
        fields = [
            "file_path", "file_name", "size_bytes", "created_time",
            "modified_time", "sha256", "verification_status", "current_sha256", "error"
        ]
        try:
            with open(filename, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(self.records)
            messagebox.showinfo("Report saved", f"CSV report saved to:\n{filename}")
            self.status_var.set(f"Report saved: {filename}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except tk.TclError:
        pass
    ForensicsApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
