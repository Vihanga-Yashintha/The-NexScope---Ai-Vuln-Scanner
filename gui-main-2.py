#!/usr/bin/env python3
"""
gui-main.py

AI-Powered Vulnerability Scanner GUI (Combined & Enhanced Version)

Features:
- Thread-safe GUI updates (use safe_ui / window.after)
- CVE lookup: queries every discovered CPE, fallback to keyword search
- NVD API key settings: Save / Copy export / Export to file / Clear
- History saved to data/scan_history.json and data/scan_history.csv
- PDF Export with HTML template (WeasyPrint/wkhtmltopdf)
- Attach raw scan outputs to PDF reports
- Simulation fallbacks when scanner parser modules are missing
"""

import os
import sys
import json
import threading
import time
import subprocess
import tempfile
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from report_generator import generate_pdf_from_scan
from models.predict_api import predict_from_scan_features

# Tkinter / CustomTkinter UI
try:
    import customtkinter as ctk
    import tkinter as tk
    from tkinter import messagebox, filedialog, TclError
except Exception as e:
    print("This program requires tkinter and customtkinter:", e)
    raise

# Add src directory to path for scanner parser imports
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

# Import report generator
try:
    from report_generator import generate_pdf_from_scan
    PDF_EXPORT_AVAILABLE = True
except Exception as e:
    print(f"Warning: report_generator not found - PDF export disabled: {e}")
    PDF_EXPORT_AVAILABLE = False

# Import scanner parser functions if available, otherwise use simulation stubs
try:
    from nmap_parser import run_nmap, parse_nmap_xml
    from gobuster_parser import run_gobuster, parse_gobuster_output
    from nikto_parser import run_nikto, parse_nikto_output
    PARSERS_AVAILABLE = True
except Exception:
    print("Warning: scanner parser modules not found — using simulation functions.")
    PARSERS_AVAILABLE = False

    def run_nmap(target, nmap_arguments="-sV -O"):
        print(f"Simulating Nmap scan on {target} with {nmap_arguments}")
        os.makedirs("data", exist_ok=True)
        path = f"data/{target}_nmap.xml"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("<nmaprun></nmaprun>")
        print(f"Simulated: nmap {nmap_arguments} {target} -oX {path}")
        return path

    def parse_nmap_xml(xml_file):
        return {
            "service_cpe": "cpe:/a:vsftpd:vsftpd:2.3.4 cpe:/a:apache:http_server:2.2.8",
            "service_name": "Apache httpd",
            "service_version": "2.2.8",
            "total_open_ports": 3,
            "port_21_open": 1,
            "nikto_high_risk_findings": 0
        }

    def run_gobuster(target, gobuster_arguments="dir -w /usr/share/wordlists/dirb/common.txt"):
        print(f"Simulating Gobuster on {target} with {gobuster_arguments}")
        os.makedirs("data", exist_ok=True)
        path = f"data/{target}_gobuster.txt"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("/admin (Status: 200)\n")
        return path

    def parse_gobuster_output(output_file):
        return {"count_path_200": 1, "path_contains_admin": 1}

    def run_nikto(target, nikto_arguments=""):
        print(f"Simulating Nikto on {target}")
        os.makedirs("data", exist_ok=True)
        path = f"data/{target}_nikto.txt"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("Nikto simulated output\n")
        return path

    def parse_nikto_output(output_file):
        return {"nikto_high_risk_findings": 0, "nikto_found_xss": 0}

# Import CVE lookup helper if available
try:
    from utils.cve_lookup import get_cves_for_service, query_nvd_by_cpe, query_nvd_by_keyword
    CVE_LOOKUP_AVAILABLE = True
except Exception:
    get_cves_for_service = None
    query_nvd_by_cpe = None
    query_nvd_by_keyword = None
    CVE_LOOKUP_AVAILABLE = False
    print("Warning: utils.cve_lookup not found; CVE lookups will be disabled.")


# CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class AIVulnerabilityScanner:
    def __init__(self):
        # Window
        self.window = ctk.CTk()
        self.window.title("AI-Powered Vulnerability Scanner")
        self.window.geometry("1200x800")
        self.window.configure(fg_color="#1a1a1a")

        # State
        self.current_tab = "scan"
        self.scanning = False
        self.scan_progress = 0.0
        self.scan_progress_text = "Ready to scan"
        self.scan_output_buffer = ""
        self.scan_ai_text = "Run a scan to see AI vulnerability predictions..."
        self.model_name = "AI-Vuln-Scanner ML Model v1.0"
        self.export_note = None
        
        # Store last scan for export
        self.last_scan_data = None
        self.last_scan_raw_files = []

        # History files
        os.makedirs(os.path.join(ROOT_DIR, "data"), exist_ok=True)
        self.history_json = os.path.join(ROOT_DIR, "data", "scan_history.json")
        self.history_csv = os.path.join(ROOT_DIR, "data", "scan_history.csv")

        # Load history (CSV preferred)
        self.scan_history: List[Dict[str, Any]] = []
        try:
            if os.path.exists(self.history_csv):
                self.load_history_from_csv(self.history_csv)
            elif os.path.exists(self.history_json):
                with open(self.history_json, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                    if isinstance(loaded, list):
                        self.scan_history = loaded
        except Exception as e:
            print(f"[!] Failed to load history: {e}")
            self.scan_history = []

        # Cached tab frames
        self._tab_frames: Dict[str, ctk.CTkFrame] = {}

        # Widgets placeholders
        self.target_entry = None
        self.tool_vars = {}
        self.nmap_custom_entry = None
        self.nmap_preset_var = None
        self.wordlist_var = None
        self.custom_wordlist_entry = None
        self.nikto_tuning_var = None
        self.start_btn = None
        self.stop_btn = None
        self.export_btn = None
        self.progress_bar = None
        self.progress_label = None
        self.ai_result_label = None
        self.output_text = None
        self.status_label = None
        self.nvd_api_entry = None

        # Build UI
        self.setup_ui()
        self.show_tab("scan")

    # ---------------------------
    # Thread-safe UI helpers
    # ---------------------------
    def safe_ui(self, fn, *args, **kwargs):
        """Schedule a UI update to run on the main thread using Tk 'after'."""
        try:
            self.window.after(0, lambda: fn(*args, **kwargs))
        except Exception as e:
            try:
                fn(*args, **kwargs)
            except Exception:
                print("safe_ui failed:", e)

    def ui_append_output(self, text: str):
        """Append text to internal buffer and schedule widget insert on main thread."""
        self.scan_output_buffer += text

        def _append():
            try:
                if getattr(self, "output_text", None) and self.output_text.winfo_exists():
                    try:
                        self.output_text.insert(tk.END, text)
                        self.output_text.see(tk.END)
                    except TclError:
                        pass
            except Exception:
                pass

        try:
            self.window.after(1, _append)
        except Exception:
            pass

    def ui_set_progress(self, value: float, text: Optional[str] = None):
        """Set progress state and schedule UI update."""
        self.scan_progress = float(max(0.0, min(1.0, value)))
        if text is not None:
            self.scan_progress_text = text

        def _set():
            try:
                if getattr(self, "progress_bar", None) and self.progress_bar.winfo_exists():
                    try:
                        self.progress_bar.set(self.scan_progress)
                    except TclError:
                        pass
                if getattr(self, "progress_label", None) and self.progress_label.winfo_exists():
                    try:
                        self.progress_label.configure(text=self.scan_progress_text)
                    except TclError:
                        pass
            except Exception:
                pass

        try:
            self.window.after(1, _set)
        except Exception:
            pass

    # ---------------------------------------------------------------------
    # Prediction -> HTML helpers
    # ---------------------------------------------------------------------
    @staticmethod
    def _make_prediction_html(prediction: dict, scan_meta: dict | None = None) -> str:
        """
        Build and return an HTML string showing the prediction dict.
        prediction: dict returned by predict_from_scan_features(...)
        scan_meta: optional dict with scan metadata (e.g., target IP) to show in header
        """
        labels = prediction.get("labels", {})
        probs = prediction.get("label_probs", {})
        cvss = prediction.get("cvss_score", 0.0)

        # header with optional scan metadata
        header_html = ""
        if scan_meta:
            # show a few useful keys if present
            items = []
            for k in ("target", "ip", "host"):
                if scan_meta.get(k):
                    items.append(f"<strong>{k}:</strong> {scan_meta.get(k)}")
            if items:
                header_html = "<p>" + " — ".join(items) + "</p>"

        rows = ""
        # predictable column order from labels dict
        for k in labels:
            prob = probs.get(k, 0.0)
            rows += f"<tr><td style='padding:6px'>{k}</td><td style='text-align:center'>{labels[k]}</td><td style='text-align:right'>{prob:.4f}</td></tr>"

        html = f"""<!doctype html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>AI Vulnerability Prediction</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 18px; }}
        table {{ border-collapse: collapse; width: 80%; max-width: 900px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; }}
        th {{ background: #f4f4f4; text-align: left; }}
        h1 {{ margin-bottom: 6px; }}
    </style>
    </head>
    <body>
    <h1>AI Model Prediction</h1>
    {header_html}
    <h3>Predicted CVSS: {cvss:.2f}</h3>
    <table>
        <thead><tr><th>Label</th><th>Predicted</th><th>Probability</th></tr></thead>
        <tbody>
        {rows}
        </tbody>
    </table>
    <p style="margin-top:18px; font-size:0.9em; color:#666;">
        Note: probabilities shown are model estimates. Threshold used: 0.5 for binary predictions.
    </p>
    </body>
    </html>
    """
        return html


    @staticmethod
    def open_prediction_in_browser(html: str) -> None:
        """Write HTML to a temp file and open it in the default web browser."""
        fd, path = tempfile.mkstemp(suffix=".html", prefix="ai_prediction_")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        webbrowser.open(f"file://{path}")


    def ui_set_ai_text(self, text: str):
        """Update AI result label on main thread."""
        self.scan_ai_text = text

        def _set():
            try:
                if getattr(self, "ai_result_label", None) and self.ai_result_label.winfo_exists():
                    try:
                        self.ai_result_label.configure(text=text)
                    except TclError:
                        pass
            except Exception:
                pass

        try:
            self.window.after(1, _set)
        except Exception:
            pass

    # ---------------------------
    # Config / API key helpers
    # ---------------------------
    def _config_path(self):
        return os.path.join(ROOT_DIR, "data", "config.json")

    def load_api_key(self) -> str:
        """Load API key from config.json into environment and return it."""
        try:
            p = self._config_path()
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as fh:
                    cfg = json.load(fh)
                    key = cfg.get("NVD_API_KEY") or cfg.get("nvd_api_key") or ""
                    if key:
                        os.environ["NVD_API_KEY"] = key
                        return key
        except Exception as e:
            print(f"[!] Failed to load config: {e}")
        return ""

    def save_api_key(self, key: str):
        """Save API key to data/config.json and set environment variable."""
        try:
            p = self._config_path()
            cfg = {}
            if os.path.exists(p):
                try:
                    cfg = json.load(open(p, "r", encoding="utf-8"))
                except Exception:
                    cfg = {}
            cfg["NVD_API_KEY"] = key
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2)
            os.environ["NVD_API_KEY"] = key
            messagebox.showinfo("API Key", "NVD API key saved and set for this session.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save API key: {e}")

    def clear_api_key(self):
        """Clear saved API key and environment variable."""
        try:
            p = self._config_path()
            if os.path.exists(p):
                try:
                    cfg = json.load(open(p, "r", encoding="utf-8"))
                except Exception:
                    cfg = {}
                cfg.pop("NVD_API_KEY", None)
                with open(p, "w", encoding="utf-8") as fh:
                    json.dump(cfg, fh, indent=2)
            os.environ.pop("NVD_API_KEY", None)
            def _clear_entry():
                try:
                    if getattr(self, "nvd_api_entry", None):
                        self.nvd_api_entry.delete(0, tk.END)
                except Exception:
                    pass
            self.safe_ui(_clear_entry)
            messagebox.showinfo("API Key", "NVD API key cleared.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear API key: {e}")

    def copy_api_export_to_clipboard(self):
        """Copy export command to clipboard for easy shell usage."""
        try:
            key = os.environ.get("NVD_API_KEY") or ""
            if not key:
                messagebox.showwarning("No API Key", "No API key set. Save one first.")
                return
            export_cmd = f'export NVD_API_KEY="{key}"'
            self.window.clipboard_clear()
            self.window.clipboard_append(export_cmd)
            messagebox.showinfo("Copied", "Export command copied to clipboard. Paste into your shell to set the env var.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")

    def export_api_key_to_file(self):
        """Export a small shell script containing the export command for the API key."""
        try:
            key = os.environ.get("NVD_API_KEY") or ""
            if not key:
                messagebox.showwarning("No API Key", "No API key set. Save one first.")
                return
            fpath = filedialog.asksaveasfilename(defaultextension=".sh",
                                                 filetypes=[("Shell script", "*.sh"), ("All files", "*.*")],
                                                 title="Save export script")
            if not fpath:
                return
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(f'#!/bin/sh\nexport NVD_API_KEY="{key}"\n')
            try:
                os.chmod(fpath, 0o700)
            except Exception:
                pass
            messagebox.showinfo("Saved", f"Export script saved to:\n{fpath}\nYou can run: source {fpath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write file: {e}")

    # ---------------------------
    # UI setup
    # ---------------------------
    def setup_ui(self):
        self.main_frame = ctk.CTkFrame(self.window, fg_color="#2b2b2b", corner_radius=10)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.create_window_controls()

        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=2, pady=2)

        self.create_sidebar()

        self.main_content = ctk.CTkFrame(self.content_frame, fg_color="#1a1a1a")
        self.main_content.pack(side="right", fill="both", expand=True, padx=(0, 0))

    def create_window_controls(self):
        controls_frame = ctk.CTkFrame(self.main_frame, height=40, fg_color="#404040")
        controls_frame.pack(fill="x", padx=0, pady=0)
        controls_frame.pack_propagate(False)

        title_label = ctk.CTkLabel(controls_frame, text="🛡️ AI Vulnerability Scanner",
                                   text_color="#ffffff", font=("Arial", 12, "bold"))
        title_label.pack(side="left", padx=15, pady=10)

        self.status_label = ctk.CTkLabel(controls_frame, text="Ready", text_color="#00C853")
        self.status_label.pack(side="right", padx=15, pady=10)

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.content_frame, width=200, fg_color="#333333")
        self.sidebar.pack(side="left", fill="y", padx=(0, 2))
        self.sidebar.pack_propagate(False)

        menu_items = [
            ("scan", "Scan", "🔍"),
            ("history", "History", "📝"),
            ("settings", "Settings", "⚙️"),
            ("about", "About", "ℹ️")
        ]

        for item_id, label, icon in menu_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=f"{icon} {label}",
                anchor="w",
                height=40,
                fg_color="#333333" if item_id != self.current_tab else "#00C853",
                hover_color="#444444",
                command=lambda x=item_id: self.show_tab(x)
            )
            btn.pack(fill="x", padx=10, pady=2)

    # ---------------------------
    # Tab management
    # ---------------------------
    def show_tab(self, tab_name):
        self.current_tab = tab_name

        # create tab frame if not cached
        if tab_name not in self._tab_frames:
            frame = ctk.CTkFrame(self.main_content, fg_color="#1a1a1a")
            self._tab_frames[tab_name] = frame
            if tab_name == "scan":
                self.create_scanning_interface(container=frame)
            elif tab_name == "history":
                self.create_history_interface(container=frame)
            elif tab_name == "settings":
                self.create_settings_interface(container=frame)
            elif tab_name == "about":
                self.create_about_interface(container=frame)

        # show/hide frames
        for name, f in list(self._tab_frames.items()):
            try:
                if name == tab_name:
                    f.pack(side="right", fill="both", expand=True, padx=(0, 0))
                else:
                    f.pack_forget()
            except Exception:
                pass

        # update sidebar button colors
        for widget in self.sidebar.winfo_children():
            if isinstance(widget, ctk.CTkButton):
                if tab_name in widget.cget("text").lower():
                    widget.configure(fg_color="#00C853")
                else:
                    widget.configure(fg_color="#333333")

        # If switching to scan tab, rehydrate progress & output
        if tab_name == "scan":
            try:
                self.ui_set_progress(self.scan_progress, self.scan_progress_text)
                self.ui_set_ai_text(self.scan_ai_text)
                def _rehydrate_output():
                    try:
                        if getattr(self, "output_text", None) and self.output_text.winfo_exists():
                            self.output_text.delete("1.0", tk.END)
                            self.output_text.insert(tk.END, self.scan_output_buffer or "Tool output will appear here...\n")
                    except TclError:
                        pass
                self.window.after(1, _rehydrate_output)
            except Exception:
                pass

    # ---------------------------
    # Scanning UI (compact layout)
    # ---------------------------
    def create_scanning_interface(self, container=None):
        parent = container or self.main_content
        for w in parent.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass

        main_frame = ctk.CTkFrame(parent, fg_color="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)

        # Top row: Target + tools
        top_row = ctk.CTkFrame(main_frame, fg_color="transparent")
        top_row.pack(fill="x", pady=(5, 10))

        ctk.CTkLabel(top_row, text="Target:", font=("Arial", 14, "bold")).pack(side="left", padx=(0, 10))
        self.target_entry = ctk.CTkEntry(top_row, placeholder_text="Enter IP or domain...", width=400)
        self.target_entry.pack(side="left", padx=(0, 20))

        # Tool checkboxes inline
        self.tool_vars = {}
        tools = ["Nmap", "Gobuster", "Nikto"]
        for tool in tools:
            var = tk.BooleanVar()
            self.tool_vars[tool] = var
            ctk.CTkCheckBox(top_row, text=tool, variable=var, command=self.toggle_tool_options).pack(side="left", padx=(5, 10))

        # Options panel: collapsible sections
        options_panel = ctk.CTkFrame(main_frame, fg_color="#2a2a2a")
        options_panel.pack(fill="x", pady=(0, 10))

        def make_toggle_section(title, create_inner):
            frame = ctk.CTkFrame(options_panel, fg_color="#2a2a2a")
            header = ctk.CTkButton(frame, text=f"▸ {title}", anchor="w", fg_color="#333333")
            header.pack(fill="x", padx=5, pady=2)
            inner = ctk.CTkFrame(frame, fg_color="#2a2a2a")
            inner_visible = [False]

            def toggle():
                if inner_visible[0]:
                    inner.pack_forget()
                    header.configure(text=f"▸ {title}")
                else:
                    inner.pack(fill="x", padx=10, pady=(0, 5))
                    header.configure(text=f"▾ {title}")
                inner_visible[0] = not inner_visible[0]

            header.configure(command=toggle)
            create_inner(inner)
            frame.pack(fill="x", pady=3)
            return frame

        # Nmap options
        def create_nmap_options(inner):
            nmap_presets = [
                "Quick (-T4 -F)", "Service (-sV)", "OS (-O)",
                "Stealth (-sS)", "UDP (-sU)", "Full (-sS -sV -O --script vuln)"
            ]
            self.nmap_preset_var = ctk.StringVar(value="Service (-sV)")
            ctk.CTkComboBox(inner, variable=self.nmap_preset_var, values=nmap_presets,
                            command=self.on_nmap_preset_change).pack(fill="x", padx=5, pady=5)
            self.nmap_custom_entry = ctk.CTkEntry(inner, placeholder_text="Custom args", width=300)
            self.nmap_custom_entry.insert(0, "-sV -O")
            self.nmap_custom_entry.pack(fill="x", padx=5, pady=(0, 5))

        make_toggle_section("Nmap Options", create_nmap_options)

        # Gobuster options
        def create_gobuster(inner):
            self.wordlist_var = ctk.StringVar(value="/usr/share/wordlists/dirb/common.txt")
            ctk.CTkLabel(inner, text="Wordlist:").pack(anchor="w", padx=5)
            ctk.CTkEntry(inner, textvariable=self.wordlist_var).pack(fill="x", padx=5, pady=(0, 5))

        make_toggle_section("Gobuster Options", create_gobuster)

        # Nikto options
        def create_nikto(inner):
            ctk.CTkLabel(inner, text="Tuning:").pack(anchor="w", padx=5)
            self.nikto_tuning_var = ctk.StringVar(value="Default")
            ctk.CTkComboBox(inner, variable=self.nikto_tuning_var,
                            values=["Default", "All (0)", "Files (2)", "SQLi (7)", "RCE (9)"]).pack(fill="x", padx=5, pady=(0, 5))

        make_toggle_section("Nikto Options", create_nikto)

        # Control buttons row
        bottom_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        bottom_frame.pack(fill="x", pady=(10, 5))

        self.start_btn = ctk.CTkButton(bottom_frame, text="▶ Start", fg_color="#00C853",
                                       hover_color="#009624", width=100, command=self.start_scan)
        self.start_btn.pack(side="left", padx=(0, 10))
        self.stop_btn = ctk.CTkButton(bottom_frame, text="⏹ Stop", fg_color="#E53935",
                                      hover_color="#C62828", width=80, command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 10))
        
        # Export PDF button (existing)
        self.export_btn = ctk.CTkButton(bottom_frame, text="📄 Export PDF", width=100, fg_color="#2196F3",
                    hover_color="#1976D2", command=self.export_pdf)
        self.export_btn.pack(side="left", padx=(0,6))
        if not PDF_EXPORT_AVAILABLE:
            self.export_btn.configure(state="disabled", text="📄 Export (N/A)")

        # View HTML button (new) - opens HTML report in browser
        self.view_btn = ctk.CTkButton(bottom_frame, text="🔍 View", width=80, fg_color="#3A7EBF",
                    hover_color="#2B6AA0", command=self.view_scan_html)
        self.view_btn.pack(side="left", padx=(0,6))

        self.progress_bar = ctk.CTkProgressBar(bottom_frame, height=8, width=180)
        self.progress_bar.pack(side="left", padx=(10, 5))
        self.progress_bar.set(self.scan_progress)
        self.progress_label = ctk.CTkLabel(bottom_frame, text=self.scan_progress_text, text_color="#888888")
        self.progress_label.pack(side="left")

        # AI prediction display
        ai_frame = ctk.CTkFrame(main_frame, fg_color="#1a2b1a")
        ai_frame.pack(fill="x", pady=(5, 5))
        self.ai_result_label = ctk.CTkLabel(ai_frame, text=self.scan_ai_text,
                                            text_color="#00C853", anchor="w", justify="left", wraplength=1000)
        self.ai_result_label.pack(fill="x", padx=10, pady=8)

        # Output area
        ctk.CTkLabel(main_frame, text="Scan Output", font=("Arial", 14, "bold")).pack(anchor="w", pady=(5, 2))
        self.output_text = ctk.CTkTextbox(main_frame, height=180, font=("Courier", 11),
                                          fg_color="#0a0a0a", text_color="#00C853")
        self.output_text.pack(fill="both", expand=True, pady=(0, 10))
        self.output_text.insert("1.0", self.scan_output_buffer or "Tool output will appear here...\n")

    def toggle_tool_options(self):
        pass

    def on_nmap_preset_change(self, choice):
        preset_map = {
            "Quick (-T4 -F)": "-T4 -F",
            "Service (-sV)": "-sV",
            "OS (-O)": "-O",
            "Stealth (-sS)": "-sS",
            "UDP (-sU)": "-sU",
            "Full (-sS -sV -O --script vuln)": "-sS -sV -O --script vuln",
        }
        try:
            if choice in preset_map and self.nmap_custom_entry:
                self.nmap_custom_entry.delete(0, tk.END)
                self.nmap_custom_entry.insert(0, preset_map[choice])
        except Exception:
            pass

    # ---------------------------
    # Scanning control
    # ---------------------------
    def start_scan(self):
        target = self.target_entry.get().strip() if self.target_entry else ""
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        selected_tools = [tool for tool, var in self.tool_vars.items() if var.get()]
        if not selected_tools:
            messagebox.showerror("Error", "Please select at least one tool")
            return

        scan_options = {
            "nmap_args": (self.nmap_custom_entry.get().strip() if self.nmap_custom_entry else "-sV -O"),
            "gobuster_wordlist": (self.wordlist_var.get() if self.wordlist_var else "/usr/share/wordlists/dirb/common.txt"),
            "nikto_tuning": (self.nikto_tuning_var.get() if self.nikto_tuning_var else "Default")
        }

        self.scanning = True
        try:
            if self.start_btn: self.start_btn.configure(state="disabled")
            if self.stop_btn: self.stop_btn.configure(state="normal")
            if self.export_btn: self.export_btn.configure(state="disabled")
        except Exception:
            pass

        # reset buffers
        self.scan_output_buffer = ""
        self.last_scan_raw_files = []
        self.ui_set_progress(0.0, "Starting scan...")
        self.ui_set_ai_text("Scan in progress... AI analysis pending.")
        self.safe_ui(lambda: self.status_label.configure(text="Scanning..."))

        scan_thread = threading.Thread(target=self.run_scan, args=(target, selected_tools, scan_options))
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self, target, tools, scan_options):
        """Core scan runner; runs in background thread."""
        all_features: Dict[str, Any] = {}
        scan_successful = True
        features_filename = None
        cve_results = []
        raw_output_files = []

        try:
            # Nmap
            if "Nmap" in tools and self.scanning:
                self.ui_append_output(f"\n[+] Running Nmap with arguments: {scan_options['nmap_args']}\n")
                self.ui_set_progress(0.05, "Running Nmap...")
                nmap_args = scan_options['nmap_args'] or "-sV -O"
                xml_file = run_nmap(target, nmap_args)
                if xml_file:
                    raw_output_files.append(xml_file)
                if xml_file and self.scanning:
                    nmap_features = parse_nmap_xml(xml_file)
                    if nmap_features is None:
                        self.ui_append_output("[!] Failed to parse Nmap XML results.\n")
                        scan_successful = False
                    else:
                        all_features.update(nmap_features)
                        vuln_text = f"[+] Nmap completed. Found {nmap_features.get('total_open_ports', 0)} open ports.\n"
                        if nmap_features.get('critical_vuln_count', 0) > 0:
                            vuln_text += f"[!] CRITICAL: {nmap_features.get('critical_vuln_count', 0)} exploitable vulnerabilities found!\n"
                        if nmap_features.get('high_vuln_count', 0) > 0:
                            vuln_text += f"[!] HIGH: {nmap_features.get('high_vuln_count', 0)} high-risk vulnerabilities\n"
                        self.ui_append_output(vuln_text)
                else:
                    self.ui_append_output("[!] Nmap scan failed or was cancelled.\n")
                    scan_successful = False
                self.ui_set_progress(0.25, "Nmap finished")

            if not scan_successful:
                self.ui_append_output("\n[!] Skipping remaining tools due to Nmap failure.\n")
                return

            # Gobuster
            if "Gobuster" in tools and self.scanning and scan_successful:
                self.ui_append_output(f"\n[+] Running Gobuster with wordlist: {scan_options['gobuster_wordlist']}\n")
                self.ui_set_progress(0.45, "Running Gobuster...")
                gobuster_cmd = f"dir -w {scan_options['gobuster_wordlist']}"
                output_file = run_gobuster(target, gobuster_cmd)
                if output_file:
                    raw_output_files.append(output_file)
                if output_file and self.scanning:
                    gobuster_features = parse_gobuster_output(output_file)
                    if gobuster_features is not None:
                        all_features.update(gobuster_features)
                        self.ui_append_output(f"[+] Gobuster completed. Found {gobuster_features.get('count_path_200', 0)} accessible paths.\n")
                    else:
                        self.ui_append_output("[!] Failed to parse Gobuster results.\n")
                else:
                    self.ui_append_output("[!] Gobuster scan failed or was cancelled.\n")
                self.ui_set_progress(0.6, "Gobuster finished")

            # Nikto
            if "Nikto" in tools and self.scanning and scan_successful:
                self.ui_append_output(f"\n[+] Running Nikto with tuning: {scan_options['nikto_tuning']}\n")
                self.ui_set_progress(0.75, "Running Nikto...")
                output_file = run_nikto(target)
                if output_file:
                    raw_output_files.append(output_file)
                if output_file and self.scanning:
                    nikto_features = parse_nikto_output(output_file)
                    if nikto_features is not None:
                        all_features.update(nikto_features)
                        self.ui_append_output(f"[+] Nikto completed. Found {nikto_features.get('nikto_high_risk_findings', 0)} high-risk findings.\n")
                    else:
                        self.ui_append_output("[!] Failed to parse Nikto results.\n")
                else:
                    self.ui_append_output("[!] Nikto scan failed or was cancelled.\n")
                self.ui_set_progress(0.85, "Nikto finished")

            # CVE Lookup
            try:
                cve_results = []
                seen_cve_ids = set()
                if CVE_LOOKUP_AVAILABLE and get_cves_for_service:
                    self.ui_append_output(f"[DEBUG] all_features keys: {list(all_features.keys())}\n")

                    # Collect CPE candidates
                    cpes = []
                    sc = all_features.get("service_cpe") or all_features.get("service_cpes") or ""
                    if isinstance(sc, str) and sc.strip():
                        toks = sc.replace(",", " ").split()
                        for t in toks:
                            if isinstance(t, str) and t.strip().startswith("cpe:"):
                                cpes.append(t.strip())
                    if isinstance(all_features.get("service_cpes"), (list, tuple)):
                        for p in all_features.get("service_cpes"):
                            if isinstance(p, str) and p.strip().startswith("cpe:"):
                                cpes.append(p.strip())
                    if isinstance(all_features.get("services"), (list, tuple)):
                        for serv in all_features.get("services"):
                            if isinstance(serv, dict):
                                if serv.get("cpe"):
                                    if isinstance(serv.get("cpe"), str):
                                        if serv.get("cpe").strip().startswith("cpe:"):
                                            cpes.append(serv.get("cpe").strip())
                                    elif isinstance(serv.get("cpe"), (list, tuple)):
                                        for p in serv.get("cpe"):
                                            if isinstance(p, str) and p.strip().startswith("cpe:"):
                                                cpes.append(p.strip())
                                if serv.get("cpe23"):
                                    p = serv.get("cpe23")
                                    if isinstance(p, str) and p.startswith("cpe:"):
                                        cpes.append(p.strip())

                    # dedupe CPEs
                    cpes = [c.strip() for c in cpes if c and c.strip().startswith("cpe:")]
                    seen = set()
                    uniq_cpes = []
                    for c in cpes:
                        if c not in seen:
                            uniq_cpes.append(c)
                            seen.add(c)
                    cpes = uniq_cpes

                    if cpes:
                        self.ui_append_output(f"[+] Detected {len(cpes)} CPE(s), querying NVD for each...\n")
                        for cpe in cpes:
                            try:
                                self.ui_append_output(f"[DEBUG] Querying NVD for CPE: {cpe}\n")
                                res = get_cves_for_service(cpe, None, api_key=os.environ.get("NVD_API_KEY"))
                                found = []
                                if isinstance(res, dict):
                                    found = res.get("cves", []) or []
                                elif isinstance(res, list):
                                    found = res
                                for item in found:
                                    cve_id = item.get("cve_id") or item.get("id") or item.get("CVE")
                                    if cve_id and cve_id not in seen_cve_ids:
                                        seen_cve_ids.add(cve_id)
                                        cve_results.append(item)
                                        self.ui_append_output(f"[+] {cve_id}  CVSS: {item.get('cvss_v3')}  { (item.get('summary') or '')[:180] }\n")
                            except Exception as e:
                                self.ui_append_output(f"[!] Error querying NVD for {cpe}: {e}\n")
                    else:
                        self.ui_append_output("[DEBUG] No CPEs found in parser output — will try keyword fallback\n")

                    # fallback keyword lookups
                    if not cve_results:
                        self.ui_append_output("[DEBUG] Trying keyword/service fallback lookups...\n")
                        candidates = []
                        for key in ("service_name", "service", "product", "service_product"):
                            if all_features.get(key):
                                candidates.append(str(all_features.get(key)))
                        top_name = all_features.get("service_name") or all_features.get("product") or ""
                        top_ver = all_features.get("service_version") or all_features.get("version") or ""
                        if top_name:
                            candidates.append(f"{top_name} {top_ver}".strip())
                        if isinstance(all_features.get("services"), (list, tuple)):
                            for serv in all_features.get("services"):
                                if isinstance(serv, dict):
                                    name = serv.get("product") or serv.get("service") or serv.get("name")
                                    ver = serv.get("version") or serv.get("ver")
                                    if name:
                                        candidates.append(f"{name} {ver or ''}".strip())
                        cand_unique = []
                        for c in candidates:
                            if c and c not in cand_unique:
                                cand_unique.append(c)

                        for cand in cand_unique:
                            try:
                                self.ui_append_output(f"[DEBUG] Keyword search: '{cand}'\n")
                                res = get_cves_for_service(cand, None, api_key=os.environ.get("NVD_API_KEY"))
                                found = []
                                if isinstance(res, dict):
                                    found = res.get("cves", []) or []
                                elif isinstance(res, list):
                                    found = res
                                for item in found:
                                    cve_id = item.get("cve_id") or item.get("id")
                                    if cve_id and cve_id not in seen_cve_ids:
                                        seen_cve_ids.add(cve_id)
                                        cve_results.append(item)
                                        self.ui_append_output(f"[+] {cve_id}  CVSS: {item.get('cvss_v3')}  { (item.get('summary') or '')[:180] }\n")
                            except Exception as e:
                                self.ui_append_output(f"[!] Keyword lookup error for '{cand}': {e}\n")
                else:
                    self.ui_append_output("[DEBUG] CVE lookup helper not available (utils.cve_lookup missing)\n")
            except Exception as e:
                self.ui_append_output(f"[!] CVE lookup fatal error: {e}\n")

            # AI PREDICTION
            if self.scanning and scan_successful:
                self.ui_append_output("\n[+] Running AI vulnerability analysis...\n")
                self.ui_set_progress(0.9, "AI Analysis...")
                ai_prediction, cvss_score, prediction_dict = self.predict_vulnerabilities(all_features)
                self.ui_set_ai_text(ai_prediction)
                self.ui_append_output(f"[+] AI analysis completed: {ai_prediction}\n")

                if not cve_results:
                    self.ui_append_output("\n[+] No CVE matches found (NVD/OSV)\n")
                else:
                    self.ui_append_output(f"\n[+] Found {len(cve_results)} unique CVE(s) (top shown above)\n")

                # Save feature vector to JSON file
                try:
                    os.makedirs(os.path.join(ROOT_DIR, "data"), exist_ok=True)
                    features_filename = os.path.join(ROOT_DIR, "data", f"{target}_features.json")
                    with open(features_filename, "w", encoding="utf-8") as f:
                        json.dump(all_features, f, indent=4)
                    self.ui_append_output(f"[+] Features saved to: {features_filename}\n")
                except Exception as e:
                    self.ui_append_output(f"[!] Failed to save features file: {str(e)}\n")

                self.ui_append_output("Scan and analysis completed successfully.\n")

                new_scan = {
                    "target": target,
                    "status": "Completed",
                    "tools": tools,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "prediction": ai_prediction,
                    "features": all_features,
                    "features_file": features_filename,
                    "cves": cve_results,
                    "label_probs": prediction_dict.get("label_probs", {}),  # ML model probabilities
                    "labels": prediction_dict.get("labels", {}),  # ML model predictions
                    "cvss_score": cvss_score,  # CVSS from model
                    "report_id": f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                }
                
                # Store for PDF export
                self.last_scan_data = new_scan
                self.last_scan_raw_files = raw_output_files
                
                # Add history on main thread to avoid UI race
                self.safe_ui(lambda: self.add_scan_history(new_scan))

        except Exception as e:
            self.ui_append_output(f"\n[!] Error during scan: {str(e)}\n")
            import traceback
            self.ui_append_output(f"Detailed error: {traceback.format_exc()}\n")
            scan_successful = False

        finally:
            self.scanning = False
            # Re-enable/disable buttons on main thread
            def _finalize_ui():
                try:
                    if self.start_btn: self.start_btn.configure(state="normal")
                    if self.stop_btn: self.stop_btn.configure(state="disabled")
                    if self.export_btn and PDF_EXPORT_AVAILABLE: 
                        self.export_btn.configure(state="normal")
                    if self.status_label: self.status_label.configure(text="Ready")
                    try:
                        if self.progress_bar:
                            self.progress_bar.set(1.0)
                    except Exception:
                        pass
                    if self.progress_label:
                        self.progress_label.configure(text="Scan completed!")
                except Exception:
                    pass
            self.safe_ui(_finalize_ui)

    def predict_vulnerabilities(self, features: Dict[str, Any]):
        """
        Call ML model for vulnerability prediction.
        Returns: (prediction_text: str, cvss_score: float, prediction_dict: dict)
        
        prediction_dict contains:
          - labels: {label_name: 0/1}
          - label_probs: {label_name: probability}
          - cvss_score: float
        """
        try:
            # Try to use ML model
            if predict_from_scan_features is None:
                raise RuntimeError("Prediction function not available")
            
            models_dir = os.path.join(ROOT_DIR, "models")
            if not os.path.exists(models_dir):
                raise FileNotFoundError(f"Models directory not found: {models_dir}")
            
            prediction_dict = predict_from_scan_features(features, models_dir=models_dir)
            
            # Extract results
            labels = prediction_dict.get("labels", {})
            probs = prediction_dict.get("label_probs", {})
            cvss_score = prediction_dict.get("cvss_score", 0.0)
            
            # Generate prediction text
            detected_vulns = [label for label, pred in labels.items() if pred == 1]
            high_prob_vulns = [label for label, prob in probs.items() if prob >= 0.7]
            
            if detected_vulns:
                vuln_list = ", ".join([v.replace("vuln_", "") for v in detected_vulns])
                prediction_text = f"🔴 ML Model Prediction: Vulnerabilities detected - {vuln_list} (CVSS: {cvss_score:.1f})"
            elif high_prob_vulns:
                vuln_list = ", ".join([v.replace("vuln_", "") for v in high_prob_vulns])
                prediction_text = f"🟡 ML Model Alert: High probability of {vuln_list} (CVSS: {cvss_score:.1f})"
            else:
                prediction_text = f"🟢 ML Model Analysis: Low risk profile detected (CVSS: {cvss_score:.1f})"
            
            return prediction_text, cvss_score, prediction_dict
            
        except Exception as e:
            # Fallback to heuristic if ML model fails
            self.ui_append_output(f"[!] ML model prediction failed: {e}. Using fallback heuristic.\n")
            
            high_risk_indicators = 0
            if features.get('port_21_open', 0) == 1:
                high_risk_indicators += 1
            if features.get('port_445_open', 0) == 1:
                high_risk_indicators += 1
            if features.get('version_contains_old', 0) == 1:
                high_risk_indicators += 2
            if features.get('nikto_high_risk_findings', 0) > 0:
                high_risk_indicators += features['nikto_high_risk_findings']
            if features.get('path_contains_admin', 0) == 1:
                high_risk_indicators += 1

            if high_risk_indicators >= 3:
                prediction_text = "🔴 HIGH RISK: Multiple vulnerability indicators detected"
                cvss_score = 8.5
            elif high_risk_indicators >= 1:
                prediction_text = "🟡 MEDIUM RISK: Some vulnerability indicators found"
                cvss_score = 5.2
            else:
                prediction_text = "🟢 LOW RISK: No significant vulnerabilities detected"
                cvss_score = 2.1
            
            # Return fallback dict
            fallback_dict = {
                "labels": {},
                "label_probs": {},
                "cvss_score": cvss_score,
                "prediction_type": "heuristic"
            }
            return prediction_text, cvss_score, fallback_dict

    def stop_scan(self):
        self.scanning = False
        self.ui_append_output("\nScan interrupted by user.\n")
        self.ui_set_ai_text("Scan cancelled. No AI analysis performed.")
        self.safe_ui(lambda: (self.start_btn.configure(state="normal") if self.start_btn else None))
        self.safe_ui(lambda: (self.stop_btn.configure(state="disabled") if self.stop_btn else None))
        if self.export_btn and PDF_EXPORT_AVAILABLE:
            self.safe_ui(lambda: self.export_btn.configure(state="normal"))
        self.ui_set_progress(self.scan_progress, "Scan cancelled")
        self.safe_ui(lambda: self.status_label.configure(text="Ready"))

    def export_pdf(self):
        """Export scan results to PDF using HTML template."""
        if not PDF_EXPORT_AVAILABLE:
            messagebox.showerror("Export Error", "PDF export not available. Please install report_generator module.")
            return
            
        scan_data = self.last_scan_data
        if not scan_data:
            if self.scan_history:
                scan_data = self.scan_history[0]
            else:
                messagebox.showwarning("No Data", "No scan data available to export. Run a scan first.")
                return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            title=f"Export report for {scan_data.get('target', 'Unknown')}"
        )
        
        if not file_path:
            return

        # Disable export button during generation
        if self.export_btn:
            self.safe_ui(lambda: self.export_btn.configure(state="disabled", text="📄 Generating..."))
        self.safe_ui(lambda: self.status_label.configure(text="Exporting PDF..."))
        self.ui_append_output(f"\n[+] Generating PDF report: {file_path}\n")

        def _export_worker():
            try:
                # Prepare raw outputs for attachment
                raw_outputs = []
                for fpath in self.last_scan_raw_files:
                    if os.path.exists(fpath):
                        fname = os.path.basename(fpath)
                        ext = os.path.splitext(fname)[1].lower()
                        
                        if ext in ['.xml', '.txt', '.log']:
                            # Text file
                            try:
                                with open(fpath, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                raw_outputs.append({
                                    "type": "text",
                                    "name": fname,
                                    "label": fname,
                                    "source": fpath,
                                    "content": content
                                })
                            except Exception as read_err:
                                self.ui_append_output(f"[!] Failed to read {fname}: {read_err}\n")
                        elif ext in ['.png', '.jpg', '.jpeg']:
                            # Image file
                            try:
                                import base64
                                with open(fpath, 'rb') as f:
                                    img_data = base64.b64encode(f.read()).decode('utf-8')
                                raw_outputs.append({
                                    "type": "image",
                                    "name": fname,
                                    "label": fname,
                                    "source": fpath,
                                    "content": img_data,
                                    "img_format": ext[1:]  # png, jpg, jpeg
                                })
                            except Exception as img_err:
                                self.ui_append_output(f"[!] Failed to encode image {fname}: {img_err}\n")
                
                # Add raw_outputs to scan data
                if raw_outputs:
                    scan_data["raw_outputs"] = raw_outputs

                # Generate PDF
                generate_pdf_from_scan(
                    scan_data,
                    file_path,
                    method="weasyprint",  # or "wkhtmltopdf"
                    model_name=self.model_name,
                    note=self.export_note
                )

                def _success():
                    if self.export_btn:
                        self.export_btn.configure(state="normal", text="📄 Export PDF")
                    self.status_label.configure(text="Ready")
                    self.ui_append_output(f"[+] PDF exported successfully: {file_path}\n")
                    messagebox.showinfo("Export Complete", f"PDF report exported to:\n{file_path}")

                self.safe_ui(_success)

            except Exception as export_error:
                import traceback
                tb_str = traceback.format_exc()
                error_msg = str(export_error)

                def _failure():
                    if self.export_btn:
                        self.export_btn.configure(state="normal", text="📄 Export PDF")
                    self.status_label.configure(text="Ready")
                    self.ui_append_output(f"[!] PDF export failed: {error_msg}\n{tb_str}\n")
                    messagebox.showerror("Export Failed", f"Failed to export PDF:\n{error_msg}")

                self.safe_ui(_failure)

        export_thread = threading.Thread(target=_export_worker, daemon=True)
        export_thread.start()

    def view_scan_html(self, scan: dict = None, attach_files: list = None):
        """
        Render the selected scan to a temporary HTML file and open in the default browser.
        If scan is None, uses last_scan_data or most recent history entry.
        Runs rendering in a background thread (non-blocking).
        """
        if scan is None:
            scan = self.last_scan_data or (self.scan_history[0] if self.scan_history else None)
        if not scan:
            messagebox.showwarning("No scan", "No scan data available to view. Run a scan first.")
            return

        # optionally prepare raw outputs similar to export_pdf (we reuse last_scan_raw_files)
        raw_outputs = []
        for fpath in getattr(self, "last_scan_raw_files", []):
            if os.path.exists(fpath):
                fname = os.path.basename(fpath)
                ext = os.path.splitext(fname)[1].lower()
                if ext in ['.xml', '.txt', '.log']:
                    try:
                        with open(fpath, 'r', encoding='utf-8') as f:
                            content = f.read()
                        raw_outputs.append({
                            "type": "text", "name": fname, "label": fname, "source": fpath, "content": content
                        })
                    except Exception:
                        pass
                elif ext in ['.png', '.jpg', '.jpeg']:
                    try:
                        import base64
                        with open(fpath, 'rb') as f:
                            img_data = base64.b64encode(f.read()).decode('utf-8')
                        raw_outputs.append({
                            "type": "image", "name": fname, "label": fname, "source": fpath, "content": img_data, "img_format": ext[1:]
                        })
                    except Exception:
                        pass
                else:
                    raw_outputs.append({"type": "link", "name": fname, "label": fname, "href": fpath})

        if raw_outputs:
            scan_to_render = dict(scan)
            scan_to_render["raw_outputs"] = raw_outputs
        else:
            scan_to_render = scan

        # UI feedback
        try:
            if getattr(self, "status_label", None):
                self.safe_ui(lambda: self.status_label.configure(text="Rendering HTML preview..."))
        except Exception:
            pass

        def _worker():
            try:
                # Use generate_html_from_scan from report_generator to render html
                from report_generator import generate_html_from_scan
                # create a temp file
                tmp_fd, tmp_path = tempfile.mkstemp(prefix="scan_preview_", suffix=".html")
                os.close(tmp_fd)
                html_path = generate_html_from_scan(scan_to_render, out_path=tmp_path,
                                                model_name=self.model_name, note=self.export_note,
                                                attach_files=None, embed_chart=True)
                # open in browser
                webbrowser.open("file://" + os.path.abspath(html_path))
                # restore status
                self.safe_ui(lambda: self.status_label.configure(text="Ready"))
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                def _fail():
                    self.ui_append_output(f"[!] Failed to render HTML preview: {e}\n{tb}\n")
                    if getattr(self, "status_label", None):
                        self.status_label.configure(text="Ready")
                    messagebox.showerror("Preview failed", f"Failed to render HTML preview:\n{e}")
                self.safe_ui(_fail)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    # ---------------------------
    # History persistence & UI
    # ---------------------------
    def save_history_file(self):
        """Persist history as JSON and CSV."""
        try:
            with open(self.history_json, "w", encoding="utf-8") as fh:
                json.dump(self.scan_history, fh, indent=2)
            self._write_history_csv(self.history_csv, self.scan_history)
        except Exception as e:
            print(f"[!] Failed to save history: {e}")

    def add_scan_history(self, new_scan: dict):
        """Insert new scan into history and persist. Avoid exact duplicates."""
        try:
            key = (new_scan.get("target"), new_scan.get("date"))
            for s in self.scan_history:
                if (s.get("target"), s.get("date")) == key:
                    s.update(new_scan)
                    self.save_history_file()
                    def _refresh():
                        if "history" in self._tab_frames:
                            try:
                                f = self._tab_frames.get("history")
                                if f and f.winfo_exists():
                                    f.destroy()
                            except Exception:
                                pass
                            self._tab_frames.pop("history", None)
                        self.show_tab("history")
                    try:
                        self.window.after(20, _refresh)
                    except Exception:
                        pass
                    return
            self.scan_history.insert(0, new_scan)
            self.save_history_file()
            def _refresh2():
                if "history" in self._tab_frames:
                    try:
                        f = self._tab_frames.get("history")
                        if f and f.winfo_exists():
                            f.destroy()
                    except Exception:
                        pass
                    self._tab_frames.pop("history", None)
                self.show_tab("history")
            try:
                self.window.after(20, _refresh2)
            except Exception:
                pass
        except Exception as e:
            print(f"[!] add_scan_history error: {e}")

    def _write_history_csv(self, path, rows):
        """Write history rows to CSV (tools semicolon-separated)."""
        import csv
        if not rows:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["target", "status", "tools", "date", "prediction", "features_file"])
            return
        fieldnames = ["target", "status", "tools", "date", "prediction", "features_file"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                out = {k: r.get(k, "") for k in fieldnames}
                tools = r.get("tools", [])
                if isinstance(tools, (list, tuple)):
                    out["tools"] = ";".join(map(str, tools))
                else:
                    out["tools"] = str(tools)
                writer.writerow(out)

    def load_history_from_csv(self, path):
        """Load history CSV into self.scan_history."""
        import csv
        try:
            rows = []
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for r in reader:
                    tools = r.get("tools", "")
                    tools_list = [t.strip() for t in tools.split(";") if t.strip()] if tools else []
                    entry = {
                        "target": r.get("target", ""),
                        "status": r.get("status", ""),
                        "tools": tools_list,
                        "date": r.get("date", ""),
                        "prediction": r.get("prediction", ""),
                        "features_file": r.get("features_file", "")
                    }
                    rows.append(entry)
            self.scan_history = rows
            with open(self.history_json, "w", encoding="utf-8") as fh:
                json.dump(self.scan_history, fh, indent=2)
        except Exception as e:
            print(f"[!] Failed to load history CSV: {e}")

    def export_history_csv(self, path=None):
        import tkinter.filedialog as fd
        if path is None:
            path = fd.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
            if not path:
                return
        try:
            self._write_history_csv(path, self.scan_history)
            messagebox.showinfo("Export", f"History exported to CSV:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def export_history_xml(self, path=None):
        import tkinter.filedialog as fd
        import xml.etree.ElementTree as ET
        if path is None:
            path = fd.asksaveasfilename(defaultextension=".xml", filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
            if not path:
                return
        root = ET.Element("history")
        for r in self.scan_history:
            e = ET.SubElement(root, "scan")
            for k in ("target", "status", "date", "prediction", "features_file"):
                v = r.get(k, "")
                sub = ET.SubElement(e, k)
                sub.text = str(v)
            tools_node = ET.SubElement(e, "tools")
            for t in r.get("tools", []):
                tnode = ET.SubElement(tools_node, "tool")
                tnode.text = str(t)
            if r.get("cves"):
                cves_node = ET.SubElement(e, "cves")
                for cv in r.get("cves", [])[:50]:
                    cvn = ET.SubElement(cves_node, "cve")
                    cvn_id = ET.SubElement(cvn, "id")
                    cvn_id.text = str(cv.get("cve_id") or cv.get("id") or "")
                    summary = ET.SubElement(cvn, "summary")
                    summary.text = str(cv.get("summary") or "")[:500]
        tree = ET.ElementTree(root)
        try:
            tree.write(path, encoding="utf-8", xml_declaration=True)
            messagebox.showinfo("Export", f"History exported to XML:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def import_history_csv(self):
        import tkinter.filedialog as fd
        p = fd.askopenfilename(title="Import history CSV", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not p:
            return
        try:
            import csv
            new_rows = []
            with open(p, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for r in reader:
                    tools = r.get("tools", "")
                    tools_list = [t.strip() for t in tools.split(";") if t.strip()] if tools else []
                    entry = {
                        "target": r.get("target", ""),
                        "status": r.get("status", ""),
                        "tools": tools_list,
                        "date": r.get("date", ""),
                        "prediction": r.get("prediction", ""),
                        "features_file": r.get("features_file", "")
                    }
                    new_rows.append(entry)
            existing_keys = {(s.get("target"), s.get("date")) for s in self.scan_history}
            added = 0
            for nr in new_rows:
                key = (nr.get("target"), nr.get("date"))
                if key not in existing_keys:
                    self.scan_history.insert(0, nr)
                    existing_keys.add(key)
                    added += 1
            if added > 0:
                self.save_history_file()
            messagebox.showinfo("Import", f"Imported {len(new_rows)} rows ({added} added).")
            try:
                if "history" in self._tab_frames:
                    f = self._tab_frames.get("history")
                    if f and f.winfo_exists():
                        f.destroy()
                    self._tab_frames.pop("history", None)
            except Exception:
                pass
            self.show_tab("history")
        except Exception as e:
            messagebox.showerror("Import failed", str(e))

    def create_history_interface(self, container=None):
        parent = container or self.main_content
        for w in parent.winfo_children():
            try: w.destroy()
            except Exception: pass

        scroll_frame = ctk.CTkScrollableFrame(parent)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        header_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(header_frame, text="Scan History", font=("Arial", 24, "bold")).pack(side="left")

        controls = ctk.CTkFrame(header_frame, fg_color="transparent")
        controls.pack(side="right")
        ctk.CTkButton(controls, text="Import CSV", width=90, command=self.import_history_csv).pack(side="left", padx=(0,6))
        ctk.CTkButton(controls, text="Export CSV", width=90, command=lambda: self.export_history_csv()).pack(side="left", padx=(0,6))
        ctk.CTkButton(controls, text="Export XML", width=90, command=lambda: self.export_history_xml()).pack(side="left")

        if not self.scan_history:
            ctk.CTkLabel(scroll_frame, text="No scan history yet.", text_color="#888888").pack(anchor="w", pady=20)
            return

        for scan in self.scan_history:
            history_frame = ctk.CTkFrame(scroll_frame)
            history_frame.pack(fill="x", pady=5)

            info_frame = ctk.CTkFrame(history_frame, fg_color="transparent")
            info_frame.pack(fill="x", padx=15, pady=10)

            ctk.CTkLabel(info_frame, text=scan.get("target", "unknown"), font=("Arial", 14, "bold")).pack(side="left")

            status_color = "#00C853" if scan.get("status") == "Completed" else "#2196F3"
            ctk.CTkLabel(info_frame, text=scan.get("status", ""), text_color=status_color).pack(side="right")

            details_frame = ctk.CTkFrame(history_frame, fg_color="transparent")
            details_frame.pack(fill="x", padx=15, pady=(0, 5))

            tools_text = f"{', '.join(scan.get('tools', []))} - {scan.get('date', '')}"
            ctk.CTkLabel(details_frame, text=tools_text, text_color="#888888").pack(side="left")

            if "prediction" in scan:
                prediction_color = "#E53935" if "HIGH" in scan["prediction"].upper() else "#FFA726" if "MEDIUM" in scan["prediction"].upper() else "#00C853"
                ctk.CTkLabel(details_frame, text=scan["prediction"], text_color=prediction_color).pack(side="left", padx=(10, 0))

            btn_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
            btn_frame.pack(side="right")
            # View button: open HTML preview in browser using the same renderer
            view_btn = ctk.CTkButton(btn_frame,text="View",width=60,fg_color="#3A7EBF",hover_color="#2B6AA0",command=lambda s=scan: self.view_scan_html(s))
            view_btn.pack(side="left", padx=(0, 5))

            if PDF_EXPORT_AVAILABLE:
                export_btn = ctk.CTkButton(btn_frame, text="Export", width=60, fg_color="#2196F3",                                           
                                           command=lambda s=scan: self._export_history_item(s))
                export_btn.pack(side="left", padx=(0, 5))
            
            del_btn = ctk.CTkButton(btn_frame, text="Delete", width=60, fg_color="#E53935", hover_color="#C62828",
                                    command=lambda s=scan: self._delete_history_item_by_obj(s))
            del_btn.pack(side="left")

            btn_frame.configure(width=240)
            btn_frame.pack_propagate(False)
            btn_frame.pack(side="right", anchor="e", padx=(8,0))

            # Create buttons (explicit widths) and pack them right-to-left so they remain visible
            view_btn = ctk.CTkButton(btn_frame, text="View", width=60, fg_color="#3A7EBF", hover_color="#2B6AA0",
                                        command=lambda s=scan: self.view_scan_html(s))
            del_btn = ctk.CTkButton(btn_frame, text="Delete", width=60, fg_color="#E53935", hover_color="#C62828",
                                        command=lambda s=scan: self._delete_history_item_by_obj(s))
            
            # Pack delete to the far right, then view to its left; export (optional) in middle
            del_btn.pack(side="right", padx=(5,0))

            if PDF_EXPORT_AVAILABLE:
                export_btn = ctk.CTkButton(btn_frame, text="Export", width=60, fg_color="#2196F3",
                                            command=lambda s=scan: self._export_history_item(s))
                export_btn.pack(side="right", padx=(0,5))

                view_btn.pack(side="right", padx=(0,5))

            # Debug/log when buttons are created (helps diagnose invisible widget issues)
            try:
                self.ui_append_output(f"[DEBUG] History buttons created for: {scan.get('target','unknown')}\n")
            except Exception:
                print(f"[DEBUG] History buttons created for: {scan.get('target','unknown')}")
            # ...existing code...

        bottom_bar = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        bottom_bar.pack(fill="x", pady=(10,0))
        ctk.CTkButton(bottom_bar, text="🗑 Clear All History", fg_color="#E53935", hover_color="#C62828", command=self._clear_all_history).pack(side="right")

    def _view_scan_details(self, scan):
        win = ctk.CTkToplevel(self.window)
        win.title(f"Details: {scan.get('target')}")
        win.geometry("900x600")
        txt = ctk.CTkTextbox(win, width=880, height=550)
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.insert("1.0", f"Target: {scan.get('target')}\nDate: {scan.get('date')}\nTools: {', '.join(scan.get('tools', []))}\nPrediction: {scan.get('prediction')}\nFeatures file: {scan.get('features_file')}\n\n")
        cves = scan.get("cves", [])
        if not cves:
            txt.insert("end", "No CVEs recorded for this scan.\n")
            return
        txt.insert("end", f"Found {len(cves)} CVE(s):\n\n")
        for c in cves:
            cid = c.get("cve_id") or c.get("id") or c.get("CVE") or ""
            txt.insert("end", f"{cid}  CVSSv3: {c.get('cvss_v3')}\n")
            txt.insert("end", f"{c.get('summary')}\n")
            refs = c.get("references") or []
            if refs:
                txt.insert("end", f"{refs[0]}\n")
            txt.insert("end", "-"*80 + "\n")

    def view_scan_and_predict(self, scan_json_path: str | None = None, scan_dict: dict | None = None):
        """
        Load scan data from `scan_json_path` or use provided scan_dict, run prediction,
        and open the HTML report in a browser. Runs in background thread so UI stays responsive.
        """
        def job():
            try:
                # Load scan features
                if scan_dict is not None:
                    scan = scan_dict
                elif scan_json_path:
                    with open(scan_json_path, "r", encoding="utf-8") as fh:
                        scan = json.load(fh)
                else:
                    # fallback: if you keep current scan features in memory, adapt here:
                    # scan = self.current_scan_dict
                    raise ValueError("No scan_json_path or scan_dict provided")

                # Extract features: prefer "features" sub-object if present
                features = {}
                if isinstance(scan, dict):
                    if "features" in scan and isinstance(scan["features"], dict):
                        features = scan["features"]
                    else:
                        # fallback to top-level numeric keys
                        for k, v in scan.items():
                            if isinstance(v, (int, float)):
                                features[k] = v
                            # also accept numeric-looking strings
                            elif isinstance(v, str) and v.isdigit():
                                features[k] = int(v)

                if not features:
                    raise ValueError("No feature vector found in scan data for prediction.")

                # Ensure prediction function exists
                if predict_from_scan_features is None:
                    raise RuntimeError("Prediction function not available (models.models.predict_from_scan_features)")

                # Run prediction (this should return dict with 'labels','label_probs','cvss_score')
                prediction = predict_from_scan_features(features, models_dir=os.path.join(ROOT_DIR, "models"))

                # Prepare scan metadata for header
                scan_meta = {}
                for k in ("target", "ip", "host"):
                    if isinstance(scan, dict) and scan.get(k):
                        scan_meta[k] = scan.get(k)

                html = self._make_prediction_html(prediction, scan_meta=scan_meta)
                self.open_prediction_in_browser(html)
            except Exception as exc:
                try:
                    messagebox.showerror("Prediction error", str(exc))
                except Exception:
                    print("Prediction error:", exc)

        # run in background thread
        threading.Thread(target=job, daemon=True).start()


    def _export_history_item(self, scan):
        """Export a specific history item to PDF."""
        self.last_scan_data = scan
        self.export_pdf()

    def _delete_history_item_by_obj(self, scan_obj):
        try:
            target = scan_obj.get("target")
            date = scan_obj.get("date")
            new_list = [s for s in self.scan_history if not (s.get("target") == target and s.get("date") == date)]
            if len(new_list) == len(self.scan_history):
                return
            self.scan_history = new_list
            self.save_history_file()
            def _refresh():
                try:
                    f = self._tab_frames.get("history")
                    if f and f.winfo_exists():
                        f.destroy()
                except Exception:
                    pass
                try:
                    self._tab_frames.pop("history", None)
                except Exception:
                    pass
                self.show_tab("history")
            try:
                self.window.after(20, _refresh)
            except Exception:
                _refresh()
        except Exception as e:
            print(f"[!] Failed to delete history item: {e}")

    def _clear_all_history(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete all scan history?"):
            self.scan_history = []
            self.save_history_file()
            try:
                f = self._tab_frames.get("history")
                if f and f.winfo_exists():
                    f.destroy()
            except Exception:
                pass
            try:
                self._tab_frames.pop("history", None)
            except Exception:
                pass
            self.show_tab("history")

    # ---------------------------
    # Settings & About
    # ---------------------------
    def create_settings_interface(self, container=None):
        parent = container or self.main_content
        for w in parent.winfo_children():
            try: w.destroy()
            except Exception: pass

        scroll_frame = ctk.CTkScrollableFrame(parent)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(scroll_frame, text="Scanner Settings", font=("Arial", 24, "bold")).pack(anchor="w", pady=(0, 20))

        # NVD API key
        api_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        api_frame.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(api_frame, text="NVD API Key (optional)", font=("Arial", 14, "bold")).pack(anchor="w", padx=15, pady=(10, 5))
        ctk.CTkLabel(api_frame, text="Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key", 
                    text_color="#888888", font=("Arial", 10)).pack(anchor="w", padx=15, pady=(0, 5))
        self.nvd_api_entry = ctk.CTkEntry(api_frame, placeholder_text="Enter NVD API key (or leave blank)")
        self.nvd_api_entry.pack(fill="x", padx=15, pady=(0, 8))

        # populate saved API key
        try:
            existing = self.load_api_key()
            if existing:
                self.nvd_api_entry.delete(0, tk.END)
                self.nvd_api_entry.insert(0, existing)
        except Exception:
            pass

        api_btns = ctk.CTkFrame(api_frame, fg_color="transparent")
        api_btns.pack(fill="x", padx=15, pady=(0, 10))

        save_btn = ctk.CTkButton(api_btns, text="💾 Save API Key", width=140, fg_color="#00C853", 
                                command=lambda: self.save_api_key(self.nvd_api_entry.get().strip()))
        save_btn.pack(side="left", padx=(0, 8))

        copy_btn = ctk.CTkButton(api_btns, text="📋 Copy export", width=140, command=self.copy_api_export_to_clipboard)
        copy_btn.pack(side="left", padx=(0, 8))

        export_btn = ctk.CTkButton(api_btns, text="🗂 Export to file", width=140, command=self.export_api_key_to_file)
        export_btn.pack(side="left", padx=(0, 8))

        clear_btn = ctk.CTkButton(api_btns, text="❌ Clear key", fg_color="#E53935", hover_color="#C62828", width=120, command=self.clear_api_key)
        clear_btn.pack(side="left")

        # PDF Export Settings
        pdf_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        pdf_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(pdf_frame, text="PDF Export Settings", font=("Arial", 14, "bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        ctk.CTkLabel(pdf_frame, text="Model Name (appears in reports):").pack(anchor="w", padx=15, pady=(5, 0))
        self.model_name_entry = ctk.CTkEntry(pdf_frame, placeholder_text="AI-Vuln-Scanner ML Model v1.0")
        self.model_name_entry.insert(0, self.model_name)
        self.model_name_entry.pack(fill="x", padx=15, pady=(0, 10))
        
        ctk.CTkLabel(pdf_frame, text="Export Note (optional):").pack(anchor="w", padx=15, pady=(5, 0))
        self.export_note_entry = ctk.CTkEntry(pdf_frame, placeholder_text="Add custom note to reports")
        if self.export_note:
            self.export_note_entry.insert(0, self.export_note)
        self.export_note_entry.pack(fill="x", padx=15, pady=(0, 10))

        # System Info
        info_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        info_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(info_frame, text="System Information", font=("Arial", 14, "bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        status_text = f"""
            PDF Export: {'Available' if PDF_EXPORT_AVAILABLE else 'Not Available'}
            CVE Lookup: {'Available' if CVE_LOOKUP_AVAILABLE else 'Not Available'}
            Scanner Parsers: {'Available' if PARSERS_AVAILABLE else 'Simulation Mode'}
        """
        ctk.CTkLabel(info_frame, text=status_text, text_color="#AFAFAF", justify="left").pack(anchor="w", padx=15, pady=(0, 10))

        save_btn = ctk.CTkButton(scroll_frame, text="💾 Save Settings", fg_color="#00C853", command=self.save_settings)
        save_btn.pack(pady=20)

    def save_settings(self):
        """Save settings from UI."""
        try:
            if hasattr(self, 'model_name_entry'):
                self.model_name = self.model_name_entry.get().strip() or "AI-Vuln-Scanner ML Model v1.0"
            if hasattr(self, 'export_note_entry'):
                self.export_note = self.export_note_entry.get().strip() or None
            messagebox.showinfo("Settings", "Scanner settings saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def create_about_interface(self, container=None):
        parent = container or self.main_content
        for w in parent.winfo_children():
            try: w.destroy()
            except Exception: pass

        scroll_frame = ctk.CTkScrollableFrame(parent)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        header_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        header_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(header_frame, text="🛡️", font=("Arial", 48)).pack(pady=(20, 10))
        ctk.CTkLabel(header_frame, text="AI Vulnerability Scanner", font=("Arial", 28, "bold")).pack(pady=(0, 5))
        ctk.CTkLabel(header_frame, text="Version 1.0", font=("Arial", 14), text_color="#888888").pack(pady=(0, 20))

        # Features
        features_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        features_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(features_frame, text="Features", font=("Arial", 18, "bold")).pack(anchor="w", padx=15, pady=(15, 10))
        
        features = [
            "🔍 Multi-tool scanning (Nmap, Gobuster, Nikto)",
            "🤖 AI-powered vulnerability prediction",
            "🔐 CVE lookup with NVD integration",
            "📊 Detailed PDF report generation",
            "📝 Scan history management",
            "⚙️ Customizable scan parameters",
            "🌐 Thread-safe GUI with real-time updates"
        ]
        
        for feature in features:
            ctk.CTkLabel(features_frame, text=feature, text_color="#AFAFAF", anchor="w").pack(anchor="w", padx=30, pady=2)
        
        ctk.CTkLabel(features_frame, text="", height=10).pack()  # spacer

        # Information
        info_frame = ctk.CTkFrame(scroll_frame, fg_color="#2a2a2a")
        info_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(info_frame, text="Information", font=("Arial", 18, "bold")).pack(anchor="w", padx=15, pady=(15, 10))
        
        info_text = """
This tool combines multiple security scanners with machine learning
to provide comprehensive vulnerability assessments.

CVE data is sourced from the National Vulnerability Database (NVD).
Ensure you have proper authorization before scanning any target.

For educational and authorized security testing purposes only.
        """
        ctk.CTkLabel(info_frame, text=info_text, text_color="#AFAFAF", justify="left").pack(anchor="w", padx=30, pady=(0, 15))

        # Footer
        footer_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        footer_frame.pack(fill="x", pady=(20, 0))
        ctk.CTkLabel(footer_frame, text="© 2024 AI Vulnerability Scanner", text_color="#666666").pack()
        ctk.CTkLabel(footer_frame, text="Developed for Cybersecurity Portfolio", text_color="#666666", font=("Arial", 10)).pack()

    # ---------------------------
    # Run app
    # ---------------------------
    def run(self):
        def on_close():
            try:
                self.save_history_file()
            except Exception:
                pass
            self.window.destroy()
        self.window.protocol("WM_DELETE_WINDOW", on_close)
        self.window.mainloop()


# Entry point
if __name__ == "__main__":
    try:
        import customtkinter
    except ImportError:
        print("CustomTkinter is required. Install it with:")
        print("pip install customtkinter")
        exit(1)

    app = AIVulnerabilityScanner()
    app.run()