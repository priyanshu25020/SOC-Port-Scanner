import socket
import threading
import time
import queue
import sys
import os
import concurrent.futures
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from google import genai

# ---------------------------
# API Configuration (Secure & Updated)
# ---------------------------
# YAHAN APNI ACTUAL API KEY DAALEIN
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_API_KEY_HERE") 

if GEMINI_API_KEY and GEMINI_API_KEY != "YOUR_API_KEY_HERE":
    client = genai.Client(api_key=GEMINI_API_KEY)

# ---------------------------
# Service Map
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 
    443: 'HTTPS', 445: 'SMB', 623: 'IPMI', 3306: 'MySQL', 
    3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Fast & Smart Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _grab_banner(self, s, port):
        """Attempts to grab the service banner for OSINT/Vulnerability mapping."""
        try:
            if port in [80, 443, 8080]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
            s.settimeout(1.0)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:60] + "..." if len(banner) > 60 else banner if banner else "No Banner Detected"
        except Exception:
            return "No Banner Detected"

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                banner = self._grab_banner(s, port)
                
                with self._lock:
                    self.open_ports.append((port, service, banner))
                self.result_queue.put(('open', port, service, banner))
            s.close()
        except Exception as e:
            pass 
        finally:
            with self._lock:
                self.scanned_count += 1
                current_count = self.scanned_count
            if current_count % 10 == 0 or current_count == self.total_ports:
                self.result_queue.put(('progress', current_count, self.total_ports))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        # max_workers ab user ke UI selection ke hisaab se dynamically set hoga
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for port in range(self.start_port, self.end_port + 1):
                if self._stop_event.is_set():
                    break
                executor.submit(self._scan_port, port)
                
        self.result_queue.put(('done', None, None, None))

# ---------------------------
# Tkinter GUI 
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced SOC Port Scanner & AI Analyzer")
        self.geometry("820x620")
        self.minsize(780, 560)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 100

        # Windows fix to ensure Treeview colors show up correctly
        style = ttk.Style(self)
        style.theme_use("default") 
        style.map("Treeview", background=[("selected", "#0078D7")], foreground=[("selected", "white")])

        self._build_ui()

    def _build_ui(self):
        # --- Top Frame: Inputs ---
        frm_top = ttk.LabelFrame(self, text="Target Configuration")
        frm_top.pack(fill="x", padx=10, pady=10)

        # Row 0: Target & Ports
        ttk.Label(frm_top, text="Target (IP/Host):").grid(row=0, column=0, padx=5, pady=8, sticky="e")
        self.ent_target = ttk.Entry(frm_top, width=30)
        self.ent_target.grid(row=0, column=1, padx=5, pady=8, sticky="w")

        ttk.Label(frm_top, text="Start Port:").grid(row=0, column=2, padx=5, pady=8, sticky="e")
        self.ent_start = ttk.Entry(frm_top, width=8)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=5, pady=8, sticky="w")

        ttk.Label(frm_top, text="End Port:").grid(row=0, column=4, padx=5, pady=8, sticky="e")
        self.ent_end = ttk.Entry(frm_top, width=8)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=5, pady=8, sticky="w")

        # --- NEW: Row 1: Scan Speed Profile ---
        ttk.Label(frm_top, text="Scan Speed:").grid(row=1, column=0, padx=5, pady=8, sticky="e")
        self.var_speed = tk.StringVar()
        self.cmb_speed = ttk.Combobox(frm_top, textvariable=self.var_speed, state="readonly", width=25)
        self.cmb_speed['values'] = ("Stealth (10 Threads)", "Normal (100 Threads)", "Aggressive (800 Threads)")
        self.cmb_speed.current(2) # Default 'Aggressive' par set hai
        self.cmb_speed.grid(row=1, column=1, columnspan=2, padx=5, pady=8, sticky="w")

        # Buttons on Row 1
        self.btn_start = ttk.Button(frm_top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=1, column=4, padx=5, pady=8, sticky="e")

        self.btn_stop = ttk.Button(frm_top, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=1, column=5, padx=5, pady=8, sticky="w")

        for i in range(6):
            frm_top.grid_columnconfigure(i, weight=1)

        # --- Progress / Status ---
        frm_status = ttk.Frame(self)
        frm_status.pack(fill="x", padx=10, pady=(0,10))

        self.var_status = tk.StringVar(value="Status: Idle")
        self.lbl_status = ttk.Label(frm_status, textvariable=self.var_status, font=("Arial", 9, "bold"))
        self.lbl_status.pack(side="left")

        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        self.lbl_elapsed = ttk.Label(frm_status, textvariable=self.var_elapsed)
        self.lbl_elapsed.pack(side="right")

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0,10))

        # --- Results Table (Treeview) ---
        frm_results = ttk.LabelFrame(self, text="Live Scan Results (Port | Service | Banner)")
        frm_results.pack(fill="both", expand=True, padx=10, pady=(0,10))

        columns = ("Port", "Service", "Banner")
        self.tree = ttk.Treeview(frm_results, columns=columns, show="headings")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Banner", text="Service Banner / Signature")
        
        self.tree.column("Port", width=80, anchor="center")
        self.tree.column("Service", width=120, anchor="center")
        self.tree.column("Banner", width=450, anchor="w")

        # Color Tags for Visual Risk Scoring
        self.tree.tag_configure("high_risk", background="#ffcccc", foreground="black")  # Light Red
        self.tree.tag_configure("medium_risk", background="#ffe6cc", foreground="black") # Light Orange
        self.tree.tag_configure("secure", background="#ccffcc", foreground="black")      # Light Green
        self.tree.tag_configure("neutral", background="white", foreground="black")       # Default

        self.tree.pack(fill="both", expand=True, side="left", padx=(10,0), pady=10)

        yscroll = ttk.Scrollbar(frm_results, orient="vertical", command=self.tree.yview)
        yscroll.pack(side="right", fill="y", pady=10)
        self.tree.configure(yscrollcommand=yscroll.set)

        # --- Bottom Buttons ---
        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(fill="x", padx=10, pady=(0,12))

        self.btn_clear = ttk.Button(frm_bottom, text="Clear Table", command=self.clear_results)
        self.btn_clear.pack(side="left")

        self.btn_report = ttk.Button(frm_bottom, text="Generate AI Security Report", command=self.trigger_ai_report, state="disabled")
        self.btn_report.pack(side="left", padx=10)

        self.btn_save = ttk.Button(frm_bottom, text="Export as CSV", command=self.save_results, state="disabled")
        self.btn_save.pack(side="right")

    # --- Helper Function to Determine Risk Level ---
    def _get_risk_tag(self, port):
        high_risk_ports = [21, 23, 135, 139, 445, 3389]   # Cleartext/Admin ports
        medium_risk_ports = [80, 8080, 3306, 5900]        # Web/Database ports
        secure_ports = [22, 443]                          # Encrypted ports
        
        if port in high_risk_ports:
            return "high_risk"
        elif port in medium_risk_ports:
            return "medium_risk"
        elif port in secure_ports:
            return "secure"
        return "neutral"

    # -----------------------
    # Control Handlers
    # -----------------------
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers.")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range must be within 0-65535.")
            return

        # --- NEW: Get Selected Speed and map to threads ---
        speed_mapping = {
            "Stealth (10 Threads)": 10,
            "Normal (100 Threads)": 100,
            "Aggressive (800 Threads)": 800
        }
        selected_speed = self.var_speed.get()
        workers = speed_mapping.get(selected_speed, 800) # Default to 800 if something goes wrong

        self.clear_results()
        
        # Pass the dynamic 'workers' value to the scanner
        self.scanner = PortScanner(target, start_port, end_port, timeout=0.5, max_workers=workers)

        try:
            resolved_ip = self.scanner.resolve_target()
            self.title(f"Scanning: {target} ({resolved_ip}) | Mode: {selected_speed.split(' ')[0]}")
        except Exception as e:
            messagebox.showerror("Resolution Error", f"Failed to resolve target '{target}'.\n{e}")
            self.scanner = None
            return

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self.btn_report.configure(state="disabled")
        self.cmb_speed.configure(state="disabled") # Disable changing speed during scan

        self.start_time = time.time()
        self.update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Status: Stopping...")

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress.configure(value=0, maximum=1)
        self.var_status.set("Status: Idle")
        self.var_elapsed.set("Elapsed: 0.00s")
        self.btn_save.configure(state="disabled")
        self.btn_report.configure(state="disabled")
        self.title("Advanced SOC Port Scanner & AI Analyzer")

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            return
        file_path = filedialog.asksaveasfilename(
            title="Export to CSV", defaultextension=".csv",
            initialfile=f"scan_results_{int(time.time())}.csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path: return
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("Port,Service,Banner\n")
                for port, service, banner in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                    clean_banner = banner.replace(",", ";").replace("\n", " ")
                    f.write(f"{port},{service},{clean_banner}\n")
            messagebox.showinfo("Saved", "Results exported to CSV successfully.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save file.\n{e}")

    # -----------------------
    # LLM Integration
    # -----------------------
    def trigger_ai_report(self):
        if not self.scanner or not self.scanner.open_ports:
            return
        
        if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_API_KEY_HERE":
            messagebox.showwarning("API Key Missing", 
                "Gemini API key is not set.\nPlease set the 'GEMINI_API_KEY' environment variable or update the code.")
            return

        self.btn_report.configure(state="disabled", text="Analyzing Data...")
        threading.Thread(target=self._fetch_llm_analysis, daemon=True).start()

    def _fetch_llm_analysis(self):
        ports_data = ", ".join([f"Port {p} ({s} - Banner: {b})" for p, s, b in self.scanner.open_ports])
        prompt = (
            f"Act as a Senior SOC Analyst. I scanned a target and found these open ports and banners: {ports_data}. "
            "Provide a concise security assessment. Point out critical vulnerabilities (like cleartext protocols or exposed RDP/SMB), "
            "evaluate the banners if available, and provide exact mitigation steps."
        )
        
        try:
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            self.after(0, self._show_report_window, response.text)
        except Exception as e:
            self.after(0, messagebox.showerror, "AI Error", f"Failed to generate report:\n{e}")
        finally:
            self.after(0, lambda: self.btn_report.configure(state="normal", text="Generate AI Security Report"))

    def _show_report_window(self, report_text):
        rep_win = tk.Toplevel(self)
        rep_win.title("SOC AI Security Assessment")
        rep_win.geometry("700x550")
        
        txt = tk.Text(rep_win, wrap="word", font=("Consolas", 10), bg="#1e1e1e", fg="#00ff00")
        txt.pack(fill="both", expand=True, padx=15, pady=15)
        txt.insert("1.0", report_text)
        txt.configure(state="disabled") 

    # -----------------------
    # UI Thread Safety Helpers
    # -----------------------
    def update_elapsed(self):
        if self.start_time and self.var_status.get().startswith("Status: Scan"):
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(100, self.update_elapsed)

    def poll_results(self):
        if not self.scanner:
            return

        try:
            while True:
                msg = self.scanner.result_queue.get_nowait()
                msg_type = msg[0]
                
                if msg_type == 'open':
                    _, port, service, banner = msg
                    risk_tag = self._get_risk_tag(port)
                    self.tree.insert("", "end", values=(port, service, banner), tags=(risk_tag,))
                    
                elif msg_type == 'progress':
                    _, current, total = msg
                    self.progress.configure(maximum=max(total, 1), value=current)
                    self.var_status.set(f"Status: Scanning... {current}/{total} ports")
                elif msg_type == 'done':
                    total_open = len(self.scanner.open_ports)
                    self.var_status.set(f"Status: Completed. Found {total_open} open ports.")
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.cmb_speed.configure(state="readonly") # Re-enable speed selection
                    
                    if total_open > 0:
                        self.btn_save.configure(state="normal")
                        self.btn_report.configure(state="normal")
                    self.start_time = None
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)

def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1) 
        except Exception:
            pass
    app = ScannerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()