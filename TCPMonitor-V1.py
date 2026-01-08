import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import time
from collections import deque
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ---------------- CONFIG ----------------
BG = "black"
FG = "lime"
FONT = ("Consolas", 10)
TITLE_FONT = ("Consolas", 12, "bold")

SUSPICIOUS_PORTS = {21, 22, 23, 25, 4444, 1337, 3389, 6666}

# ---------------- APP ----------------
class TCPMonitor:
    def __init__(self, root):
        self.root = root
        self.root.overrideredirect(True)
        self.root.geometry("1200x600")
        self.root.configure(bg=BG)

        self.offset_x = self.offset_y = 0
        self.conn_history = deque(maxlen=30)

        self.build_ui()
        self.auto_refresh()

    # ---------- UI ----------
    def build_ui(self):
        top = tk.Frame(self.root, bg="#111", height=30)
        top.pack(fill="x")

        title = tk.Label(top, text=" Advanced TCP Monitor", fg=FG, bg="#111", font=TITLE_FONT)
        title.pack(side="left")
        title.bind("<Button-1>", self.start_move)
        title.bind("<B1-Motion>", self.move_window)

        tk.Button(top, text="_", bg="#111", fg=FG, bd=0,
                  command=self.root.iconify).pack(side="right")
        tk.Button(top, text="X", bg="#111", fg="red", bd=0,
                  command=self.root.destroy).pack(side="right")

        # Search
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", pady=5)

        tk.Label(bar, text="Filter Port:", fg=FG, bg=BG).pack(side="left")
        self.port_filter = tk.StringVar()
        tk.Entry(bar, textvariable=self.port_filter,
                 bg="#111", fg=FG, insertbackground=FG).pack(side="left", padx=5)

        tk.Button(bar, text="Refresh", command=self.refresh,
                  bg="#111", fg=FG).pack(side="left")

        tk.Button(bar, text="Kill Selected",
                  bg="#400", fg="white",
                  command=self.kill_connection).pack(side="right", padx=10)

        # Table
        cols = ("PID", "Process", "Local", "Remote", "Status")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=200)

        self.tree.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="black", foreground="lime",
                        fieldbackground="black", rowheight=22)

        # Graph
        self.fig, self.ax = plt.subplots(figsize=(4, 2), facecolor="black")
        self.ax.set_facecolor("black")
        self.ax.tick_params(colors="lime")
        self.ax.set_title("Connections / Refresh", color="lime")

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(fill="x")

    # ---------- DATA ----------
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        count = 0
        port_filter = self.port_filter.get()

        for c in psutil.net_connections(kind="tcp"):
            if not c.laddr:
                continue

            try:
                proc = psutil.Process(c.pid) if c.pid else None
                pname = proc.name() if proc else "Unknown"
            except:
                pname = "Access Denied"

            lport = c.laddr.port
            rport = c.raddr.port if c.raddr else ""

            if port_filter and port_filter not in str(lport) and port_filter not in str(rport):
                continue

            local = f"{c.laddr.ip}:{lport}"
            remote = f"{c.raddr.ip}:{rport}" if c.raddr else "-"

            tag = ""
            if lport in SUSPICIOUS_PORTS or rport in SUSPICIOUS_PORTS:
                tag = "sus"

            self.tree.insert("", "end",
                             values=(c.pid, pname, local, remote, c.status),
                             tags=(tag,))
            count += 1

        self.tree.tag_configure("sus", background="#400")
        self.conn_history.append(count)
        self.update_graph()

    # ---------- GRAPH ----------
    def update_graph(self):
        self.ax.clear()
        self.ax.plot(list(self.conn_history), color="lime")
        self.ax.set_facecolor("black")
        self.ax.set_title("Connections / Refresh", color="lime")
        self.ax.tick_params(colors="lime")
        self.canvas.draw()

    # ---------- KILL ----------
    def kill_connection(self):
        selected = self.tree.selection()
        if not selected:
            return

        pid = self.tree.item(selected[0])["values"][0]

        if not pid:
            messagebox.showerror("Error", "No PID found.")
            return

        try:
            psutil.Process(pid).terminate()
            messagebox.showinfo("Killed", f"Process {pid} terminated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------- AUTO ----------
    def auto_refresh(self):
        self.refresh()
        self.root.after(2000, self.auto_refresh)

    # ---------- MOVE ----------
    def start_move(self, e):
        self.offset_x = e.x
        self.offset_y = e.y

    def move_window(self, e):
        self.root.geometry(f"+{e.x_root - self.offset_x}+{e.y_root - self.offset_y}")

# ---------------- RUN ----------------
root = tk.Tk()
TCPMonitor(root)
root.mainloop()
