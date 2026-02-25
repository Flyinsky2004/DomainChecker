#!/usr/bin/env python3
"""
Domain Availability Checker
读取 domains/ 目录下所有 .txt 文件中的域名，
通过 WHOIS（主）+ RDAP（备）检查域名是否真实可注册，
可选配置 GoDaddy 生产 API 以获得更快速的结果。
结果导出为 CSV 文件，便于在 Excel 中筛选。

使用方式:
    python main.py

注意:
  GoDaddy OTE（测试）Key 返回的是模拟数据，无法反映真实可注册状态。
  默认使用 WHOIS 直连注册局，数据来源最权威。
"""

import os
import csv
import asyncio
import collections
import aiohttp
from datetime import datetime
from pathlib import Path
import sys

# ── 配置 ───────────────────────────────────────────────────────────────────────

DOMAINS_DIR     = Path("domains")
RESULTS_DIR     = Path("results")
CONCURRENCY     = 10   # 并发请求数
REQUEST_TIMEOUT = 15   # 每个请求超时秒数（WHOIS + RDAP + GoDaddy）
WHOIS_TIMEOUT   = 10   # WHOIS 连接超时（秒）

# 从 .env 文件加载环境变量（无需安装 python-dotenv）
_env_file = Path(".env")
if _env_file.exists():
    with open(_env_file, encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ.setdefault(_key.strip(), _val.strip().strip('"').strip("'"))

GODADDY_API_KEY    = os.environ.get("GODADDY_API_KEY", "")
GODADDY_API_SECRET = os.environ.get("GODADDY_API_SECRET", "")
GODADDY_ENV        = os.environ.get("GODADDY_ENV", "ote").lower()
GODADDY_BASE_URL   = (
    "https://api.godaddy.com"
    if GODADDY_ENV == "production"
    else "https://api.ote-godaddy.com"
)

# 频率限制（可在 .env 中配置，0 = 不限制）
# RATE_UNIT 支持: second（每秒）/ minute（每分钟）
try:
    RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "30"))
except ValueError:
    RATE_LIMIT = 30
RATE_UNIT = os.environ.get("RATE_UNIT", "minute").strip().lower()
if RATE_UNIT not in ("second", "minute"):
    RATE_UNIT = "minute"

# CSV 字段顺序
FIELDNAMES = [
    "domain", "tld", "available",
    "registrar", "expiry_date", "domain_status",
    "method", "error", "checked_at",
]

# ── WHOIS 配置 ─────────────────────────────────────────────────────────────────

# 各 TLD 对应的权威 WHOIS 服务器
_WHOIS_SERVERS: dict[str, str] = {
    "ac":     "whois.nic.ac",
    "ai":     "whois.nic.ai",
    "app":    "whois.nic.google",
    "au":     "whois.auda.org.au",
    "biz":    "whois.biz",
    "cc":     "whois.nic.cc",
    "cn":     "whois.cnnic.cn",
    "co":     "whois.nic.co",
    "com":    "whois.verisign-grs.com",
    "de":     "whois.denic.de",
    "dev":    "whois.nic.google",
    "eu":     "whois.eu",
    "fr":     "whois.afnic.fr",
    "info":   "whois.afilias.net",
    "io":     "whois.nic.io",
    "jp":     "whois.jprs.jp",
    "me":     "whois.nic.me",
    "mobi":   "whois.dotmobiregistry.net",
    "net":    "whois.verisign-grs.com",
    "nl":     "whois.domain-registry.nl",
    "online": "whois.nic.online",
    "org":    "whois.pir.org",
    "site":   "whois.nic.site",
    "store":  "whois.nic.store",
    "tech":   "whois.nic.tech",
    "tv":     "whois.nic.tv",
    "uk":     "whois.nic.uk",
    "us":     "whois.nic.us",
    "xyz":    "whois.nic.xyz",
}

# 表示「域名未注册/可注册」的响应字符串（大小写不敏感）
_NOT_FOUND: tuple[str, ...] = (
    "no match",
    "not found",
    "no entries found",
    "no data found",
    "no object found",
    "object does not exist",
    "status:      free",    # DENIC (.de)
    "status: free",
    "domain not found",
    "available for registration",
    "% no entries found",
    "% no match",
    "not registered",
    "no domain records",
    "is available",
)

# 表示「域名已注册」的响应字符串
_FOUND: tuple[str, ...] = (
    "domain name:",
    "domain:",
    "registrar:",
    "holder:",
    "registrant:",
    "nserver:",
    "name server:",
    "status: connect",      # DENIC (.de) 已注册
)


# ── 频率限制器 ──────────────────────────────────────────────────────────────────

class RateLimiter:
    """滑动窗口异步频率限制器。"""

    def __init__(self, max_calls: int, period: float) -> None:
        self._max_calls = max_calls
        self._period    = period
        self._calls: collections.deque[float] = collections.deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now    = asyncio.get_event_loop().time()
                cutoff = now - self._period
                while self._calls and self._calls[0] <= cutoff:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return
                sleep_for = self._calls[0] + self._period - now
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)


class _NoopRateLimiter:
    async def acquire(self) -> None:
        pass


def make_rate_limiter(max_calls: int, unit: str) -> "RateLimiter | _NoopRateLimiter":
    if max_calls <= 0:
        return _NoopRateLimiter()
    return RateLimiter(max_calls, 1.0 if unit == "second" else 60.0)


# ── 读取域名 ────────────────────────────────────────────────────────────────────

def load_domains() -> list[str]:
    if not DOMAINS_DIR.exists():
        print(f"❌  找不到目录 '{DOMAINS_DIR}'，请先创建并添加域名文件。")
        sys.exit(1)

    txt_files = sorted(DOMAINS_DIR.glob("*.txt"))
    if not txt_files:
        print(f"❌  '{DOMAINS_DIR}/' 下没有 .txt 文件。")
        sys.exit(1)

    seen: set[str] = set()
    domains: list[str] = []

    for txt_file in txt_files:
        with open(txt_file, encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith("#") and d not in seen:
                    seen.add(d)
                    domains.append(d)

    print(f"📂  从 {len(txt_files)} 个文件中加载了 {len(domains)} 个唯一域名")
    return domains


# ── 结果模板 ────────────────────────────────────────────────────────────────────

def _make_result(domain: str) -> dict:
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    return {
        "domain":        domain,
        "tld":           tld,
        "available":     "",
        "registrar":     "",
        "expiry_date":   "",
        "domain_status": "",
        "method":        "",
        "error":         "",
        "checked_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── WHOIS 检查器（主方式，直连注册局）──────────────────────────────────────────

async def _whois_raw(host: str, query: str, timeout: float) -> str:
    """向 host:43 发送 WHOIS 查询，返回原始文本。"""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 43), timeout=timeout
    )
    try:
        writer.write((query + "\r\n").encode())
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="ignore")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def check_via_whois(domain: str) -> dict:
    """
    直连 TLD 注册局 WHOIS 服务器查询（端口 43），数据最权威。
    - 未知 TLD 先查 IANA 获取服务器地址
    - .de 使用 DENIC 专用查询格式
    """
    result = _make_result(domain)
    result["method"] = "WHOIS"

    tld    = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    server = _WHOIS_SERVERS.get(tld)

    # 对未知 TLD，通过 IANA 获取 WHOIS 服务器
    if not server:
        try:
            iana_text = await _whois_raw("whois.iana.org", tld, timeout=8.0)
            for line in iana_text.splitlines():
                if line.lower().startswith("refer:"):
                    server = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass

    if not server:
        server = f"whois.nic.{tld}"  # 最后尝试标准格式

    try:
        # DENIC (.de) 需要特殊查询格式
        query = f"-T dn,ace {domain}" if tld == "de" else domain
        text  = await _whois_raw(server, query, timeout=WHOIS_TIMEOUT)
        lower = text.lower()

        if any(pat in lower for pat in _NOT_FOUND):
            result["available"]     = "是"
            result["domain_status"] = "未注册"
        elif any(pat in lower for pat in _FOUND):
            result["available"] = "否"
            # 提取注册商
            for line in text.splitlines():
                ll = line.lower().strip()
                if ll.startswith("registrar:"):
                    result["registrar"] = line.split(":", 1)[1].strip()
                    break
            # 提取到期日
            for line in text.splitlines():
                ll = line.lower().strip()
                for kw in ("expires on:", "expiry date:", "registry expiry date:",
                           "registrar registration expiration date:", "paid-till:"):
                    if ll.startswith(kw):
                        result["expiry_date"] = line.split(":", 1)[1].strip()[:10]
                        break
        else:
            result["available"] = "未知"
            result["error"]     = f"无法解析 {server} 的响应"

    except asyncio.TimeoutError:
        result["available"] = "未知"
        result["error"]     = f"WHOIS 超时 ({server})"
    except (OSError, ConnectionRefusedError):
        result["available"] = "未知"
        result["error"]     = f"无法连接 {server}:43"
    except Exception as e:
        result["available"] = "未知"
        result["error"]     = str(e)[:100]

    return result


# ── RDAP 检查器（备用，WHOIS 失败时启用）──────────────────────────────────────

async def check_via_rdap(session: aiohttp.ClientSession, domain: str) -> dict:
    """通过 RDAP 协议检查（WHOIS 失败时的备用方案）。"""
    result = _make_result(domain)
    result["method"] = "RDAP"

    url     = f"https://rdap.org/domain/{domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 DomainChecker/1.0 (domain availability research)",
        "Accept":     "application/rdap+json, application/json",
    }
    try:
        async with session.get(
            url, headers=headers,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            allow_redirects=True,
        ) as resp:
            if resp.status == 404:
                result["available"]     = "是"
                result["domain_status"] = "未注册"
            elif resp.status == 200:
                result["available"] = "否"
                try:
                    data = await resp.json(content_type=None)
                    for entity in data.get("entities", []):
                        if "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray", [[], []])
                            if len(vcard) > 1:
                                for entry in vcard[1]:
                                    if entry[0] == "fn":
                                        result["registrar"] = entry[3]
                                        break
                    for event in data.get("events", []):
                        if event.get("eventAction") == "expiration":
                            result["expiry_date"] = event.get("eventDate", "")[:10]
                    result["domain_status"] = "; ".join(data.get("status", []))
                except Exception:
                    pass
            else:
                result["available"] = "未知"
                result["error"]     = f"HTTP {resp.status}"

    except asyncio.TimeoutError:
        result["available"] = "未知"
        result["error"]     = "RDAP 超时"
    except Exception as e:
        result["available"] = "未知"
        result["error"]     = str(e)[:100]

    return result


# ── GoDaddy API 检查器（仅生产环境 Key 可信）──────────────────────────────────

async def check_via_godaddy(session: aiohttp.ClientSession, domain: str) -> dict:
    """通过 GoDaddy 生产 API 检查（最精准，需生产 Key）。"""
    result  = _make_result(domain)
    result["method"] = "GoDaddy"

    url     = f"{GODADDY_BASE_URL}/v1/domains/available"
    headers = {
        "Authorization": f"sso-key {GODADDY_API_KEY}:{GODADDY_API_SECRET}",
        "Accept":        "application/json",
    }
    params  = {"domain": domain, "checkType": "FAST"}

    try:
        async with session.get(
            url, headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            data = await resp.json(content_type=None)
            if resp.status == 200:
                available  = data.get("available", False)
                definitive = data.get("definitive", True)
                result["available"] = "是" if available else "否"
                if not definitive:
                    result["error"] = "结果不确定（建议手动验证）"
            elif resp.status == 400:
                result["available"] = "未知"
                msg = data.get("message", "")
                result["error"] = f"400 Bad Request: {msg or str(data)[:80]}"
            elif resp.status == 401:
                result["available"] = "未知"
                result["error"]     = "401 Key/Secret 无效"
            elif resp.status == 403:
                result["available"] = "未知"
                result["error"]     = "403 无权限（OTE Key 请将 GODADDY_ENV=ote）"
            elif resp.status == 429:
                result["available"] = "未知"
                result["error"]     = "429 超出频率限制"
            elif resp.status == 422:
                result["available"] = "未知"
                result["error"]     = data.get("message", "不支持的 TLD")
            else:
                result["available"] = "未知"
                result["error"]     = data.get("message", f"HTTP {resp.status}")

    except asyncio.TimeoutError:
        result["available"] = "未知"
        result["error"]     = "请求超时"
    except Exception as e:
        result["available"] = "未知"
        result["error"]     = str(e)[:100]

    return result


# ── 免费组合检查：WHOIS 主 + RDAP 备 ──────────────────────────────────────────

async def check_free(session: aiohttp.ClientSession, domain: str) -> dict:
    """WHOIS 直连注册局（主）；若 WHOIS 失败则回退到 RDAP。"""
    result = await check_via_whois(domain)
    if result["available"] == "未知":
        # WHOIS 连接失败（防火墙、未知 TLD 等）→ 尝试 RDAP
        rdap = await check_via_rdap(session, domain)
        if rdap["available"] != "未知":
            rdap["error"] = ("WHOIS 不可用→RDAP" + (f"({result['error']})" if result["error"] else ""))
            return rdap
    return result


# ── 并发处理 ─────────────────────────────────────────────────────────────────────

async def process_all(
    domains: list[str],
    rate_limiter: "RateLimiter | _NoopRateLimiter",
    use_godaddy_prod: bool,
) -> list[dict]:
    checker = check_via_godaddy if use_godaddy_prod else check_free

    semaphore = asyncio.Semaphore(CONCURRENCY)
    total     = len(domains)
    width     = len(str(total))
    results   = [None] * total

    connector = aiohttp.TCPConnector(limit=CONCURRENCY * 2)
    async with aiohttp.ClientSession(connector=connector) as session:

        async def worker(idx: int, domain: str):
            await rate_limiter.acquire()
            async with semaphore:
                res = await checker(session, domain)
                results[idx] = res
                icon    = {"是": "✓", "否": "✗"}.get(res["available"], "?")
                method  = res["method"]
                err_str = f"  [{res['error']}]" if res["error"] else ""
                print(f"  [{idx + 1:>{width}}/{total}] {icon} {domain:<38} ({method}){err_str}")

        await asyncio.gather(*[worker(i, d) for i, d in enumerate(domains)])

    return results  # type: ignore[return-value]


# ── 输出 CSV ─────────────────────────────────────────────────────────────────────

def save_csv(results: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


def print_summary(results: list[dict], elapsed: float) -> None:
    count_yes     = sum(1 for r in results if r["available"] == "是")
    count_no      = sum(1 for r in results if r["available"] == "否")
    count_unknown = sum(1 for r in results if r["available"] not in ("是", "否"))

    print()
    print("─" * 44)
    print(f"  检查总数    : {len(results):>4}  (耗时 {elapsed:.1f}s)")
    print(f"  ✓ 可注册    : {count_yes:>4}")
    print(f"  ✗ 已被注册  : {count_no:>4}")
    print(f"  ? 未知/错误 : {count_unknown:>4}")
    print("─" * 44)


# ── 入口 ─────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 44)
    print("   Domain Availability Checker")
    print("=" * 44)

    domains = load_domains()

    has_keys         = bool(GODADDY_API_KEY and GODADDY_API_SECRET)
    use_godaddy_prod = has_keys and GODADDY_ENV == "production"
    use_godaddy_ote  = has_keys and GODADDY_ENV != "production"

    if use_godaddy_prod:
        print("🔍  检查方式: GoDaddy API（生产环境，最精准）")
        print(f"    端点    : {GODADDY_BASE_URL}")
    elif use_godaddy_ote:
        print("⚠️   检测到 GoDaddy OTE 测试 Key！")
        print("    OTE 环境返回的是【模拟数据】，所有域名都会显示可注册。")
        print("    已自动降级为: WHOIS + RDAP（真实数据，直连注册局）")
        print()
        print("    要使用 GoDaddy API:")
        print("    → 访问 developer.godaddy.com/keys")
        print("    → 点击 Add Production Key")
        print("    → 在 .env 中设置 GODADDY_ENV=production")
    else:
        print("🔍  检查方式: WHOIS（主）+ RDAP（备）")
        print("    直连各 TLD 注册局服务器，数据来源权威")

    print(f"⚡  并发数  : {CONCURRENCY}")
    if RATE_LIMIT > 0:
        unit_zh = "秒" if RATE_UNIT == "second" else "分钟"
        print(f"🚦  频率限制: {RATE_LIMIT} 次 / {unit_zh}")
    else:
        print("🚦  频率限制: 不限制")
    print()

    rate_limiter = make_rate_limiter(RATE_LIMIT, RATE_UNIT)
    start        = datetime.now()
    results      = asyncio.run(process_all(domains, rate_limiter, use_godaddy_prod))
    elapsed      = (datetime.now() - start).total_seconds()

    print_summary(results, elapsed)

    RESULTS_DIR.mkdir(exist_ok=True)
    ts          = start.strftime("%Y%m%d_%H%M%S")
    out_path    = RESULTS_DIR / f"domain_check_{ts}.csv"
    latest_path = RESULTS_DIR / "latest.csv"

    save_csv(results, out_path)
    save_csv(results, latest_path)

    print(f"\n📊  已保存 → {out_path}")
    print(f"📊  已保存 → {latest_path}  (每次运行覆盖)")
    print()
    print("Excel 使用技巧: 打开 CSV → 选中 'available' 列 → 数据 → 筛选 → 勾选「是」")


if __name__ == "__main__":
    main()
