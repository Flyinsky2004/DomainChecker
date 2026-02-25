#!/usr/bin/env python3
"""
Domain Availability Checker
读取 domains/ 目录下所有 .txt 文件中的域名，
通过 RDAP（无需 API Key）或 GoDaddy API（可选，更精准）检查可注册性，
并将结果导出为 CSV 文件，便于在 Excel 中筛选。

使用方式:
    python main.py

可选 GoDaddy API（更准确）:
    在 .env 文件中设置 GODADDY_API_KEY 和 GODADDY_API_SECRET
    免费申请: https://developer.godaddy.com/
"""

import os
import csv
import asyncio
import aiohttp
from datetime import datetime
from pathlib import Path
import sys

# ── 配置 ───────────────────────────────────────────────────────────────────────

DOMAINS_DIR     = Path("domains")
RESULTS_DIR     = Path("results")
CONCURRENCY     = 10   # 并发请求数
REQUEST_TIMEOUT = 15   # 每个请求超时秒数

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
# 第一个申请的 Key 是 OTE 测试环境，必须用 api.ote-godaddy.com
# 申请了 Production Key 后改为 production
GODADDY_ENV        = os.environ.get("GODADDY_ENV", "ote").lower()
GODADDY_BASE_URL   = (
    "https://api.godaddy.com"
    if GODADDY_ENV == "production"
    else "https://api.ote-godaddy.com"
)

# CSV 字段顺序
FIELDNAMES = [
    "domain", "tld", "available",
    "registrar", "expiry_date", "domain_status",
    "method", "error", "checked_at",
]


# ── 读取域名 ────────────────────────────────────────────────────────────────────

def load_domains() -> list[str]:
    """读取 domains/ 目录下所有 .txt 文件，去重后返回域名列表。"""
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
                # 跳过空行和注释行
                if d and not d.startswith("#") and d not in seen:
                    seen.add(d)
                    domains.append(d)

    file_word = f"{len(txt_files)} 个文件"
    print(f"📂  从 {file_word} 中加载了 {len(domains)} 个唯一域名")
    return domains


# ── 检查器 ──────────────────────────────────────────────────────────────────────

def _make_result(domain: str) -> dict:
    """创建结果字典的初始模板。"""
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


async def check_via_rdap(session: aiohttp.ClientSession, domain: str) -> dict:
    """
    通过 RDAP 协议检查域名（完全免费，无需 API Key）。
    RDAP 是 ICANN 的注册数据访问协议，404 = 未注册（可能可注册），200 = 已注册。
    注意: 少数小众 TLD 可能不支持 RDAP。
    """
    result = _make_result(domain)
    result["method"] = "RDAP"

    url = f"https://rdap.org/domain/{domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 DomainChecker/1.0 (domain availability research)",
        "Accept":     "application/rdap+json, application/json",
    }
    try:
        async with session.get(
            url,
            headers=headers,
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
                    # 提取注册商
                    for entity in data.get("entities", []):
                        if "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray", [[], []])
                            if len(vcard) > 1:
                                for entry in vcard[1]:
                                    if entry[0] == "fn":
                                        result["registrar"] = entry[3]
                                        break
                            if not result["registrar"]:
                                result["registrar"] = entity.get("handle", "")
                    # 提取到期日
                    for event in data.get("events", []):
                        if event.get("eventAction") == "expiration":
                            result["expiry_date"] = event.get("eventDate", "")[:10]
                    # 提取状态
                    result["domain_status"] = "; ".join(data.get("status", []))
                except Exception:
                    pass  # JSON 解析失败时保留基本可用性结果
            elif resp.status == 400:
                result["available"] = "未知"
                result["error"]     = "域名格式无效"
            else:
                result["available"] = "未知"
                result["error"]     = f"HTTP {resp.status}"

    except asyncio.TimeoutError:
        result["available"] = "未知"
        result["error"]     = "请求超时"
    except aiohttp.ClientConnectorError:
        result["available"] = "未知"
        result["error"]     = "连接失败（检查网络）"
    except Exception as e:
        result["available"] = "未知"
        result["error"]     = str(e)[:120]

    return result


async def check_via_godaddy(session: aiohttp.ClientSession, domain: str) -> dict:
    """
    通过 GoDaddy API 检查域名（免费 API Key，精准度更高）。
    免费申请: https://developer.godaddy.com/
    """
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
                available = data.get("available", False)
                definitive = data.get("definitive", True)
                result["available"] = "是" if available else "否"
                if not definitive:
                    result["error"] = "结果不确定（建议手动验证）"
            elif resp.status == 400:
                result["available"] = "未知"
                msg = data.get("message", "")
                # 400 最常见原因: OTE Key 用了生产 URL，或 Key/Secret 填错
                result["error"] = f"400 Bad Request: {msg or str(data)[:80]}"
            elif resp.status == 401:
                result["available"] = "未知"
                result["error"]     = "401 Key/Secret 无效，请检查 .env 文件"
            elif resp.status == 403:
                result["available"] = "未知"
                result["error"]     = "403 无权限（OTE Key 请将 GODADDY_ENV=ote）"
            elif resp.status == 429:
                result["available"] = "未知"
                result["error"]     = "429 超出 API 频率限制，稍后重试"
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
        result["error"]     = str(e)[:120]

    return result


# ── 并发处理 ─────────────────────────────────────────────────────────────────────

async def process_all(domains: list[str]) -> list[dict]:
    """使用信号量控制并发，批量检查所有域名。"""
    use_godaddy = bool(GODADDY_API_KEY and GODADDY_API_SECRET)
    checker     = check_via_godaddy if use_godaddy else check_via_rdap

    semaphore = asyncio.Semaphore(CONCURRENCY)
    total     = len(domains)
    width     = len(str(total))
    results   = [None] * total

    connector = aiohttp.TCPConnector(limit=CONCURRENCY * 2)
    async with aiohttp.ClientSession(connector=connector) as session:

        async def worker(idx: int, domain: str):
            async with semaphore:
                res = await checker(session, domain)
                results[idx] = res
                icon    = {"是": "✓", "否": "✗"}.get(res["available"], "?")
                err_str = f"  [{res['error']}]" if res["error"] else ""
                print(f"  [{idx + 1:>{width}}/{total}] {icon} {domain:<38}{err_str}")

        await asyncio.gather(*[worker(i, d) for i, d in enumerate(domains)])

    return results  # type: ignore[return-value]


# ── 输出 CSV ─────────────────────────────────────────────────────────────────────

def save_csv(results: list[dict], path: Path) -> None:
    """保存结果为 UTF-8 BOM 编码的 CSV（Excel 直接打开不乱码）。"""
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
    print(f"  ✓ 可能可注册: {count_yes:>4}")
    print(f"  ✗ 已被注册  : {count_no:>4}")
    print(f"  ? 未知/错误 : {count_unknown:>4}")
    print("─" * 44)


# ── 入口 ─────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 44)
    print("   Domain Availability Checker")
    print("=" * 44)

    domains = load_domains()

    use_godaddy = bool(GODADDY_API_KEY and GODADDY_API_SECRET)
    if use_godaddy:
        env_label   = "OTE 测试环境" if GODADDY_ENV != "production" else "生产环境"
        method_name = f"GoDaddy API（{env_label}）"
        print(f"🔍  检查方式: {method_name}")
        print(f"    端点    : {GODADDY_BASE_URL}")
        if GODADDY_ENV != "production":
            print("    ⚠️  OTE 环境仅供测试，域名可用性数据为模拟值")
            print("    ℹ️  需要真实结果请申请 Production Key 并设置 GODADDY_ENV=production")
    else:
        print("🔍  检查方式: RDAP / rdap.org（免费模式）")
        print("    提示: 在 .env 中配置 GoDaddy API Key 可获得更准确的结果")
    print(f"⚡  并发数  : {CONCURRENCY}")
    print()

    start   = datetime.now()
    results = asyncio.run(process_all(domains))
    elapsed = (datetime.now() - start).total_seconds()

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
