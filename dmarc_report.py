#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DMARC 集約レポート（Aggregate Report）を人が読みやすい HTML に変換するツール。

DMARC の集約レポートは RFC 7489 で定義された XML 形式で、各メールプロバイダ
(Google, Microsoft など) から送られてきます。生の XML は読みにくいため、
本スクリプトで集計・可視化した HTML レポートを生成します。

対応入力:
  - .xml               生の XML ファイル
  - .xml.gz / .gz      gzip 圧縮された XML
  - .zip               zip 内の XML（複数可）
  - ディレクトリ        配下の上記ファイルをすべて読み込み

使い方:
  python dmarc_report.py sample                 # sample フォルダを処理
  python dmarc_report.py sample -o report.html  # 出力先を指定
  python dmarc_report.py a.xml b.xml.gz c.zip   # 複数指定
  python dmarc_report.py sample --open          # 生成後にブラウザで開く

標準ライブラリのみで動作します（追加インストール不要）。
"""

import argparse
import glob
import gzip
import html
import io
import os
import re
import socket
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


# ---------------------------------------------------------------------------
# データモデル
# ---------------------------------------------------------------------------

@dataclass
class Record:
    """レポート中の 1 レコード（送信元 IP ごとの集計行）。"""
    source_ip: str
    count: int
    disposition: str          # none / quarantine / reject
    dkim_eval: str            # policy_evaluated 上の DKIM 結果 (pass/fail)
    spf_eval: str             # policy_evaluated 上の SPF 結果 (pass/fail)
    header_from: str
    envelope_to: str
    dkim_domain: str
    dkim_result: str          # auth_results 上の生の DKIM 結果
    dkim_selector: str
    spf_domain: str
    spf_result: str           # auth_results 上の生の SPF 結果
    reason_type: str
    reason_comment: str

    @property
    def aligned(self) -> bool:
        """DMARC 準拠（DKIM か SPF のどちらかが pass）かどうか。"""
        return self.dkim_eval == "pass" or self.spf_eval == "pass"


@dataclass
class Report:
    """1 つの DMARC 集約レポート（1 XML ファイル）。"""
    org_name: str
    email: str
    report_id: str
    date_begin: int
    date_end: int
    domain: str
    policy_p: str
    policy_sp: str
    policy_pct: str
    policy_adkim: str
    policy_aspf: str
    records: list = field(default_factory=list)
    source_file: str = ""

    @property
    def total_count(self) -> int:
        return sum(r.count for r in self.records)


# ---------------------------------------------------------------------------
# パース
# ---------------------------------------------------------------------------

def _text(node, path, default=""):
    """XPath 相当で子要素のテキストを取得。無ければ default。"""
    if node is None:
        return default
    found = node.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def parse_report(xml_bytes: bytes, source_file: str = "") -> Report:
    """XML バイト列を Report にパースする。"""
    root = ET.fromstring(xml_bytes)

    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    date_range = meta.find("date_range") if meta is not None else None

    report = Report(
        org_name=_text(meta, "org_name", "(不明)"),
        email=_text(meta, "email"),
        report_id=_text(meta, "report_id"),
        date_begin=int(_text(date_range, "begin", "0") or 0),
        date_end=int(_text(date_range, "end", "0") or 0),
        domain=_text(policy, "domain"),
        policy_p=_text(policy, "p"),
        policy_sp=_text(policy, "sp"),
        policy_pct=_text(policy, "pct"),
        policy_adkim=_text(policy, "adkim"),
        policy_aspf=_text(policy, "aspf"),
        source_file=source_file,
    )

    for rec in root.findall("record"):
        row = rec.find("row")
        pe = row.find("policy_evaluated") if row is not None else None
        ident = rec.find("identifiers")
        auth = rec.find("auth_results")

        report.records.append(Record(
            source_ip=_text(row, "source_ip"),
            count=int(_text(row, "count", "0") or 0),
            disposition=_text(pe, "disposition"),
            dkim_eval=_text(pe, "dkim"),
            spf_eval=_text(pe, "spf"),
            header_from=_text(ident, "header_from"),
            envelope_to=_text(ident, "envelope_to"),
            dkim_domain=_text(auth, "dkim/domain"),
            dkim_result=_text(auth, "dkim/result"),
            dkim_selector=_text(auth, "dkim/selector"),
            spf_domain=_text(auth, "spf/domain"),
            spf_result=_text(auth, "spf/result"),
            reason_type=_text(pe, "reason/type"),
            reason_comment=_text(pe, "reason/comment"),
        ))

    return report


# ---------------------------------------------------------------------------
# 入力の読み込み（ファイル / gz / zip / ディレクトリ）
# ---------------------------------------------------------------------------

def iter_xml_sources(paths):
    """指定パス群から (xml_bytes, source_name) を順に yield する。"""
    for path in paths:
        if os.path.isdir(path):
            # ディレクトリ配下の対応ファイルを再帰的に拾う
            patterns = ("*.xml", "*.xml.gz", "*.gz", "*.zip")
            found = []
            for pat in patterns:
                found.extend(glob.glob(os.path.join(path, "**", pat), recursive=True))
            for f in sorted(set(found)):
                yield from _read_one(f)
        else:
            yield from _read_one(path)


def _read_one(path):
    lower = path.lower()
    try:
        if lower.endswith(".zip"):
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".xml"):
                        yield zf.read(name), f"{os.path.basename(path)}:{name}"
                    elif name.lower().endswith(".gz"):
                        with zf.open(name) as raw:
                            data = gzip.decompress(raw.read())
                            yield data, f"{os.path.basename(path)}:{name}"
        elif lower.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                yield f.read(), os.path.basename(path)
        elif lower.endswith(".xml"):
            with open(path, "rb") as f:
                yield f.read(), os.path.basename(path)
        else:
            print(f"  [スキップ] 未対応の形式: {path}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"  [エラー] 読み込み失敗 {path}: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 集計
# ---------------------------------------------------------------------------

def resolve_ptr(ip: str, cache: dict) -> str:
    """IP の逆引きホスト名を取得（失敗時は空文字）。結果はキャッシュ。"""
    if ip in cache:
        return cache[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        host = ""
    cache[ip] = host
    return host


def summarize(reports, resolve_dns=False):
    """全レポートを横断集計してダッシュボード用の統計を返す。"""
    stats = {
        "total_messages": 0,
        "pass_messages": 0,       # DMARC 準拠
        "fail_messages": 0,       # 非準拠
        "disp_none": 0,
        "disp_quarantine": 0,
        "disp_reject": 0,
        "by_ip": defaultdict(lambda: {
            "count": 0, "pass": 0, "fail": 0, "host": "",
            "dispositions": defaultdict(int),
        }),
        "by_org": defaultdict(lambda: {"count": 0, "pass": 0, "fail": 0}),
        "domains": set(),
        "date_min": None,
        "date_max": None,
    }

    ptr_cache = {}

    for rep in reports:
        if rep.domain:
            stats["domains"].add(rep.domain)
        if rep.date_begin:
            stats["date_min"] = (rep.date_begin if stats["date_min"] is None
                                 else min(stats["date_min"], rep.date_begin))
        if rep.date_end:
            stats["date_max"] = (rep.date_end if stats["date_max"] is None
                                 else max(stats["date_max"], rep.date_end))

        for r in rep.records:
            n = r.count
            stats["total_messages"] += n

            if r.aligned:
                stats["pass_messages"] += n
            else:
                stats["fail_messages"] += n

            disp = r.disposition or "none"
            if disp == "none":
                stats["disp_none"] += n
            elif disp == "quarantine":
                stats["disp_quarantine"] += n
            elif disp == "reject":
                stats["disp_reject"] += n

            ip = stats["by_ip"][r.source_ip]
            ip["count"] += n
            ip["dispositions"][disp] += n
            if r.aligned:
                ip["pass"] += n
            else:
                ip["fail"] += n
            if resolve_dns and not ip["host"]:
                ip["host"] = resolve_ptr(r.source_ip, ptr_cache)

            org = stats["by_org"][rep.org_name]
            org["count"] += n
            if r.aligned:
                org["pass"] += n
            else:
                org["fail"] += n

    return stats


# ---------------------------------------------------------------------------
# HTML 生成
# ---------------------------------------------------------------------------

def _fmt_ts(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _pct(part, whole):
    if not whole:
        return 0.0
    return part / whole * 100.0


def make_output_filename(stats):
    """ドメインと集計期間から出力ファイル名を自動生成する。

    例: dmarc_morinoichigo.net_20260721-20260722.html
    複数ドメインが混在する場合は "multi" とする。
    """
    domains = sorted(stats["domains"])
    if len(domains) == 1:
        domain_part = domains[0]
    elif len(domains) > 1:
        domain_part = "multi"
    else:
        domain_part = "unknown"
    # ファイル名に使えない文字を除去
    domain_part = re.sub(r'[^A-Za-z0-9._-]', '_', domain_part)

    def _date(ts):
        if not ts:
            return "unknown"
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")

    begin = _date(stats["date_min"])
    end = _date(stats["date_max"])
    period_part = begin if begin == end else f"{begin}-{end}"

    return f"dmarc_{domain_part}_{period_part}.html"


def _e(s):
    return html.escape(str(s) if s is not None else "")


def _badge(result):
    """pass/fail/softfail などを色付きバッジに。"""
    r = (result or "").lower()
    if r == "pass":
        cls = "ok"
    elif r in ("fail", "reject"):
        cls = "bad"
    elif r in ("softfail", "quarantine", "neutral", "none"):
        cls = "warn"
    else:
        cls = "muted"
    label = result or "-"
    return f'<span class="badge {cls}">{_e(label)}</span>'


def _disposition_badge(disp):
    d = (disp or "none").lower()
    cls = {"none": "ok", "quarantine": "warn", "reject": "bad"}.get(d, "muted")
    jp = {"none": "配信 (none)", "quarantine": "隔離 (quarantine)",
          "reject": "拒否 (reject)"}.get(d, disp)
    return f'<span class="badge {cls}">{_e(jp)}</span>'


def build_html(reports, stats) -> str:
    total = stats["total_messages"]
    pass_pct = _pct(stats["pass_messages"], total)
    fail_pct = _pct(stats["fail_messages"], total)

    domains = ", ".join(sorted(stats["domains"])) or "-"
    period = f'{_fmt_ts(stats["date_min"])} 〜 {_fmt_ts(stats["date_max"])}'
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 送信元 IP テーブル（メッセージ数の多い順）
    ip_rows = sorted(stats["by_ip"].items(),
                     key=lambda kv: kv[1]["count"], reverse=True)
    ip_html = []
    for ip, d in ip_rows:
        rate = _pct(d["pass"], d["count"])
        rate_cls = "ok" if rate >= 99.9 else ("warn" if rate >= 80 else "bad")
        host = _e(d["host"]) if d["host"] else '<span class="muted">-</span>'
        ip_html.append(f"""
        <tr>
          <td class="mono">{_e(ip)}</td>
          <td>{host}</td>
          <td class="num">{d['count']:,}</td>
          <td class="num ok-text">{d['pass']:,}</td>
          <td class="num bad-text">{d['fail']:,}</td>
          <td class="num">
            <div class="bar-wrap">
              <div class="bar {rate_cls}" style="width:{rate:.0f}%"></div>
              <span class="bar-label">{rate:.1f}%</span>
            </div>
          </td>
        </tr>""")

    # 送信元組織テーブル
    org_rows = sorted(stats["by_org"].items(),
                      key=lambda kv: kv[1]["count"], reverse=True)
    org_html = []
    for org, d in org_rows:
        rate = _pct(d["pass"], d["count"])
        rate_cls = "ok" if rate >= 99.9 else ("warn" if rate >= 80 else "bad")
        org_html.append(f"""
        <tr>
          <td>{_e(org)}</td>
          <td class="num">{d['count']:,}</td>
          <td class="num ok-text">{d['pass']:,}</td>
          <td class="num bad-text">{d['fail']:,}</td>
          <td class="num">
            <div class="bar-wrap">
              <div class="bar {rate_cls}" style="width:{rate:.0f}%"></div>
              <span class="bar-label">{rate:.1f}%</span>
            </div>
          </td>
        </tr>""")

    # レポート別の詳細（折りたたみ）
    detail_html = []
    for rep in sorted(reports, key=lambda r: r.date_begin):
        rec_rows = []
        for r in sorted(rep.records, key=lambda x: x.count, reverse=True):
            reason = ""
            if r.reason_type or r.reason_comment:
                reason = (f'<div class="reason">理由: {_e(r.reason_type)} '
                          f'{_e(r.reason_comment)}</div>')
            dkim_detail = ""
            if r.dkim_domain or r.dkim_selector:
                sel = f" / selector: {_e(r.dkim_selector)}" if r.dkim_selector else ""
                dkim_detail = (f'<div class="sub">DKIM: {_e(r.dkim_domain)}'
                               f'{sel} → {_badge(r.dkim_result)}</div>')
            spf_detail = ""
            if r.spf_domain:
                spf_detail = (f'<div class="sub">SPF: {_e(r.spf_domain)} '
                              f'→ {_badge(r.spf_result)}</div>')
            row_cls = "" if r.aligned else "row-fail"
            rec_rows.append(f"""
            <tr class="{row_cls}">
              <td class="mono">{_e(r.source_ip)}</td>
              <td class="num">{r.count:,}</td>
              <td>{_disposition_badge(r.disposition)}{reason}</td>
              <td>{_badge(r.dkim_eval)}{dkim_detail}</td>
              <td>{_badge(r.spf_eval)}{spf_detail}</td>
              <td>{'<span class="badge ok">準拠</span>' if r.aligned
                   else '<span class="badge bad">非準拠</span>'}</td>
            </tr>""")

        detail_html.append(f"""
      <details class="report-block">
        <summary>
          <span class="rep-org">{_e(rep.org_name)}</span>
          <span class="rep-meta">{_fmt_ts(rep.date_begin)} 〜 {_fmt_ts(rep.date_end)}
            ・ {rep.total_count:,} 通 ・ ポリシー: p={_e(rep.policy_p or '-')}</span>
        </summary>
        <div class="rep-info">
          <span>ドメイン: <b>{_e(rep.domain)}</b></span>
          <span>連絡先: {_e(rep.email)}</span>
          <span>レポートID: <span class="mono">{_e(rep.report_id)}</span></span>
          <span>整合: adkim={_e(rep.policy_adkim or '-')} / aspf={_e(rep.policy_aspf or '-')} / pct={_e(rep.policy_pct or '-')}</span>
          <span class="muted">source: {_e(rep.source_file)}</span>
        </div>
        <div class="table-scroll">
        <table class="detail">
          <thead><tr>
            <th>送信元 IP</th><th>通数</th><th>処理 (disposition)</th>
            <th>DKIM</th><th>SPF</th><th>DMARC 判定</th>
          </tr></thead>
          <tbody>{''.join(rec_rows)}</tbody>
        </table>
        </div>
      </details>""")

    # 円グラフ用（CSS conic-gradient）
    donut = (f"conic-gradient(var(--ok) 0 {pass_pct:.2f}%, "
             f"var(--bad) {pass_pct:.2f}% 100%)")

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DMARC 集約レポート — {_e(domains)}</title>
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --card2: #263449;
    --text: #e2e8f0; --muted: #94a3b8; --border: #334155;
    --ok: #22c55e; --bad: #ef4444; --warn: #f59e0b; --accent: #38bdf8;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, "Segoe UI", "Hiragino Kaku Gothic ProN",
      "Yu Gothic", Meiryo, sans-serif; line-height: 1.6;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 28px 20px 64px; }}
  header h1 {{ margin: 0 0 4px; font-size: 24px; }}
  header .sub {{ color: var(--muted); font-size: 14px; }}
  .grid {{ display: grid; gap: 16px; }}
  .cards {{ grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); margin: 24px 0; }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 18px 20px;
  }}
  .card .k {{ color: var(--muted); font-size: 13px; margin-bottom: 6px; }}
  .card .v {{ font-size: 28px; font-weight: 700; }}
  .card .v.ok-text {{ color: var(--ok); }}
  .card .v.bad-text {{ color: var(--bad); }}
  .card .foot {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .overview {{
    display: grid; grid-template-columns: 200px 1fr; gap: 24px;
    align-items: center; background: var(--card);
    border: 1px solid var(--border); border-radius: 12px; padding: 24px;
  }}
  .donut {{
    width: 170px; height: 170px; border-radius: 50%;
    background: {donut}; display: grid; place-items: center; margin: 0 auto;
  }}
  .donut .hole {{
    width: 112px; height: 112px; border-radius: 50%; background: var(--card);
    display: grid; place-items: center; text-align: center;
  }}
  .donut .hole .big {{ font-size: 26px; font-weight: 700; color: var(--ok); }}
  .donut .hole .lbl {{ font-size: 11px; color: var(--muted); }}
  .legend {{ display: flex; gap: 20px; flex-wrap: wrap; }}
  .legend .item {{ display: flex; align-items: center; gap: 8px; }}
  .dot {{ width: 12px; height: 12px; border-radius: 3px; display: inline-block; }}
  .dot.ok {{ background: var(--ok); }} .dot.bad {{ background: var(--bad); }}
  .dot.warn {{ background: var(--warn); }}
  h2 {{ font-size: 18px; margin: 34px 0 12px; border-left: 4px solid var(--accent);
    padding-left: 10px; }}
  .table-scroll {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card);
    border-radius: 10px; overflow: hidden; font-size: 14px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--card2); color: var(--muted); font-weight: 600;
    font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  tbody tr:hover {{ background: rgba(255,255,255,.03); }}
  .mono {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }}
  .muted {{ color: var(--muted); }}
  .ok-text {{ color: var(--ok); }} .bad-text {{ color: var(--bad); }}
  .badge {{ display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 12px; font-weight: 600; }}
  .badge.ok {{ background: rgba(34,197,94,.15); color: #4ade80; }}
  .badge.bad {{ background: rgba(239,68,68,.15); color: #f87171; }}
  .badge.warn {{ background: rgba(245,158,11,.15); color: #fbbf24; }}
  .badge.muted {{ background: rgba(148,163,184,.15); color: var(--muted); }}
  .bar-wrap {{ position: relative; background: var(--card2); border-radius: 6px;
    height: 20px; min-width: 90px; overflow: hidden; }}
  .bar {{ height: 100%; border-radius: 6px; }}
  .bar.ok {{ background: var(--ok); }} .bar.warn {{ background: var(--warn); }}
  .bar.bad {{ background: var(--bad); }}
  .bar-label {{ position: absolute; right: 8px; top: 0; line-height: 20px;
    font-size: 11px; font-weight: 600; }}
  details.report-block {{ background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; margin-bottom: 12px; overflow: hidden; }}
  details summary {{ cursor: pointer; padding: 14px 18px; list-style: none;
    display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;
    align-items: center; }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary:hover {{ background: var(--card2); }}
  .rep-org {{ font-weight: 700; font-size: 15px; }}
  .rep-meta {{ color: var(--muted); font-size: 13px; }}
  .rep-info {{ display: flex; flex-wrap: wrap; gap: 6px 20px; padding: 4px 18px 14px;
    color: var(--muted); font-size: 13px; }}
  .rep-info b {{ color: var(--text); }}
  table.detail {{ margin: 0 0 14px; }}
  .row-fail {{ background: rgba(239,68,68,.06); }}
  .sub {{ color: var(--muted); font-size: 11px; margin-top: 3px; }}
  .reason {{ color: var(--warn); font-size: 11px; margin-top: 3px; }}
  footer {{ margin-top: 40px; color: var(--muted); font-size: 12px; text-align: center; }}
  a {{ color: var(--accent); }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>📧 DMARC 集約レポート</h1>
    <div class="sub">対象ドメイン: <b>{_e(domains)}</b> ・ 集計期間: {period}</div>
  </header>

  <div class="grid cards">
    <div class="card"><div class="k">総メッセージ数</div>
      <div class="v">{total:,}</div>
      <div class="foot">レポート {len(reports)} 件を集計</div></div>
    <div class="card"><div class="k">DMARC 準拠</div>
      <div class="v ok-text">{stats['pass_messages']:,}</div>
      <div class="foot">{pass_pct:.1f}% が認証成功</div></div>
    <div class="card"><div class="k">DMARC 非準拠</div>
      <div class="v bad-text">{stats['fail_messages']:,}</div>
      <div class="foot">{fail_pct:.1f}% が認証失敗</div></div>
    <div class="card"><div class="k">送信元 IP 数</div>
      <div class="v">{len(stats['by_ip']):,}</div>
      <div class="foot">ユニークな送信元</div></div>
  </div>

  <div class="overview">
    <div class="donut"><div class="hole">
      <div><div class="big">{pass_pct:.1f}%</div>
      <div class="lbl">DMARC 準拠率</div></div>
    </div></div>
    <div>
      <h2 style="margin-top:0;border:none;padding:0">認証結果の内訳</h2>
      <div class="legend">
        <div class="item"><span class="dot ok"></span>準拠 {stats['pass_messages']:,} 通 ({pass_pct:.1f}%)</div>
        <div class="item"><span class="dot bad"></span>非準拠 {stats['fail_messages']:,} 通 ({fail_pct:.1f}%)</div>
      </div>
      <div style="margin-top:16px" class="legend">
        <div class="item"><span class="dot ok"></span>配信 none: {stats['disp_none']:,}</div>
        <div class="item"><span class="dot warn"></span>隔離 quarantine: {stats['disp_quarantine']:,}</div>
        <div class="item"><span class="dot bad"></span>拒否 reject: {stats['disp_reject']:,}</div>
      </div>
    </div>
  </div>

  <h2>送信元 IP 別サマリー</h2>
  <div class="table-scroll">
  <table>
    <thead><tr>
      <th>送信元 IP</th><th>ホスト名 (PTR)</th><th>通数</th>
      <th>準拠</th><th>非準拠</th><th>準拠率</th>
    </tr></thead>
    <tbody>{''.join(ip_html)}</tbody>
  </table>
  </div>

  <h2>送信元組織 (レポート提供者) 別サマリー</h2>
  <div class="table-scroll">
  <table>
    <thead><tr>
      <th>組織</th><th>通数</th><th>準拠</th><th>非準拠</th><th>準拠率</th>
    </tr></thead>
    <tbody>{''.join(org_html)}</tbody>
  </table>
  </div>

  <h2>レポート別 詳細</h2>
  {''.join(detail_html)}

  <footer>
    生成日時: {generated} ・ DMARC Aggregate Report Viewer<br>
    「準拠」= DKIM または SPF が DMARC 整合。「非準拠」= どちらも失敗し、なりすまし等の可能性。
  </footer>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DMARC 集約レポート(XML)を HTML に変換します。")
    parser.add_argument("inputs", nargs="+",
                        help="XML/.gz/.zip ファイル、またはそれらを含むディレクトリ")
    parser.add_argument("-o", "--output", default=None,
                        help="出力 HTML ファイル名 (既定: ドメインと集計期間から自動生成"
                             " 例 dmarc_example.com_20260721-20260722.html)")
    parser.add_argument("--resolve-dns", action="store_true",
                        help="送信元 IP の逆引き(PTR)を行う (遅くなる場合あり)")
    parser.add_argument("--open", action="store_true",
                        help="生成後に既定ブラウザで開く")
    args = parser.parse_args()

    print("DMARC レポートを解析中...")
    reports = []
    for xml_bytes, source in iter_xml_sources(args.inputs):
        try:
            rep = parse_report(xml_bytes, source)
            reports.append(rep)
            print(f"  [OK] {source} — {rep.org_name}, {rep.total_count} 通")
        except ET.ParseError as e:
            print(f"  [エラー] XML 解析失敗 {source}: {e}", file=sys.stderr)

    if not reports:
        print("有効な DMARC レポートが見つかりませんでした。", file=sys.stderr)
        sys.exit(1)

    stats = summarize(reports, resolve_dns=args.resolve_dns)
    html_str = build_html(reports, stats)

    output = args.output or make_output_filename(stats)
    with open(output, "w", encoding="utf-8") as f:
        f.write(html_str)

    print(f"\n完了: {len(reports)} レポート / 計 {stats['total_messages']:,} 通")
    print(f"HTML を出力しました → {os.path.abspath(output)}")

    if args.open:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(output))


if __name__ == "__main__":
    main()
