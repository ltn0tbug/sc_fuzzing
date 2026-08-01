"""Fetch verified Solidity sources for the curated DeFiHackLabs target contracts.

Uses the Etherscan **v2 unified API** (one key works across all supported chains
via the `chainid` query param). Free-tier rate limit is 5 req/s — we throttle to
4 req/s to leave headroom for retries.

Usage:
    uv run python utils/fetch_defihacklabs_sources.py [--force]

Reads `ETHERSCAN_API_KEY` from `.env`. Caches under
`data/defihacklabs/source/<safe_id>/`:
    - raw.json          full Etherscan response (audit trail)
    - meta.json         normalized: name, compiler, optimizer, runs, proxy, impl
    - <ContractName>.sol  primary source (multi-file projects are also written
                          as a tree under `src/` next to it)
For proxy targets, the implementation address is resolved and fetched too; the
"primary" source is the impl, not the proxy.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT       = Path(__file__).resolve().parents[1]   # repo root (utils is 1 level deep)
DOTENV     = ROOT / ".env"
CURATED    = ROOT / "utils" / "legacy_intermediate" / "curated_targets.json"
SRC_DIR    = ROOT / "data" / "defihacklabs" / "source"

API_URL    = "https://api.etherscan.io/v2/api"
CHAIN_ID   = {"mainnet": 1, "bsc": 56, "fantom": 250, "avalanche": 43114,
              "arbitrum": 42161, "polygon": 137, "base": 8453, "optimism": 10}
MIN_DELAY  = 0.25   # ~4 req/s, under the 5 req/s free-tier cap

# Etherscan v2 unified API does NOT serve every chain we reference (notably
# Fantom/250 — "unsupported chainid"), and some targets are simply unverified on
# Etherscan even when their source was published elsewhere. Sourcify is a
# keyless, multi-chain verification registry that uses the same numeric chainid;
# we query it as a fallback whenever Etherscan returns no source. This is a
# generic provider fallback — it does not target any specific dataset row.
SOURCIFY_API = "https://sourcify.dev/server"


def load_env_key() -> str:
    if not DOTENV.exists():
        sys.exit(".env not found")
    for line in DOTENV.read_text().splitlines():
        line = line.strip()
        if line.startswith("ETHERSCAN_API_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("ETHERSCAN_API_KEY not set in .env")


_LAST_CALL = 0.0
def throttled_get(params: dict) -> dict:
    """Single Etherscan v2 GET with throttling + minimal retry."""
    global _LAST_CALL
    url = f"{API_URL}?{urlencode(params)}"
    for attempt in range(1, 4):
        dt = MIN_DELAY - (time.monotonic() - _LAST_CALL)
        if dt > 0:
            time.sleep(dt)
        _LAST_CALL = time.monotonic()
        try:
            with urlopen(Request(url, headers={"User-Agent": "sc-fuzzing/1"}), timeout=30) as r:
                body = json.loads(r.read().decode())
            # Etherscan returns 200 even on errors; check the envelope.
            if isinstance(body, dict) and body.get("status") in ("1", "0"):
                return body
            return body
        except Exception as e:
            if attempt == 3:
                raise
            print(f"  retry {attempt}/3 after {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(0.5 * attempt)
    raise RuntimeError("unreachable")


def fetch_source(api_key: str, chain: str, address: str) -> dict:
    body = throttled_get({
        "chainid": CHAIN_ID[chain],
        "module":  "contract",
        "action":  "getsourcecode",
        "address": address,
        "apikey":  api_key,
    })
    if not isinstance(body, dict) or body.get("status") not in ("1", "0"):
        raise RuntimeError(f"unexpected envelope: {str(body)[:200]}")
    if not body.get("result"):
        raise RuntimeError(f"empty result: {body}")
    return body


def fetch_source_sourcify(chain: str, address: str) -> dict | None:
    """Fallback provider: query Sourcify v2 for verified source.

    Returns a dict shaped like the fields we consume from an Etherscan record
    (``ContractName``/``SourceCode``-as-files/``CompilerVersion``/…) or None when
    Sourcify has no match. Keyless; uses the same numeric chainid as Etherscan.
    """
    cid = CHAIN_ID.get(chain)
    if cid is None:
        return None
    url = f"{SOURCIFY_API}/v2/contract/{cid}/{address}?fields=sources,compilation"
    req = Request(url, headers={"User-Agent": "sc-fuzzing/1"})
    try:
        with urlopen(req, timeout=40) as r:
            body = json.loads(r.read().decode())
    except HTTPError as e:
        if e.code != 404:   # 404 = no match (the common case)
            print(f"  sourcify probe error for {address}: HTTP {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  sourcify probe error for {address}: {type(e).__name__}: {e}", file=sys.stderr)
        return None
    if not body or body.get("match") is None:
        return None
    sources = body.get("sources") or {}          # {path: {"content": ...}}
    if not sources:
        return None
    comp = body.get("compilation") or {}
    return {
        "_provider": "sourcify",
        "ContractName": comp.get("name") or "Contract",
        "CompilerVersion": comp.get("compilerVersion") or comp.get("compiler") or "",
        "EVMVersion": comp.get("evmVersion") or "default",
        "OptimizationUsed": "0",
        "Runs": "200",
        "LicenseType": "",
        "ABI": "",
        "Proxy": "0",
        "Implementation": "",
        # Mirror the Etherscan multi-file envelope so split_multifile() reuses it.
        "_sourcify_files": {p: (v.get("content") or "") for p, v in sources.items()},
    }


def split_multifile(source_code: str) -> dict[str, str] | None:
    """Etherscan wraps multi-file projects as `{{ ... }}` JSON. Single-file
    contracts just return raw Solidity. Returns {path: content} or None for
    single-file."""
    sc = source_code.strip()
    if sc.startswith("{{") and sc.endswith("}}"):
        # Standard JSON-input envelope, double-braced
        try:
            data = json.loads(sc[1:-1])
        except json.JSONDecodeError:
            return None
        if "sources" in data and isinstance(data["sources"], dict):
            return {k: v.get("content", "") for k, v in data["sources"].items()}
        return None
    if sc.startswith("{") and sc.endswith("}"):
        # Some BscScan responses use single-brace JSON
        try:
            data = json.loads(sc)
        except json.JSONDecodeError:
            return None
        if "sources" in data and isinstance(data["sources"], dict):
            return {k: v.get("content", "") for k, v in data["sources"].items()}
        # Some return {FileName.sol: {content: ...}} directly
        if all(isinstance(v, dict) and "content" in v for v in data.values()):
            return {k: v["content"] for k, v in data.items()}
    return None


def safe_path(p: str) -> str:
    """Sanitize a file path from Etherscan source bundle to avoid `..` escapes."""
    # Replace backslashes, strip leading slashes, drop any `..` segments.
    parts = [
        seg for seg in re.split(r"[/\\]", p.strip())
        if seg and seg != "." and seg != ".."
    ]
    return "/".join(parts) if parts else "contract.sol"


def is_empty_response(rec: dict) -> bool:
    """An unverified contract returns a record with all-empty strings. A Sourcify
    fallback record carries its files under ``_sourcify_files`` instead."""
    return not ((rec.get("SourceCode") or "").strip() or rec.get("_sourcify_files"))


def save_one(api_key: str, target_id: str, chain: str, address: str, *, force: bool) -> dict:
    """Fetch + persist one target (handles proxy chasing). Returns meta dict."""
    safe_id = target_id.replace("/", "_")
    out_dir = SRC_DIR / safe_id
    if out_dir.exists() and (out_dir / "meta.json").exists() and not force:
        meta = json.loads((out_dir / "meta.json").read_text())
        print(f"  [cached] {target_id} → {meta.get('contract_name')}")
        return meta

    out_dir.mkdir(parents=True, exist_ok=True)

    # Provider 1: Etherscan v2 (may raise on unsupported chains, e.g. Fantom).
    rec = None
    try:
        body = fetch_source(api_key, chain, address)
        (out_dir / "raw.json").write_text(json.dumps(body, indent=2))
        rec = body["result"][0] if isinstance(body["result"], list) else body["result"]
        if is_empty_response(rec):
            rec = None
    except Exception as e:
        print(f"  [etherscan-miss] {target_id}: {type(e).__name__}: {e}", file=sys.stderr)
        rec = None

    # Provider 2 (fallback): Sourcify — keyless, multi-chain, same chainid.
    if rec is None:
        sf = fetch_source_sourcify(chain, address)
        if sf is not None:
            print(f"  [sourcify] {target_id} recovered via Sourcify")
            rec = sf

    if rec is None or is_empty_response(rec):
        meta = {
            "target_id": target_id,
            "chain": chain,
            "address": address.lower(),
            "verified": False,
            "skip_reason": "no_verified_source_etherscan_sourcify",
        }
        (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))
        print(f"  [skip] {target_id} unverified (no source at Etherscan/Sourcify)")
        return meta

    proxy = rec.get("Proxy") == "1"
    impl_address = (rec.get("Implementation") or "").strip()
    impl_rec = None
    impl_body = None
    if proxy and impl_address and impl_address.lower() != address.lower():
        print(f"  [proxy] {target_id} → impl {impl_address}")
        impl_body = fetch_source(api_key, chain, impl_address)
        (out_dir / "impl.raw.json").write_text(json.dumps(impl_body, indent=2))
        impl_rec = impl_body["result"][0] if isinstance(impl_body["result"], list) else impl_body["result"]
        if is_empty_response(impl_rec):
            meta = {
                "target_id": target_id,
                "chain": chain,
                "address": address.lower(),
                "verified": False,
                "proxy": True,
                "implementation": impl_address.lower(),
                "skip_reason": "proxy_impl_unverified",
            }
            (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))
            print(f"  [skip] {target_id} proxy with unverified impl")
            return meta

    primary = impl_rec or rec
    contract_name = primary.get("ContractName") or "Contract"
    compiler      = primary.get("CompilerVersion", "")
    optimizer     = primary.get("OptimizationUsed", "0") == "1"
    runs          = int(primary.get("Runs") or "200")
    license_type  = primary.get("LicenseType", "")
    evm_version   = primary.get("EVMVersion", "default")
    abi_raw       = primary.get("ABI") or ""

    # Write source: multi-file → tree under src/; single-file → <name>.sol.
    files = primary.get("_sourcify_files") or split_multifile(primary.get("SourceCode", ""))
    written_files: list[str] = []
    if files:
        src_root = out_dir / "src"
        src_root.mkdir(exist_ok=True)
        for path, content in files.items():
            sp = safe_path(path)
            fp = src_root / sp
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content)
            written_files.append(f"src/{sp}")
    else:
        fp = out_dir / f"{contract_name}.sol"
        fp.write_text(primary.get("SourceCode", ""))
        written_files.append(f"{contract_name}.sol")

    # ABI: Etherscan returns JSON string or "Contract source code not verified"
    abi_path = None
    if abi_raw and not abi_raw.startswith("Contract source"):
        try:
            abi = json.loads(abi_raw)
            (out_dir / "abi.json").write_text(json.dumps(abi, indent=2))
            abi_path = "abi.json"
        except json.JSONDecodeError:
            pass

    meta = {
        "target_id": target_id,
        "chain": chain,
        "address": address.lower(),
        "verified": True,
        "provider": primary.get("_provider", "etherscan"),
        "proxy": proxy,
        "implementation": impl_address.lower() if impl_address else None,
        "contract_name": contract_name,
        "compiler_version": compiler,
        "evm_version": evm_version,
        "optimizer": optimizer,
        "optimizer_runs": runs,
        "license": license_type,
        "source_files": written_files,
        "primary_source": written_files[0] if not files else None,
        "multifile": bool(files),
        "abi_path": abi_path,
        "fetched_at_unix": int(time.time()),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  [ok]   {target_id} → {contract_name} ({len(written_files)} file(s))")
    return meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="Re-fetch even if cached")
    args = ap.parse_args()

    if not CURATED.exists():
        sys.exit(f"missing curated targets file: {CURATED}")
    targets = json.loads(CURATED.read_text())
    api_key = load_env_key()

    SRC_DIR.mkdir(parents=True, exist_ok=True)
    ok = skipped = 0
    metas: list[dict] = []
    print(f"Fetching {len(targets)} targets (throttle ≈4 req/s) …")
    for t in targets:
        try:
            meta = save_one(
                api_key,
                target_id=t["id"],
                chain=t["chain"],
                address=t["target_address"],
                force=args.force,
            )
            metas.append(meta)
            if meta.get("verified"):
                ok += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  [ERROR] {t['id']}: {type(e).__name__}: {e}", file=sys.stderr)
            skipped += 1
            metas.append({"target_id": t["id"], "verified": False, "skip_reason": f"fetch_error:{e}"})
    (SRC_DIR / "_index.json").write_text(json.dumps(metas, indent=2))
    print(f"\nDone — verified={ok}  skipped/failed={skipped}  total={len(targets)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
