#!/usr/bin/env python3
"""Estimate MLSAGS verification gas against a local Geth JSON-RPC node."""

from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_DIR = ROOT / "py"
if str(PY_DIR) not in sys.path:
    sys.path.insert(0, str(PY_DIR))

import sha3  # noqa: E402


DEFAULT_RING_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256]
DEFAULT_SPOT_CHECK_SIZES = [8, 64]
DEFAULT_RPC_URL = "http://127.0.0.1:8545"
DEFAULT_VECTOR_DIR = ROOT / "results" / "fig10_ringsig" / "vectors"
DEFAULT_OUTDIR = ROOT / "results" / "fig10_ringsig"
DEFAULT_TX_GAS_CAP = 16_000_000
SOLC_INPUTS = [
    "contracts/Debuggable.sol",
    "contracts/ECMathInterface.sol",
    "contracts/ECMath.sol",
    "contracts/MLSAGVerify.sol",
]


class JsonRpcClient:
    def __init__(self, rpc_url: str, timeout: int = 30):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self._request_id = 0

    def call(self, method: str, params: list):
        self._request_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": params,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"JSON-RPC request failed for {method}: {exc}") from exc

        if body.get("error"):
            raise RuntimeError(f"JSON-RPC error for {method}: {body['error']}")
        return body["result"]


def parse_ring_sizes(value: str) -> list[int]:
    sizes = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        parsed = int(item)
        if parsed <= 0:
            raise argparse.ArgumentTypeError("ring sizes must be positive integers")
        sizes.append(parsed)
    if not sizes:
        raise argparse.ArgumentTypeError("at least one ring size is required")
    return sizes


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def read_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def format_float(value: float) -> str:
    return f"{value:.6f}"


def hex_to_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = value.strip()
    return int(text, 16) if text.startswith("0x") else int(text)


def encode_uint256(value: int) -> str:
    return value.to_bytes(32, byteorder="big").hex()


def encode_address(value: str) -> str:
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != 20:
        raise ValueError(f"address must be 20 bytes, got {value}")
    return raw.rjust(32, b"\x00").hex()


def encode_uint256_array(values: list[int]) -> str:
    return encode_uint256(len(values)) + "".join(encode_uint256(value) for value in values)


def function_selector(signature: str) -> str:
    return sha3.keccak_256(signature.encode("utf-8")).digest()[:4].hex()


def build_constructor_data(bytecode: str, encoded_args: list[str]) -> str:
    base = bytecode.removeprefix("0x")
    return "0x" + base + "".join(encoded_args)


def build_verify_mlsag_call(msg_hash: int, key_images: list[int], pubkeys: list[int], signature: list[int]) -> str:
    selector = function_selector("VerifyMLSAG(uint256,uint256[],uint256[],uint256[])")
    i_block = encode_uint256_array(key_images)
    p_block = encode_uint256_array(pubkeys)
    s_block = encode_uint256_array(signature)
    head_size = 32 * 4
    i_offset = head_size
    p_offset = i_offset + (len(i_block) // 2)
    s_offset = p_offset + (len(p_block) // 2)
    payload = (
        encode_uint256(msg_hash)
        + encode_uint256(i_offset)
        + encode_uint256(p_offset)
        + encode_uint256(s_offset)
        + i_block
        + p_block
        + s_block
    )
    return "0x" + selector + payload


def decode_bool(result_hex: str) -> bool:
    return bool(int(result_hex, 16))


def hex_quantity(value: int) -> str:
    return hex(value)


def extract_bytecode(artifact: dict) -> str:
    for candidate in (
        artifact.get("bytecode"),
        artifact.get("data", {}).get("bytecode", {}).get("object"),
        artifact.get("evm", {}).get("bytecode", {}).get("object"),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate if candidate.startswith("0x") else f"0x{candidate}"
    raise RuntimeError("could not locate bytecode in artifact")


def load_committed_artifacts() -> dict[str, dict]:
    ec_artifact = read_json(ROOT / "contracts" / "artifacts" / "ECMath.json")
    mlsag_artifact = read_json(ROOT / "contracts" / "artifacts" / "MLSAGVerify.json")
    return {
        "source": "committed_artifacts",
        "ECMath": {
            "abi": ec_artifact["abi"],
            "bytecode": extract_bytecode(ec_artifact),
        },
        "MLSAGVerify": {
            "abi": mlsag_artifact["abi"],
            "bytecode": extract_bytecode(mlsag_artifact),
        },
    }


def compile_optimized_artifacts(output_dir: Path) -> dict[str, dict]:
    if output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "npx",
        "solc@0.4.24",
        "--optimize",
        "--bin",
        "--abi",
        "-o",
        str(output_dir),
        *SOLC_INPUTS,
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "optimized solc 0.4.24 compile failed:\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    def read_compiled(contract_name: str, stem: str) -> dict:
        abi = json.loads((output_dir / f"{stem}.abi").read_text(encoding="utf-8"))
        bytecode = (output_dir / f"{stem}.bin").read_text(encoding="utf-8").strip()
        if not bytecode.startswith("0x"):
            bytecode = f"0x{bytecode}"
        return {"abi": abi, "bytecode": bytecode}

    return {
        "source": "optimized_solc_0_4_24",
        "ECMath": read_compiled("ECMath", "contracts_ECMath_sol_ECMath"),
        "MLSAGVerify": read_compiled("MLSAGVerify", "contracts_MLSAGVerify_sol_MLSAGVerify"),
    }


def load_vector_file(path: Path) -> dict:
    record = read_json(path)
    key_images = record["key_images"]
    pubkeys = record["pubkeys"]
    signature = record["signature"]

    if key_images and isinstance(key_images[0], dict):
        flat_key_images: list[str] = []
        for point in key_images:
            flat_key_images.extend([point["x"], point["y"]])
        key_images = flat_key_images

    if pubkeys and isinstance(pubkeys[0], dict):
        flat_pubkeys: list[str] = []
        for point in pubkeys:
            flat_pubkeys.extend([point["x"], point["y"]])
        pubkeys = flat_pubkeys

    return {
        "ring_size": int(record["ring_size"]),
        "rep": int(record["rep"]),
        "msg_hash": hex_to_int(record["message_hash"]),
        "key_images": [hex_to_int(value) for value in key_images],
        "pubkeys": [hex_to_int(value) for value in pubkeys],
        "signature": [hex_to_int(value) for value in signature],
        "source_file": str(path.relative_to(ROOT)),
    }


def load_vectors(vector_dir: Path, ring_sizes: set[int]) -> list[dict]:
    vectors = []
    for path in sorted(vector_dir.glob("L*_rep*.json")):
        record = load_vector_file(path)
        if record["ring_size"] in ring_sizes:
            vectors.append(record)
    vectors.sort(key=lambda row: (row["ring_size"], row["rep"]))
    if not vectors:
        raise RuntimeError(f"no vector JSON files found in {vector_dir}")
    return vectors


def wait_for_receipt(client: JsonRpcClient, tx_hash: str, timeout_seconds: float = 180.0) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        receipt = client.call("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for receipt: {tx_hash}")


def estimate_gas(client: JsonRpcClient, tx: dict) -> int:
    return int(client.call("eth_estimateGas", [tx]), 16)


def send_transaction(client: JsonRpcClient, tx: dict) -> str:
    return client.call("eth_sendTransaction", [tx])


def latest_block_gas_limit(client: JsonRpcClient) -> int:
    block = client.call("eth_getBlockByNumber", ["latest", False])
    return int(block["gasLimit"], 16)


def deploy_contract(client: JsonRpcClient, from_addr: str, gas_price: str, data: str, tx_gas_cap: int) -> dict:
    tx = {"from": from_addr, "data": data}
    block_gas_limit = latest_block_gas_limit(client)
    max_tx_gas = math.floor(block_gas_limit * 0.95)
    if tx_gas_cap > 0:
        max_tx_gas = min(max_tx_gas, tx_gas_cap)
    try:
        estimated = estimate_gas(client, tx)
    except RuntimeError:
        estimated = max_tx_gas
    tx["gas"] = hex_quantity(min(math.ceil(estimated * 1.2), max_tx_gas))
    tx["gasPrice"] = gas_price
    tx_hash = send_transaction(client, tx)
    receipt = wait_for_receipt(client, tx_hash)
    if receipt.get("status") not in ("0x1", 1):
        raise RuntimeError(f"deployment failed: {tx_hash}")
    return {
        "tx_hash": tx_hash,
        "contract_address": receipt["contractAddress"],
        "gas_used": int(receipt["gasUsed"], 16),
    }


def deploy_verifier_pair(
    client: JsonRpcClient,
    from_addr: str,
    gas_price: str,
    artifacts: dict,
    tx_gas_cap: int,
) -> tuple[dict, dict]:
    ec_deploy = deploy_contract(
        client,
        from_addr,
        gas_price,
        build_constructor_data(artifacts["ECMath"]["bytecode"], [encode_uint256(256)]),
        tx_gas_cap,
    )
    mlsag_deploy = deploy_contract(
        client,
        from_addr,
        gas_price,
        build_constructor_data(artifacts["MLSAGVerify"]["bytecode"], [encode_address(ec_deploy["contract_address"])]),
        tx_gas_cap,
    )
    return ec_deploy, mlsag_deploy


def summarize_gas(rows: list[dict], ring_sizes: list[int]) -> list[dict]:
    grouped: dict[int, list[int]] = {ring_size: [] for ring_size in ring_sizes}
    for row in rows:
        if row["measurement_kind"] != "estimate":
            continue
        grouped[int(row["ring_size"])].append(int(row["gas"]))

    summary_rows: list[dict] = []
    for ring_size in ring_sizes:
        samples = grouped[ring_size]
        if not samples:
            raise RuntimeError(f"no gas samples collected for ring size {ring_size}")
        mean_gas = statistics.fmean(samples)
        std_gas = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        summary_rows.append(
            {
                "ring_size": ring_size,
                "rep_count": len(samples),
                "mean_verification_gas": str(round(mean_gas)),
                "std_verification_gas": format_float(std_gas),
                "mean_verification_k_gas": format_float(mean_gas / 1000.0),
            }
        )
    return summary_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Estimate MLSAGS verification gas over a ring-size sweep.")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL, help="JSON-RPC endpoint (default: http://127.0.0.1:8545).")
    parser.add_argument("--vector-dir", type=Path, default=DEFAULT_VECTOR_DIR, help="Vector directory from the signing benchmark.")
    parser.add_argument("--outdir", type=Path, default=DEFAULT_OUTDIR, help="Output directory (default: results/fig10_ringsig).")
    parser.add_argument(
        "--tx-gas-cap",
        type=int,
        default=DEFAULT_TX_GAS_CAP,
        help="Optional per-transaction gas cap for contract deployment; use 0 to disable (default: 16000000).",
    )
    parser.add_argument(
        "--ring-sizes",
        type=parse_ring_sizes,
        default=DEFAULT_RING_SIZES,
        help="Comma-separated ring sizes to include (default: 1,2,4,8,16,32,64,128).",
    )
    parser.add_argument(
        "--spot-check-sizes",
        type=parse_ring_sizes,
        default=DEFAULT_SPOT_CHECK_SIZES,
        help="Comma-separated ring sizes for actual tx spot checks (default: 8,64).",
    )
    parser.add_argument("--no-spot-check", action="store_true", help="Disable actual transaction spot checks.")
    args = parser.parse_args()

    ring_sizes = args.ring_sizes if not isinstance(args.ring_sizes, str) else parse_ring_sizes(args.ring_sizes)
    spot_check_sizes = (
        args.spot_check_sizes
        if not isinstance(args.spot_check_sizes, str)
        else parse_ring_sizes(args.spot_check_sizes)
    )

    client = JsonRpcClient(args.rpc_url)
    vector_dir = args.vector_dir.expanduser().resolve()
    outdir = args.outdir.expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    vectors = load_vectors(vector_dir, set(ring_sizes))
    accounts = client.call("eth_accounts", [])
    if not accounts:
        raise RuntimeError("no unlocked accounts exposed by JSON-RPC node")
    from_addr = accounts[0]
    gas_price = client.call("eth_gasPrice", [])
    artifacts = load_committed_artifacts()
    try:
        ec_deploy, mlsag_deploy = deploy_verifier_pair(client, from_addr, gas_price, artifacts, args.tx_gas_cap)
    except RuntimeError as exc:
        print(
            "Committed artifacts failed to deploy on the local JSON-RPC backend; "
            "retrying with solc 0.4.24 --optimize output.",
            file=sys.stderr,
        )
        print(f"Original deployment error: {exc}", file=sys.stderr)
        artifacts = compile_optimized_artifacts(outdir / "compiled")
        ec_deploy, mlsag_deploy = deploy_verifier_pair(client, from_addr, gas_price, artifacts, args.tx_gas_cap)

    deployment_report = {
        "rpc_url": args.rpc_url,
        "from": from_addr,
        "gas_price": gas_price,
        "tx_gas_cap": args.tx_gas_cap,
        "artifact_source": artifacts["source"],
        "ecmath": ec_deploy,
        "mlsag_verify": mlsag_deploy,
    }
    with (outdir / "deployments.json").open("w", encoding="utf-8") as handle:
        json.dump(deployment_report, handle, indent=2)
        handle.write("\n")

    gas_rows: list[dict] = []
    spot_check_records: list[dict] = []
    spot_check_set = set(spot_check_sizes if not args.no_spot_check else [])
    spot_check_done: set[int] = set()

    for vector in vectors:
        calldata = build_verify_mlsag_call(
            vector["msg_hash"],
            vector["key_images"],
            vector["pubkeys"],
            vector["signature"],
        )
        call_tx = {
            "from": from_addr,
            "to": mlsag_deploy["contract_address"],
            "data": calldata,
        }
        call_result = client.call("eth_call", [call_tx, "latest"])
        if not decode_bool(call_result):
            raise RuntimeError(f"VerifyMLSAG returned false for {vector['source_file']}")

        estimate = estimate_gas(client, call_tx)
        gas_rows.append(
            {
                "ring_size": vector["ring_size"],
                "rep": vector["rep"],
                "measurement_kind": "estimate",
                "gas": str(estimate),
                "source_file": vector["source_file"],
                "tx_hash": "",
                "status": "",
            }
        )

        if vector["ring_size"] in spot_check_set and vector["ring_size"] not in spot_check_done:
            tx = dict(call_tx)
            tx["gas"] = hex_quantity(math.ceil(estimate * 1.2))
            tx["gasPrice"] = gas_price
            tx_hash = send_transaction(client, tx)
            receipt = wait_for_receipt(client, tx_hash)
            gas_used = int(receipt["gasUsed"], 16)
            status = receipt.get("status", "0x0")
            gas_rows.append(
                {
                    "ring_size": vector["ring_size"],
                    "rep": vector["rep"],
                    "measurement_kind": "spot_check_tx",
                    "gas": str(gas_used),
                    "source_file": vector["source_file"],
                    "tx_hash": tx_hash,
                    "status": status,
                }
            )
            spot_check_records.append(
                {
                    "ring_size": vector["ring_size"],
                    "rep": vector["rep"],
                    "estimate_gas": estimate,
                    "tx_hash": tx_hash,
                    "gas_used": gas_used,
                    "status": status,
                }
            )
            spot_check_done.add(vector["ring_size"])

        print(
            f"L={vector['ring_size']:>3} rep={vector['rep']:>2} "
            f"verify={estimate:>8} gas from {vector['source_file']}"
        )

    summary_rows = summarize_gas(gas_rows, ring_sizes)
    write_csv(
        outdir / "gas_raw.csv",
        gas_rows,
        ["ring_size", "rep", "measurement_kind", "gas", "source_file", "tx_hash", "status"],
    )
    write_csv(
        outdir / "gas_summary.csv",
        summary_rows,
        ["ring_size", "rep_count", "mean_verification_gas", "std_verification_gas", "mean_verification_k_gas"],
    )
    with (outdir / "spot_checks.json").open("w", encoding="utf-8") as handle:
        json.dump(spot_check_records, handle, indent=2)
        handle.write("\n")

    print(f"Wrote gas samples to {outdir / 'gas_raw.csv'}")
    print(f"Wrote gas summary to {outdir / 'gas_summary.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
