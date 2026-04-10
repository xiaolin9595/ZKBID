#!/usr/bin/env python3
"""Run the full MLSAGS ring-size experiment and regenerate fig10_ringsig.tikz."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RING_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256]
DEFAULT_SPOT_CHECK_SIZES = [8, 64]
DEFAULT_OUTDIR = ROOT / "results" / "fig10_ringsig"
DEFAULT_TIKZ_PATH = ROOT / "fig10_ringsig.tikz"
DEFAULT_RPC_URL = "http://127.0.0.1:8545"


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


def json_rpc_ready(rpc_url: str, timeout: int = 5) -> bool:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_accounts",
            "params": [],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return False
    return "result" in body


def wait_for_rpc(rpc_url: str, timeout_seconds: float = 30.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if json_rpc_ready(rpc_url):
            return
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for geth JSON-RPC at {rpc_url}")


def reset_output_dir(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    if (outdir / "vectors").exists():
        shutil.rmtree(outdir / "vectors", ignore_errors=True)
    if (outdir / "compiled").exists():
        shutil.rmtree(outdir / "compiled", ignore_errors=True)
    for file_name in [
        "deployments.json",
        "fit_report.csv",
        "gas_raw.csv",
        "gas_summary.csv",
        "signing_raw.csv",
        "signing_summary.csv",
        "signing_summary.json",
        "spot_checks.json",
        "summary.csv",
    ]:
        file_path = outdir / file_name
        if file_path.exists():
            file_path.unlink()


def read_csv(path: Path) -> list[dict]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def linear_fit(points: list[dict], x_key: str, y_key: str) -> dict[str, float]:
    xs = [float(point[x_key]) for point in points]
    ys = [float(point[y_key]) for point in points]
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    denominator = sum((x - x_mean) ** 2 for x in xs)
    slope = numerator / denominator if denominator else 0.0
    intercept = y_mean - slope * x_mean
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r_squared = 1.0 if ss_tot == 0 else 1.0 - (ss_res / ss_tot)
    return {
        "slope": slope,
        "intercept": intercept,
        "r_squared": r_squared,
    }


def format_float(value: float) -> str:
    return f"{value:.6f}"


def choose_axis_upper(max_value: float, tick_count: int) -> tuple[int, int]:
    if max_value <= 0:
        return tick_count, 1

    rough_step = max_value / tick_count
    magnitude = 10 ** math.floor(math.log10(rough_step))
    normalized = rough_step / magnitude

    if normalized <= 1:
        nice = 1
    elif normalized <= 2:
        nice = 2
    elif normalized <= 5:
        nice = 5
    else:
        nice = 10

    step = int(nice * magnitude)
    upper = int(math.ceil(max_value / step) * step)
    return upper, step


def merge_summaries(outdir: Path, ring_sizes: list[int]) -> list[dict]:
    signing_rows = {
        int(row["ring_size"]): row
        for row in read_csv(outdir / "signing_summary.csv")
    }
    gas_rows = {
        int(row["ring_size"]): row
        for row in read_csv(outdir / "gas_summary.csv")
    }

    summary_rows: list[dict] = []
    for ring_size in ring_sizes:
        signing = signing_rows[ring_size]
        gas = gas_rows[ring_size]
        summary_rows.append(
            {
                "ring_size": ring_size,
                "nrep": signing["nrep"],
                "mean_signing_time_ms": signing["mean_signing_time_ms"],
                "std_signing_time_ms": signing["std_signing_time_ms"],
                "mean_verification_gas": gas["mean_verification_gas"],
                "std_verification_gas": gas["std_verification_gas"],
                "mean_verification_k_gas": gas["mean_verification_k_gas"],
            }
        )

    write_csv(
        outdir / "summary.csv",
        summary_rows,
        [
            "ring_size",
            "nrep",
            "mean_signing_time_ms",
            "std_signing_time_ms",
            "mean_verification_gas",
            "std_verification_gas",
            "mean_verification_k_gas",
        ],
    )
    return summary_rows


def write_fit_report(outdir: Path, summary_rows: list[dict]) -> None:
    signing_fit = linear_fit(summary_rows, "ring_size", "mean_signing_time_ms")
    gas_fit = linear_fit(summary_rows, "ring_size", "mean_verification_gas")
    rows = [
        {
            "metric": "signing_time_ms",
            "slope": format_float(signing_fit["slope"]),
            "intercept": format_float(signing_fit["intercept"]),
            "r_squared": format_float(signing_fit["r_squared"]),
        },
        {
            "metric": "verification_gas",
            "slope": format_float(gas_fit["slope"]),
            "intercept": format_float(gas_fit["intercept"]),
            "r_squared": format_float(gas_fit["r_squared"]),
        },
    ]
    write_csv(outdir / "fit_report.csv", rows, ["metric", "slope", "intercept", "r_squared"])


def update_tikz(tikz_path: Path, summary_rows: list[dict]) -> None:
    original = tikz_path.read_text(encoding="utf-8")
    ring_sizes = [int(row["ring_size"]) for row in summary_rows]
    x_max = max(ring_sizes)
    xticks = ",".join(str(size) for size in ring_sizes)
    signing_max = max(float(row["mean_signing_time_ms"]) for row in summary_rows)
    gas_max = max(float(row["mean_verification_k_gas"]) for row in summary_rows)
    signing_upper, signing_step = choose_axis_upper(signing_max * 1.05, 4)
    gas_upper, gas_step = choose_axis_upper(gas_max * 1.05, 5)
    signing_ticks = ",".join(str(value) for value in range(0, signing_upper + signing_step, signing_step))
    gas_ticks = ",".join(str(value) for value in range(0, gas_upper + gas_step, gas_step))
    gas_tick_labels = ",".join("0" if value == 0 else f"{value // 1000}k" for value in range(0, gas_upper + gas_step, gas_step))
    signing_coords = "\n".join(
        f"      ({row['ring_size']},{float(row['mean_signing_time_ms']):.6f})"
        for row in summary_rows
    )
    gas_coords = "\n".join(
        f"      ({row['ring_size']},{float(row['mean_verification_k_gas']):.6f})"
        for row in summary_rows
    )

    signing_start = original.index("    ] coordinates {\n")
    signing_end = original.index("\n    };\n    \\addlegendentry{MLSAGS signing}")
    updated = original[: signing_start + len("    ] coordinates {\n")] + signing_coords + original[signing_end:]

    marker = "      transform canvas={xshift=3pt},\n      mark=square*,\n      mark options={fill=white, draw=zkRed},\n    ] coordinates {\n"
    gas_start = updated.index(marker) + len(marker)
    gas_end = updated.index("\n    };\n  \\end{axis}", gas_start)
    updated = updated[:gas_start] + gas_coords + updated[gas_end:]
    updated = re.sub(r"xmin=1, xmax=\d+,", f"xmin=1, xmax={x_max},", updated)
    updated = re.sub(r"xtick=\{[^\}]+\},", f"xtick={{{xticks}}},", updated)
    updated = re.sub(r"ymin=0, ymax=\d+,\n    ytick=\{[^\}]+\},", f"ymin=0, ymax={signing_upper},\n    ytick={{{signing_ticks}}},", updated, count=1)
    updated = re.sub(
        r"ymin=0, ymax=\d+,\n    ytick=\{[^\}]+\},\n    yticklabels=\{[^\}]+\},",
        f"ymin=0, ymax={gas_upper},\n    ytick={{{gas_ticks}}},\n    yticklabels={{{gas_tick_labels}}},",
        updated,
        count=1,
    )

    tikz_path.write_text(updated, encoding="utf-8")


def build_geth_command(datadir: Path, rpc_url: str, geth_binary: str) -> list[str]:
    host_port = rpc_url.removeprefix("http://")
    host, port = host_port.split(":")
    return [
        geth_binary,
        "--dev",
        "--dev.gaslimit",
        "60000000",
        "--dev.period",
        "1",
        "--http",
        "--http.addr",
        host,
        "--http.port",
        port,
        "--http.api",
        "eth,net,web3,miner",
        "--rpc.gascap",
        "0",
        "--rpc.txfeecap",
        "0",
        "--ipcdisable",
        "--datadir",
        str(datadir),
        "--verbosity",
        "2",
    ]


def build_ganache_command(rpc_url: str) -> list[str]:
    host_port = rpc_url.removeprefix("http://")
    host, port = host_port.split(":")
    return [
        "npx",
        "ganache",
        "--wallet.deterministic",
        "--chain.chainId",
        "1337",
        "--miner.blockGasLimit",
        "0x3938700",
        "--server.host",
        host,
        "--server.port",
        port,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the MLSAGS ring-size experiment end-to-end.")
    parser.add_argument(
        "--ring-sizes",
        type=parse_ring_sizes,
        default=DEFAULT_RING_SIZES,
        help="Comma-separated ring sizes to benchmark (default: 1,2,4,8,16,32,64,128).",
    )
    parser.add_argument("--nrep", type=int, default=10, help="Repetitions per ring size (default: 10).")
    parser.add_argument("--outdir", type=Path, default=DEFAULT_OUTDIR, help="Output directory (default: results/fig10_ringsig).")
    parser.add_argument("--tikz-path", type=Path, default=DEFAULT_TIKZ_PATH, help="Path to fig10_ringsig.tikz.")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL, help="Local JSON-RPC URL for the spawned backend.")
    parser.add_argument("--backend", choices=["geth", "ganache"], default="ganache", help="Local EVM backend to start (default: ganache).")
    parser.add_argument("--geth-binary", default="geth", help="Geth executable to use (default: geth).")
    parser.add_argument("--geth-datadir", type=Path, default=Path("/tmp/zkbid_fig10_ringsig_geth"), help="Temporary datadir for geth.")
    parser.add_argument("--geth-log", type=Path, default=Path("/tmp/zkbid_fig10_ringsig_node.log"), help="Path for backend stdout/stderr log.")
    parser.add_argument("--tx-gas-cap", type=int, default=16_000_000, help="Per-transaction deploy gas cap to pass to the estimator; use 0 to disable.")
    parser.add_argument(
        "--spot-check-sizes",
        type=parse_ring_sizes,
        default=DEFAULT_SPOT_CHECK_SIZES,
        help="Comma-separated ring sizes for actual transaction spot checks (default: 8,64).",
    )
    parser.add_argument("--no-spot-check", action="store_true", help="Disable actual transaction spot checks.")
    parser.add_argument("--keep-geth", action="store_true", help="Leave the spawned geth process running after completion.")
    args = parser.parse_args()

    ring_sizes = args.ring_sizes if not isinstance(args.ring_sizes, str) else parse_ring_sizes(args.ring_sizes)
    spot_check_sizes = (
        args.spot_check_sizes
        if not isinstance(args.spot_check_sizes, str)
        else parse_ring_sizes(args.spot_check_sizes)
    )
    if args.nrep <= 0:
        raise SystemExit("--nrep must be a positive integer")

    outdir = args.outdir.expanduser().resolve()
    tikz_path = args.tikz_path.expanduser().resolve()
    datadir = args.geth_datadir.expanduser().resolve()
    log_path = args.geth_log.expanduser().resolve()

    reset_output_dir(outdir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    node_command = None
    if args.backend == "geth":
        if datadir.exists():
            shutil.rmtree(datadir)
        datadir.mkdir(parents=True, exist_ok=True)
        node_command = build_geth_command(datadir, args.rpc_url, args.geth_binary)
    else:
        node_command = build_ganache_command(args.rpc_url)

    geth_proc = None
    try:
        with log_path.open("w", encoding="utf-8") as log_file:
            geth_proc = subprocess.Popen(
                node_command,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )

        wait_for_rpc(args.rpc_url)

        signing_cmd = [
            sys.executable,
            str(ROOT / "scripts" / "measure_mlsag_signing.py"),
            "--ring-sizes",
            ",".join(str(size) for size in ring_sizes),
            "--nrep",
            str(args.nrep),
            "--outdir",
            str(outdir),
        ]
        subprocess.run(signing_cmd, check=True, cwd=ROOT)

        gas_cmd = [
            sys.executable,
            str(ROOT / "scripts" / "estimate_mlsag_gas.py"),
            "--rpc-url",
            args.rpc_url,
            "--vector-dir",
            str(outdir / "vectors"),
            "--outdir",
            str(outdir),
            "--ring-sizes",
            ",".join(str(size) for size in ring_sizes),
            "--tx-gas-cap",
            str(0 if args.backend == "ganache" else args.tx_gas_cap),
        ]
        if spot_check_sizes:
            gas_cmd.extend(["--spot-check-sizes", ",".join(str(size) for size in spot_check_sizes)])
        if args.no_spot_check:
            gas_cmd.append("--no-spot-check")
        subprocess.run(gas_cmd, check=True, cwd=ROOT)

        summary_rows = merge_summaries(outdir, ring_sizes)
        write_fit_report(outdir, summary_rows)
        update_tikz(tikz_path, summary_rows)

        print(f"Wrote merged summary to {outdir / 'summary.csv'}")
        print(f"Wrote fit report to {outdir / 'fit_report.csv'}")
        print(f"Updated TikZ figure at {tikz_path}")
        print(f"Backend: {args.backend}")
        print(f"Node log saved to {log_path}")
        return 0
    finally:
        if geth_proc is not None and not args.keep_geth:
            geth_proc.terminate()
            try:
                geth_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                geth_proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
