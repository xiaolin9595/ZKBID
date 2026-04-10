#!/usr/bin/env python3
"""Measure MLSAGS signing time for the ring-size experiment.

This script is intentionally self-contained:
- it inserts ``py/`` into ``sys.path`` and reuses the existing
  ``py/ring_signatures.py`` implementation,
- it benchmarks only ``MLSAG.Sign_GenRandom(...)``,
- it writes raw timing CSVs, per-repetition vector JSON files, and an
  aggregated summary CSV under ``results/fig10_ringsig``.

The benchmark is designed for the ring-size sweep used by the paper figures.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import sys
import time
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PY_DIR = ROOT / "py"
if str(PY_DIR) not in sys.path:
    sys.path.insert(0, str(PY_DIR))

import ring_signatures as rs  # noqa: E402


DEFAULT_RING_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256]
DEFAULT_NREP = 10
DEFAULT_OUTDIR = ROOT / "results" / "fig10_ringsig"


def parse_ring_sizes(value: str) -> list[int]:
    sizes: list[int] = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        size = int(item)
        if size <= 0:
            raise argparse.ArgumentTypeError("ring sizes must be positive integers")
        sizes.append(size)
    if not sizes:
        raise argparse.ArgumentTypeError("at least one ring size is required")
    return sizes


def int_to_hex32(value: int) -> str:
    return "0x" + value.to_bytes(32, byteorder="big").hex()


def serialize_points(points) -> list[str]:
    flat_points: list[str] = []
    for point in points:
        normalized = rs.normalize(point)
        flat_points.extend(
            [
                int_to_hex32(normalized[0].n),
                int_to_hex32(normalized[1].n),
            ]
        )
    return flat_points


def make_message_hash() -> bytes:
    # Keep the benchmark domain fixed across repetitions.
    return hashlib.sha3_256(b"zkbid-mlsags-signing-benchmark").digest()


def generate_inputs(ring_size: int, signer_index: int):
    xk = [rs.getRandom()]
    pubkeys = [rs.multiply(rs.G1, rs.getRandom()) for _ in range(ring_size)]
    indices = [signer_index]
    return xk, pubkeys, indices


def bench_once(ring_size: int, rep: int, outdir: Path, indent: int) -> dict:
    signer_index = rs.getRandom() % ring_size
    xk, pubkeys, indices = generate_inputs(ring_size, signer_index)
    msg_hash = make_message_hash()

    start = time.perf_counter()
    signature = rs.MLSAG.Sign_GenRandom(1, msg_hash, xk, indices[:], pubkeys)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    vector_dir = outdir / "vectors"
    vector_dir.mkdir(parents=True, exist_ok=True)
    vector_path = vector_dir / f"L{ring_size}_rep{rep:02d}.json"

    vector_payload = {
        "ring_size": ring_size,
        "rep": rep,
        "m": 1,
        "signer_index": signer_index,
        "message_domain": "zkbid-mlsags-signing-benchmark",
        "message_hash": "0x" + msg_hash.hex(),
        "private_key": int_to_hex32(xk[0]),
        "key_images": serialize_points(signature.key_images),
        "pubkeys": serialize_points(signature.pub_keys),
        "signature": [int_to_hex32(value) for value in signature.signature],
    }
    with vector_path.open("w", encoding="utf-8") as fh:
        json.dump(vector_payload, fh, indent=indent, sort_keys=True)
        fh.write("\n")

    return {
        "ring_size": ring_size,
        "rep": rep,
        "signer_index": signer_index,
        "signing_time_ms": elapsed_ms,
        "vector_path": str(vector_path.relative_to(ROOT)),
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def reset_output_dir(outdir: Path) -> None:
    vector_dir = outdir / "vectors"
    if vector_dir.exists():
        shutil.rmtree(vector_dir, ignore_errors=True)

    for file_name in [
        "signing_raw.csv",
        "signing_summary.csv",
        "signing_summary.json",
    ]:
        file_path = outdir / file_name
        if file_path.exists():
            file_path.unlink()


def summarize(rows: list[dict]) -> list[dict]:
    grouped: dict[int, list[float]] = {}
    for row in rows:
        grouped.setdefault(int(row["ring_size"]), []).append(float(row["signing_time_ms"]))

    summary: list[dict] = []
    for ring_size in sorted(grouped):
        samples = grouped[ring_size]
        mean_ms = statistics.fmean(samples)
        stdev_ms = statistics.pstdev(samples) if len(samples) > 1 else 0.0
        summary.append(
            {
                "ring_size": ring_size,
                "mean_signing_time_ms": mean_ms,
                "std_signing_time_ms": stdev_ms,
                "nrep": len(samples),
            }
        )
    return summary


def format_float(value: float) -> str:
    return f"{value:.6f}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure MLSAGS signing time over a ring-size sweep.",
    )
    parser.add_argument(
        "--ring-sizes",
        type=parse_ring_sizes,
        default=DEFAULT_RING_SIZES,
        help="Comma-separated ring sizes to benchmark (default: 1,2,4,8,16,32,64,128).",
    )
    parser.add_argument(
        "--nrep",
        type=int,
        default=DEFAULT_NREP,
        help="Number of repetitions per ring size (default: 10).",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help="Output directory (default: results/fig10_ringsig).",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation for vector files (default: 2).",
    )
    args = parser.parse_args()

    ring_sizes = args.ring_sizes
    if isinstance(ring_sizes, str):
        ring_sizes = parse_ring_sizes(ring_sizes)
    if args.nrep <= 0:
        raise SystemExit("--nrep must be a positive integer")

    outdir = args.outdir.expanduser().resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    reset_output_dir(outdir)

    raw_rows: list[dict] = []
    for ring_size in ring_sizes:
        for rep in range(args.nrep):
            row = bench_once(ring_size, rep, outdir, args.indent)
            raw_rows.append(row)
            print(
                f"L={ring_size:>3} rep={rep:>2} "
                f"{row['signing_time_ms']:.3f} ms -> {row['vector_path']}"
            )

    raw_csv_path = outdir / "signing_raw.csv"
    write_csv(
        raw_csv_path,
        raw_rows,
        ["ring_size", "rep", "signer_index", "signing_time_ms", "vector_path"],
    )

    summary_rows = summarize(raw_rows)
    summary_csv_rows = [
        {
            "ring_size": row["ring_size"],
            "mean_signing_time_ms": format_float(row["mean_signing_time_ms"]),
            "std_signing_time_ms": format_float(row["std_signing_time_ms"]),
            "nrep": row["nrep"],
        }
        for row in summary_rows
    ]
    write_csv(
        outdir / "signing_summary.csv",
        summary_csv_rows,
        ["ring_size", "mean_signing_time_ms", "std_signing_time_ms", "nrep"],
    )

    report_path = outdir / "signing_summary.json"
    with report_path.open("w", encoding="utf-8") as fh:
        json.dump(summary_rows, fh, indent=2)
        fh.write("\n")

    print(f"Wrote raw samples to {raw_csv_path}")
    print(f"Wrote summary to {outdir / 'signing_summary.csv'}")
    print(f"Wrote summary JSON to {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
