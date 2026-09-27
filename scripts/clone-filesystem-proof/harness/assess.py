#!/usr/bin/env python3
"""Assess the frozen clone-admission timing matrix; external gates stay separate.

Usage: python3 assess.py INPUT.json OUTPUT.json
Exit 0 means a valid assessment was written, including hold/inconclusive results.
Exit 1 means invalid or incomplete input. No product process is invoked.
"""

import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


FILESYSTEMS = ("xfs", "btrfs")
OPERATIONS = ("createCloneSource", "copyTree-empty", "copyTree-small-nested")
BLOCKS = 8
POSITIONS = 4
SAMPLES = 5
ITERATIONS = 30
WARMUPS = 5
BOOTSTRAP_RESAMPLES = 100_000
BOOTSTRAP_SEED = 732
UINT32_MASK = (1 << 32) - 1
UPPER95_INDEX = 94_999  # ceil(0.95 * 100000) - 1, nearest rank.
THRESHOLD = 1.05


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def expected_schedule():
    result = []
    for block in range(1, BLOCKS + 1):
        order = "ABBA" if block % 2 else "BAAB"
        filesystems = FILESYSTEMS if block % 2 else tuple(reversed(FILESYSTEMS))
        for filesystem in filesystems:
            for position, role in enumerate(order, 1):
                result.append((filesystem, block, position, role))
    return result


def exact_keys(value, keys, label, errors):
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    if set(value) != set(keys):
        errors.append(f"{label} must contain exactly: {', '.join(keys)}")
        return False
    return True


def validate_input(data):
    errors = []
    if not exact_keys(data, ("legs",), "input", errors):
        return None, errors
    legs = data["legs"]
    if not isinstance(legs, list) or len(legs) != 64:
        return None, ["legs must contain exactly 64 entries in the frozen schedule order"]
    medians = {}
    for index, (leg, expected) in enumerate(zip(legs, expected_schedule())):
        label = f"legs[{index}]"
        if not exact_keys(leg, ("filesystem", "block", "position", "role", "rows"), label, errors):
            continue
        if type(leg["block"]) is not int or type(leg["position"]) is not int:
            errors.append(f"{label} block/position must be integers, excluding booleans")
        actual = (leg["filesystem"], leg["block"], leg["position"], leg["role"])
        if actual != expected:
            errors.append(f"{label} schedule tuple {actual!r} differs from {expected!r}")
        if not exact_keys(leg["rows"], OPERATIONS, f"{label}.rows", errors):
            continue
        for operation in OPERATIONS:
            row_label = f"{label}.rows[{operation!r}]"
            row = leg["rows"][operation]
            if not exact_keys(row, ("sampleMeansUs",), row_label, errors):
                continue
            values = row["sampleMeansUs"]
            if not isinstance(values, list) or len(values) != SAMPLES:
                errors.append(f"{row_label}.sampleMeansUs must contain exactly five values")
                continue
            valid = True
            converted = []
            for sample_index, value in enumerate(values):
                try:
                    if type(value) not in (int, float):
                        raise ValueError("not a numeric value")
                    number = float(value)
                    if not math.isfinite(number) or number <= 0:
                        raise ValueError("not finite and positive")
                    converted.append(number)
                except (ValueError, OverflowError):
                    errors.append(f"{row_label}.sampleMeansUs[{sample_index}] must be finite and positive")
                    valid = False
            if valid:
                # Use the validated schedule key, never an untrusted role for pairing.
                filesystem, block, position, _ = expected
                medians[(filesystem, block, position, operation)] = statistics.median(converted)
    return (medians if not errors else None), errors


def mean(values):
    return math.fsum(values) / len(values)


def bootstrap_upper95(log_ratios):
    # Reset the stream for each cell; resample whole quartets, not sample means.
    state = BOOTSTRAP_SEED
    resampled_means = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        draws = []
        for _ in range(BLOCKS):
            state = (state ^ (state << 13)) & UINT32_MASK
            state = (state ^ (state >> 17)) & UINT32_MASK
            state = (state ^ (state << 5)) & UINT32_MASK
            # floor(uint32 / 2**32 * 8), exactly, without a float conversion.
            draws.append(log_ratios[state >> 29])
        resampled_means.append(mean(draws))
    resampled_means.sort()
    return math.exp(resampled_means[UPPER95_INDEX])


def assess_cells(medians):
    cells = []
    for filesystem in FILESYSTEMS:
        for operation in OPERATIONS:
            quartets = []
            log_ratios = []
            by_order = {"ABBA": [], "BAAB": []}
            for block in range(1, BLOCKS + 1):
                order = "ABBA" if block % 2 else "BAAB"
                arms = {"A": [], "B": []}
                leg_medians = []
                for position, role in enumerate(order, 1):
                    value = medians[(filesystem, block, position, operation)]
                    arms[role].append(math.log(value))
                    leg_medians.append({"position": position, "role": role, "medianUs": value})
                log_ratio = mean(arms["B"]) - mean(arms["A"])
                log_ratios.append(log_ratio)
                by_order[order].append(log_ratio)
                quartets.append({
                    "block": block, "order": order, "legMedians": leg_medians,
                    "logRatio": log_ratio, "ratio": math.exp(log_ratio),
                })
            paired = math.exp(mean(log_ratios))
            orders = {order: math.exp(mean(values)) for order, values in by_order.items()}
            upper95 = bootstrap_upper95(log_ratios)
            derived = [paired, upper95, *orders.values(), *(x["ratio"] for x in quartets)]
            if any(not math.isfinite(value) or value <= 0 for value in derived):
                raise ValueError(f"{filesystem}/{operation} produced an unrepresentable ratio")
            if paired > THRESHOLD or any(value > THRESHOLD for value in orders.values()):
                outcome = "hold"
            elif upper95 > THRESHOLD:
                outcome = "inconclusive"
            else:
                outcome = "pass"
            cells.append({
                "filesystem": filesystem, "operation": operation, "metric": "callUs",
                "pairedRatio": paired, "orderRatios": orders, "upper95": upper95,
                "outcome": outcome, "quartets": quartets,
            })
    return cells


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = {
        "schema": 1,
        "assessorSha256": sha256(Path(__file__).read_bytes()),
        "validInput": False,
        "performanceOutcome": "inconclusive",
        "overallOutcome": "not-assessed",
        "externalGates": {name: "not-verified-by-statistics" for name in (
            "correctness", "traces", "provenance", "cleanup",
        )},
        "fixedProtocol": {
            "filesystems": list(FILESYSTEMS), "operations": list(OPERATIONS),
            "legs": 64, "quartetsPerFilesystem": BLOCKS, "samplesPerRow": SAMPLES,
            "iterationsPerSample": ITERATIONS, "warmupCallsPerRow": WARMUPS,
            "legStatistic": "median of five sample arithmetic mean callUs values",
            "resamplingUnit": "complete quartet log ratio", "drawsPerResample": BLOCKS,
            "bootstrapResamples": BOOTSTRAP_RESAMPLES, "xorshift32Seed": BOOTSTRAP_SEED,
            "xorshift32Shifts": [13, 17, 5], "resetStreamPerCell": True,
            "upper95Method": "nearest rank", "upper95ZeroBasedIndex": UPPER95_INDEX,
            "thresholdRatio": THRESHOLD,
        },
        "limitations": [
            "Statistics alone do not establish the combined acceptance gate.",
            "The coordinator must separately verify correctness, traces, source/package provenance, and cleanup.",
            "Input sample means do not independently prove iteration counts, row order, warmups, or public-call boundaries.",
            "Whole-quartet empirical bootstrap does not establish a population latency guarantee.",
        ],
        "counts": {"pass": 0, "hold": 0, "inconclusive": 0},
        "cells": [], "errors": [],
    }
    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError("output must not overwrite the input artifact")
        raw = args.input.read_bytes()
        result["input"] = {"path": str(args.input.resolve()), "bytes": len(raw), "sha256": sha256(raw)}
        data = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
        medians, errors = validate_input(data)
        result["errors"] = errors
        if not errors:
            cells = assess_cells(medians)
            result["cells"] = cells
            result["validInput"] = True
            for cell in cells:
                result["counts"][cell["outcome"]] += 1
            result["performanceOutcome"] = (
                "hold" if result["counts"]["hold"] else
                "inconclusive" if result["counts"]["inconclusive"] else "pass"
            )
    except (OSError, ValueError, OverflowError) as error:
        result["errors"].append(f"{type(error).__name__}: {error}")
    # Do not overwrite input even when emitting an invalid-input receipt.
    if args.input.resolve() == args.output.resolve():
        print(json.dumps(result, indent=2, allow_nan=False), file=sys.stderr)
        return 1
    try:
        args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except OSError as error:
        print(f"cannot write assessment: {error}", file=sys.stderr)
        return 1
    return 0 if result["validInput"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
