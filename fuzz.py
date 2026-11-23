import random
import string
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
KUBESEC_DIR = REPO_ROOT / "slikube" / "KubeSec-master"

# Ensure local KubeSec modules resolve ahead of any standard-library names
if str(KUBESEC_DIR) not in sys.path:
    sys.path.insert(0, str(KUBESEC_DIR))

import graphtaint  # noqa: E402
import parser  # noqa: E402
import scanner  # noqa: E402

ITERATIONS_PER_TARGET = 200
SEED = 20261122

DOMAIN_STRINGS = [
    "",
    " ",
    "a",
    "ab",
    "user",
    "username",
    "admin_user",
    "user_domain",
    "password",
    "passwd",
    "admin_pass",
    "pass_hash",
    "secret_key",
    "tls.crt",
    ":undef",
    "[]",
    "/",
    "unset",
    "-----BEGIN RSA PRIVATE KEY-----",
    ".Values.app.secret",
    "no_dots_here",
    "trailing.dot.",
    "spec",
    "metadata",
    "kind",
    "apiVersion",
]


def random_string(rng: random.Random) -> str:
    if rng.random() < 0.45:
        return rng.choice(DOMAIN_STRINGS)
    length = rng.randint(0, 32)
    alphabet = string.ascii_letters + string.digits + "._-/: %[]{}'\"\\\n\t\x00"
    return "".join(rng.choice(alphabet) for _ in range(length))


def random_scalar(rng: random.Random):
    kind = rng.choice(["str", "str", "int", "float", "bool", "none"])
    if kind == "str":
        return random_string(rng)
    if kind == "int":
        return rng.randint(-1000, 1000)
    if kind == "float":
        return rng.uniform(-100.0, 100.0)
    if kind == "bool":
        return rng.choice([True, False])
    return None


def random_nested(rng: random.Random, depth: int = 0, force_dict: bool = False):
    if not force_dict and depth >= 3:
        return random_scalar(rng)

    kind = "dict" if force_dict else rng.choice(["dict", "list", "scalar"])
    if kind == "scalar":
        return random_scalar(rng)
    if kind == "list":
        return [random_nested(rng, depth + 1) for _ in range(rng.randint(0, 4))]

    out = {}
    for _ in range(rng.randint(0, 4)):
        key = rng.choice([
            random_string(rng),
            rng.choice(["user", "username", "password", "key", "spec", "kind", "data"]),
            rng.randint(0, 5),
            None,
            True,
        ])
        out[key] = random_nested(rng, depth + 1)
    return out


def gen_construct_helm_args(rng: random.Random):
    mode = rng.choice(["valid_tuple", "bad_types_tuple", "wrong_len_tuple", "non_tuple"])
    if mode == "valid_tuple":
        k1 = random_string(rng)
        k2 = k1 if rng.random() < 0.25 else random_string(rng)
        return ((k1, k2, random_scalar(rng)),)
    if mode == "bad_types_tuple":
        return ((random_scalar(rng), random_scalar(rng), random_scalar(rng)),)
    if mode == "wrong_len_tuple":
        size = rng.choice([0, 1, 2, 4])
        return (tuple(random_scalar(rng) for _ in range(size)),)
    return (random_scalar(rng),)


def gen_valid_taints_args(rng: random.Random):
    mode = rng.choice(["valid_list", "mixed_tuples", "bad_items", "non_list"])
    if mode == "valid_list":
        items = [(random_string(rng), random_string(rng)) for _ in range(rng.randint(0, 4))]
        return (items,)
    if mode == "mixed_tuples":
        items = [(random_scalar(rng), random_scalar(rng)) for _ in range(rng.randint(1, 3))]
        return (items,)
    if mode == "bad_items":
        items = [rng.choice([None, ("only_one",), ("a", "b", "c"), 42])]
        return (items,)
    return (rng.choice([None, 123, "not_a_list"]),)


def gen_find_json_path_args(rng: random.Random):
    parser.key_jsonpath_mapping.clear()
    mode = rng.choice(["nested_dict", "bad_keys", "list_input", "bad_paths_arg"])
    if mode == "nested_dict":
        return (random_nested(rng, force_dict=True),)
    if mode == "bad_keys":
        bad_key = rng.choice([None, 3.14, ("nested", "key")])
        return ({bad_key: random_scalar(rng)},)
    if mode == "list_input":
        return ([random_nested(rng) for _ in range(rng.randint(0, 3))],)
    return (random_nested(rng, force_dict=True), "", "not_a_list")


def gen_multi_docs_args(rng: random.Random):
    mode = rng.choice(["dicts_dup_keys", "nested_list_edge", "mixed_docs", "non_list"])
    if mode == "dicts_dup_keys":
        shared_key = rng.choice(["metadata", "spec", 1, None, True])
        return ([{shared_key: random_scalar(rng)}, {shared_key: random_scalar(rng)}],)
    if mode == "nested_list_edge":
        return ([rng.choice([[], [{"a": 1}], [None]])],)
    if mode == "mixed_docs":
        docs = [
            rng.choice([random_nested(rng, force_dict=True), None, random_scalar(rng)])
            for _ in range(rng.randint(0, 4))
        ]
        return (docs,)
    return (rng.choice([None, 123]),)


def gen_scan_username_args(rng: random.Random):
    key = rng.choice(["user", "username", "admin_user", "user_domain", random_scalar(rng)])
    val_mode = rng.choice(["list", "list", "str", "none", "int"])
    if val_mode == "list":
        vals = [random_scalar(rng) for _ in range(rng.randint(0, 4))]
    elif val_mode == "str":
        vals = random_string(rng)
    elif val_mode == "none":
        vals = None
    else:
        vals = rng.randint(-10, 10)
    return (key, vals)


def gen_item_from_secret_args(rng: random.Random):
    mode = rng.choice(["valid", "bad_pos", "bad_tuple", "non_dict"])
    if mode == "valid":
        sec = {
            random_string(rng): (
                [random_string(rng)],
                [random_string(rng)],
                [random_string(rng)],
            )
        }
        return (sec, rng.choice([0, 1, 2]))
    if mode == "bad_pos":
        sec = {"password": (["u"], ["p"], ["k"])}
        return (sec, rng.choice([3, 5, "0", None]))
    if mode == "bad_tuple":
        sec = {"password": rng.choice([None, (), 123, (None, None, None)])}
        return (sec, 0)
    return (rng.choice([None, [], "not_a_dict"]), 0)


def fuzz_target(target_name: str, fn, gen_args):
    runs = 0
    error_count = 0
    unique_bugs = {}

    for i in range(ITERATIONS_PER_TARGET):
        args = gen_args()
        runs += 1
        try:
            fn(*args)
        except Exception as exc:
            error_count += 1
            frames = traceback.extract_tb(exc.__traceback__)
            last = frames[-1] if frames else None
            location = (
                f"{Path(last.filename).name}:{last.lineno} in {last.name}"
                if last
                else "unknown"
            )
            sig = (type(exc).__name__, location)
            if sig not in unique_bugs:
                unique_bugs[sig] = {
                    "count": 1,
                    "first_iteration": i,
                    "sample_message": str(exc),
                    "sample_args": repr(args)[:220],
                }
            else:
                unique_bugs[sig]["count"] += 1

    return {
        "target": target_name,
        "runs": runs,
        "errors": error_count,
        "unique_bugs": unique_bugs,
    }


def main():
    rng = random.Random(SEED)

    targets = [
        ("graphtaint.constructHelmString", graphtaint.constructHelmString, lambda: gen_construct_helm_args(rng)),
        ("graphtaint.getValidTaints", graphtaint.getValidTaints, lambda: gen_valid_taints_args(rng)),
        ("parser.find_json_path_keys", parser.find_json_path_keys, lambda: gen_find_json_path_args(rng)),
        (
            "parser.getKeyRecursively",
            parser.getKeyRecursively,
            lambda: (
                random_nested(rng, force_dict=rng.random() < 0.8),
                [] if rng.random() < 0.85 else None,
                0 if rng.random() < 0.85 else rng.choice([None, "0"]),
            ),
        ),
        (
            "parser.getValsFromKey",
            parser.getValsFromKey,
            lambda: (
                random_nested(rng, force_dict=rng.random() < 0.8),
                random_scalar(rng),
                [] if rng.random() < 0.85 else None,
            ),
        ),
        ("parser.getSingleDict4MultiDocs", parser.getSingleDict4MultiDocs, lambda: gen_multi_docs_args(rng)),
        ("scanner.isValidUserName", scanner.isValidUserName, lambda: (random_scalar(rng),)),
        ("scanner.checkIfValidSecret", scanner.checkIfValidSecret, lambda: (random_scalar(rng),)),
        ("scanner.scanUserName", scanner.scanUserName, lambda: gen_scan_username_args(rng)),
        ("scanner.getItemFromSecret", scanner.getItemFromSecret, lambda: gen_item_from_secret_args(rng)),
    ]

    results = [fuzz_target(name, fn, gen_args) for name, fn, gen_args in targets]

    total_runs = sum(r["runs"] for r in results)
    total_errors = sum(r["errors"] for r in results)
    total_unique = sum(len(r["unique_bugs"]) for r in results)

    log_path = REPO_ROOT / "fuzz_results.log"
    timestamp = datetime.now(timezone.utc).isoformat()
    lines = [
        f"Fuzz Run Timestamp (UTC): {timestamp}",
        f"Seed: {SEED} | Targets: {len(targets)} | Total Runs: {total_runs}",
        f"Total Exceptions Captured: {total_errors} | Unique Crash Sites: {total_unique}",
        "=" * 70,
        "Per-Target Summary:",
    ]

    for r in results:
        lines.append(
            f"  - {r['target']}: runs={r['runs']}, errors={r['errors']}, "
            f"unique_crash_sites={len(r['unique_bugs'])}"
        )

    lines.append("=" * 70)
    lines.append("Unique Bugs / Crash Sites by Target:")

    for r in results:
        lines.append(f"\n[{r['target']}]")
        if not r["unique_bugs"]:
            lines.append("  No exceptions raised.")
            continue
        sorted_bugs = sorted(r["unique_bugs"].items(), key=lambda item: item[1]["count"], reverse=True)
        for (exc_type, location), info in sorted_bugs:
            lines.append(
                f"  - {exc_type} at {location} "
                f"(hits={info['count']}, first_iter={info['first_iteration']})"
            )
            lines.append(f"    message: {info['sample_message']}")
            lines.append(f"    sample_args: {info['sample_args']}")

    report_text = "\n".join(lines) + "\n"
    log_path.write_text(report_text, encoding="utf-8")
    print(report_text)


if __name__ == "__main__":
    main()