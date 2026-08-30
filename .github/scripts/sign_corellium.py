#!/usr/bin/env python3
import argparse
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

CODESIGN = "/usr/bin/codesign"


def run(cmd, *, stdout=None, stderr=None):
    print("+", " ".join(str(x) for x in cmd), flush=True)
    subprocess.run(cmd, check=True, stdout=stdout, stderr=stderr)


def bundle_id(bundle: Path) -> str:
    info = bundle / "Info.plist"
    with info.open("rb") as f:
        value = plistlib.load(f).get("CFBundleIdentifier")
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"Missing CFBundleIdentifier in {info}")
    return value


def entitlements_for(team_id: str, bid: str, *, data_protection: bool) -> dict:
    app_id = f"{team_id}.{bid}"
    ent = {
        "application-identifier": app_id,
        "com.apple.developer.team-identifier": team_id,
        "keychain-access-groups": [app_id],
    }
    if data_protection:
        ent["com.apple.developer.default-data-protection"] = "NSFileProtectionComplete"
    return ent


def write_plist(path: Path, value: dict) -> None:
    with path.open("wb") as f:
        plistlib.dump(value, f, fmt=plistlib.FMT_XML, sort_keys=False)


def sign(path: Path, entitlements: Path | None = None) -> None:
    cmd = [CODESIGN, "--force", "--sign", "-", "--timestamp=none"]
    if entitlements is not None:
        cmd += ["--entitlements", str(entitlements)]
    cmd.append(str(path))
    run(cmd)


def sign_nested_code(app: Path, team_id: str, temp: Path) -> None:
    # Sign leaf code first. Do not sign executable files inside .framework bundles
    # separately; codesign seals the framework bundle as a unit.
    frameworks = [p for p in app.rglob("*.framework") if p.is_dir()]
    dylibs = [
        p for p in app.rglob("*.dylib")
        if p.is_file() and not any(parent.suffix == ".framework" for parent in p.parents)
    ]
    for item in sorted(frameworks + dylibs, key=lambda p: len(p.parts), reverse=True):
        sign(item)

    # Extensions are containers themselves, so sign them after their embedded code.
    appexes = [p for p in app.rglob("*.appex") if p.is_dir()]
    for appex in sorted(appexes, key=lambda p: len(p.parts), reverse=True):
        bid = bundle_id(appex)
        ent_path = temp / f"{appex.name}.entitlements.plist"
        write_plist(ent_path, entitlements_for(team_id, bid, data_protection=False))
        sign(appex, ent_path)


def extract_entitlements(app: Path, out: Path) -> dict:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        proc = subprocess.run(
            [CODESIGN, "-d", "--entitlements", ":-", str(app)],
            stdout=f,
            stderr=subprocess.PIPE,
            check=False,
        )
    if proc.returncode != 0:
        sys.stderr.buffer.write(proc.stderr or b"")
        raise subprocess.CalledProcessError(proc.returncode, proc.args)

    try:
        with out.open("rb") as f:
            return plistlib.load(f)
    except Exception:
        print("codesign entitlement output was not a plist:", file=sys.stderr)
        print(out.read_text(errors="replace"), file=sys.stderr)
        if proc.stderr:
            sys.stderr.buffer.write(proc.stderr)
        raise


def verify(app: Path, team_id: str, out: Path) -> tuple[str, str]:
    run([CODESIGN, "--verify", "--deep", "--strict", "--verbose=4", str(app)])
    bid = bundle_id(app)
    expected = f"{team_id}.{bid}"
    ent = extract_entitlements(app, out)

    actual_app_id = ent.get("application-identifier")
    actual_team_id = ent.get("com.apple.developer.team-identifier")
    groups = ent.get("keychain-access-groups", [])

    if actual_app_id != expected:
        raise RuntimeError(
            f"application-identifier mismatch: expected {expected!r}, got {actual_app_id!r}"
        )
    if actual_team_id != team_id:
        raise RuntimeError(
            f"team-identifier mismatch: expected {team_id!r}, got {actual_team_id!r}"
        )
    if expected not in groups:
        raise RuntimeError(
            f"keychain-access-groups missing {expected!r}: got {groups!r}"
        )

    print(f"Bundle ID: {bid}")
    print(f"application-identifier: {actual_app_id}")
    print(f"team-identifier: {actual_team_id}")
    print(f"keychain-access-groups: {groups}")
    return bid, expected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("team_id")
    parser.add_argument("entitlements_output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    app = args.app.resolve()
    if not (app / "Info.plist").is_file():
        raise SystemExit(f"Not an app bundle: {app}")

    if not args.verify_only:
        with tempfile.TemporaryDirectory(prefix="corellium-sign-") as tmp:
            temp = Path(tmp)
            bid = bundle_id(app)
            main_entitlements = temp / "app.entitlements.plist"
            write_plist(
                main_entitlements,
                entitlements_for(args.team_id, bid, data_protection=True),
            )

            sign_nested_code(app, args.team_id, temp)
            sign(app, main_entitlements)

    verify(app, args.team_id, args.entitlements_output)


if __name__ == "__main__":
    main()
