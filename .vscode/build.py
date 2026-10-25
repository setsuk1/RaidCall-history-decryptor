#!/usr/bin/env python3
"""Portable VS Code build entry point for the RaidCall History Decryptor.

Same target command on Windows and Linux. No macOS, no Windows VM, no Docker
assumptions. Windows -> Linux delegates to an installed WSL Linux distribution.
Run from the project root: python3 .vscode/build.py --target windows|linux|both
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_WIN = "x86_64-pc-windows-gnu"


class BuildError(RuntimeError):
    pass


def host_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    raise BuildError("Only Windows and Linux hosts are supported. macOS is out of scope.")


def run(cmd: list[str], *, env: dict[str, str] | None = None,
        cwd: Path = ROOT) -> None:
    print("+", subprocess.list2cmdline(cmd) if os.name == "nt" else
          " ".join(__import__("shlex").quote(arg) for arg in cmd), flush=True)
    try:
        subprocess.run(cmd, cwd=cwd, env=env, check=True)
    except FileNotFoundError as exc:
        raise BuildError(f"Missing executable: {cmd[0]}. Install the required toolchain.") from exc
    except subprocess.CalledProcessError as exc:
        raise BuildError(f"Build command failed with exit code {exc.returncode}: {cmd[0]}") from exc


def need(program: str, instruction: str) -> None:
    if shutil.which(program) is None:
        raise BuildError(f"Missing '{program}'. {instruction}")


def installed_target(target: str) -> None:
    need("rustup", "Install Rust from https://rustup.rs/")
    targets = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True, text=True, check=True
    ).stdout.splitlines()
    if target not in targets:
        print(f"Installing missing Rust target: {target}", flush=True)
        run(["rustup", "target", "add", target])


def wsl_linux_build(args: argparse.Namespace) -> None:
    need("wsl.exe", "Install WSL with 'wsl --install -d Ubuntu', then configure Rust and build prerequisites inside WSL.")
    try:
        path = subprocess.run(
            ["wsl.exe", "--exec", "wslpath", "-u", str(ROOT)],
            capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BuildError(
            "Could not access the source folder from WSL. Install/configure a WSL2 Linux distribution "
            "and ensure it can access this checkout (for example /mnt/c/...)."
        ) from exc
    if not path.startswith("/"):
        raise BuildError(f"WSL did not return a usable Linux path: {path!r}")
    # With --cd, WSL uses its own Linux Python and Rust toolchain.
    # The invoked helper detects Linux, so it cannot recurse into WSL.
    command = [
        "wsl.exe", "--cd", path, "--exec", "python3",
        ".vscode/build.py", "--target", "linux", "--mode", args.mode,
    ]
    if args.run:
        command.append("--run")
    run(command)
    print(f"Linux binary was built by WSL; output lives in the checkout under {path}", flush=True)


def decryptor_build(target: str, mode: str) -> list[Path]:
    need("cargo", "Install Rust via rustup.")
    args = ["cargo", "build"]
    if mode == "release":
        args.append("--release")
    extra: list[str] = []
    directory = ROOT / "target"
    env = os.environ.copy()
    if target == "windows" and host_platform() == "linux":
        need("x86_64-w64-mingw32-gcc", "Install MinGW-w64 and its x86_64 resource compiler (windres).")
        need("x86_64-w64-mingw32-windres", "Install MinGW-w64 binutils for Windows icon embedding.")
        installed_target(TARGET_WIN)
        extra = ["--target", TARGET_WIN]
        env["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] = "x86_64-w64-mingw32-gcc"
        directory /= TARGET_WIN
    args.extend(extra)
    run(args + ["--bin", "rc-dat-decrypt"], env=env)
    run(args + ["--features", "gui", "--bin", "raidcall-gui"], env=env)
    directory /= "release" if mode == "release" else "debug"
    suffix = ".exe" if target == "windows" else ""
    return [directory / ("rc-dat-decrypt" + suffix), directory / ("raidcall-gui" + suffix)]


def build(target: str, args: argparse.Namespace) -> None:
    host = host_platform()
    print(f"[decryptor] host={host}; requested={target}; mode={args.mode}", flush=True)
    if host == "windows" and target == "linux":
        wsl_linux_build(args)
        return
    outputs = decryptor_build(target, args.mode)
    print("Expected output(s):", flush=True)
    for output in outputs:
        print(" -", output, flush=True)
        if not output.is_file():
            raise BuildError(f"Build returned success, but executable was not found: {output}")
    if args.run:
        if target != host:
            raise BuildError("Only a native build can be run on the current host; choose '--target native'.")
        # The CLI requires an input .dat; launch the GUI for --run.
        program = outputs[1]
        run([str(program)])


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto-select native/cross toolchain by build target and host OS.")
    parser.add_argument("--target", choices=["windows", "linux", "both", "native"], required=True)
    parser.add_argument("--mode", choices=["release", "debug"], default="release")
    parser.add_argument("--run", action="store_true", help="Launch a native-built GUI after success.")
    args = parser.parse_args()
    try:
        targets = (["windows", "linux"] if args.target == "both" else
                   [host_platform()] if args.target == "native" else [args.target])
        if args.run and (len(targets) != 1 or targets[0] != host_platform()):
            raise BuildError("--run is only available with '--target native'.")
        for target in targets:
            build(target, args)
        return 0
    except (BuildError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
