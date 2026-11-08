#!/usr/bin/env python3
"""Safely validate and update firewall-web's EnvironmentFile without sourcing it."""

import argparse
import ipaddress
import json
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


DEFAULTS = {
    "NFT_SECRET": "",
    "NFT_HOST": "127.0.0.1",
    "NFT_PORT": "5005",
    "NFT_ALLOWED_ORIGINS": "",
    "NFT_BACKUP_DIR": "/var/lib/firewall-web/backups",
    "NFT_NATIVE_STATE": "/var/lib/firewall-web/native-rules.json",
    "NFT_BACKEND": "auto",
    "NFT_BACKEND_ACK": "",
}
BACKENDS = {"auto", "ufw", "firewalld", "nftables", "iptables", "inspection"}
ASSIGNMENT = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./,:@+-]*$")
PIN_FILE = Path("/var/lib/firewall-web/initial-pin")


class ConfigError(Exception):
    pass


def decode_value(value):
    try:
        parts = shlex.split(value, comments=False, posix=True)
    except ValueError as exc:
        raise ConfigError("Invalid quoting in configuration.") from exc
    if len(parts) > 1:
        raise ConfigError("Configuration values must not contain unquoted whitespace.")
    return parts[0] if parts else ""


def encode_value(value):
    return value if SAFE_VALUE.fullmatch(value) else json.dumps(value)


def read_config(path):
    values = {}
    if not path.exists():
        return values
    if path.is_symlink() or not path.is_file():
        raise ConfigError(f"Configuration is not a regular file: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"Cannot read configuration: {path}") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(line)
        if not match:
            raise ConfigError("Configuration contains a malformed assignment.")
        values[match.group(1)] = decode_value(match.group(2))
    return values


def validate_host(value):
    if not value or value.strip() != value or any(char.isspace() for char in value):
        raise ConfigError("NFT_HOST must be an IP address or hostname.")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", value):
        raise ConfigError("NFT_HOST must be a valid IP address or hostname.")
    if value.lower() == "localhost" or HOSTNAME.fullmatch(value):
        return
    raise ConfigError("NFT_HOST must be an IP address or hostname.")


def validate_port(value):
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ConfigError("NFT_PORT must be an integer from 1 to 65535.")


def validate_backend(value):
    if value not in BACKENDS:
        raise ConfigError("NFT_BACKEND must be auto, ufw, firewalld, nftables, iptables, or inspection.")


def validate_ack(value):
    if value and value != "active-managers:firewalld,ufw":
        raise ConfigError("NFT_BACKEND_ACK is not a supported conflict acknowledgement.")


def validate_secret(value):
    if not re.fullmatch(r"[0-9]{4}", value, flags=re.ASCII):
        raise ConfigError("NFT_SECRET must contain exactly four digits.")


def validate_values(values):
    validate_secret(values.get("NFT_SECRET", ""))
    validate_host(values.get("NFT_HOST", ""))
    validate_port(values.get("NFT_PORT", ""))
    validate_backend(values.get("NFT_BACKEND", ""))
    validate_ack(values.get("NFT_BACKEND_ACK", ""))


def random_pin():
    return f"{secrets.randbelow(10000):04d}"


def atomic_write(path, lines):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ConfigError(f"Refusing to replace a symlink: {path}")
    current_stat = path.stat() if path.exists() else None
    owner = (0, 0) if os.geteuid() == 0 else (
        current_stat.st_uid if current_stat else os.getuid(),
        current_stat.st_gid if current_stat else os.getgid(),
    )
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, *owner)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines).rstrip("\n") + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        os.chown(path, *owner)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_pin_file(pin, pin_path):
    atomic_write(pin_path, [pin])


def remove_pin_file(pin_path):
    try:
        info = pin_path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"Refusing to remove a non-regular generated PIN file: {pin_path}")
    pin_path.unlink()


def secure_config(path):
    values = dict(DEFAULTS)
    values.update(read_config(path))
    validate_values(values)
    if not path.exists():
        raise ConfigError(f"Configuration file is missing: {path}")
    os.chmod(path, 0o600)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def check_readiness(path):
    values = dict(DEFAULTS)
    values.update(read_config(path))
    validate_values(values)
    host = values["NFT_HOST"]
    if host in ("0.0.0.0",):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    request = urllib.request.Request(
        f"http://{host}:{values['NFT_PORT']}/api/health",
        headers={"X-Secret": values["NFT_SECRET"]},
    )
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError, TimeoutError):
        return False


def apply_config(path, mode, answers, pin_path=PIN_FILE):
    values = read_config(path)
    incoming = dict(zip(("NFT_HOST", "NFT_PORT", "NFT_SECRET", "NFT_BACKEND", "NFT_BACKEND_ACK"), answers))
    if len(answers) != 5:
        raise ConfigError("Expected five configuration answers.")

    merged = dict(DEFAULTS)
    merged.update(values)
    for key in ("NFT_HOST", "NFT_PORT", "NFT_BACKEND", "NFT_BACKEND_ACK"):
        candidate = incoming[key]
        if mode == "reconfigure":
            merged[key] = candidate
            continue
        if mode == "update":
            if candidate:
                merged[key] = candidate
            continue
        if key not in values:
            merged[key] = candidate
            continue
        try:
            {"NFT_HOST": validate_host, "NFT_PORT": validate_port,
             "NFT_BACKEND": validate_backend, "NFT_BACKEND_ACK": validate_ack}[key](merged[key])
        except ConfigError:
            merged[key] = candidate

    supplied_pin = incoming["NFT_SECRET"]
    generated = False
    if mode == "reconfigure" or (mode == "initial" and
                                  not re.fullmatch(r"[0-9]{4}", merged["NFT_SECRET"], flags=re.ASCII)):
        if supplied_pin:
            validate_secret(supplied_pin)
            merged["NFT_SECRET"] = supplied_pin
            remove_pin_file(pin_path)
        else:
            merged["NFT_SECRET"] = random_pin()
            write_pin_file(merged["NFT_SECRET"], pin_path)
            generated = True
    validate_values(merged)

    original_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    updated = []
    emitted = set()
    for line in original_lines:
        match = ASSIGNMENT.fullmatch(line)
        if not match or match.group(1) not in DEFAULTS:
            updated.append(line)
            continue
        key = match.group(1)
        if key not in emitted:
            updated.append(f"{key}={encode_value(merged[key])}")
            emitted.add(key)
    for key in DEFAULTS:
        if key not in emitted:
            updated.append(f"{key}={encode_value(merged[key])}")
    atomic_write(path, updated)
    print("generated" if generated else "configured")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--config", type=Path, required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--config", type=Path, required=True)
    apply_parser.add_argument("--mode", choices=("initial", "reconfigure", "update"), required=True)
    apply_parser.add_argument("--pin-file", type=Path, default=PIN_FILE)
    read_parser = subparsers.add_parser("read")
    read_parser.add_argument("--config", type=Path, required=True)
    read_parser.add_argument("key")
    secure_parser = subparsers.add_parser("secure")
    secure_parser.add_argument("--config", type=Path, required=True)
    ready_parser = subparsers.add_parser("ready")
    ready_parser.add_argument("--config", type=Path, required=True)
    exec_parser = subparsers.add_parser("exec")
    exec_parser.add_argument("--config", type=Path, required=True)
    exec_parser.add_argument("argv", nargs=argparse.REMAINDER)
    value_parser = subparsers.add_parser("validate-value")
    value_parser.add_argument("key")
    value_parser.add_argument("value")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            values = dict(DEFAULTS)
            values.update(read_config(args.config))
            validate_values(values)
            print("Configuration is valid.")
        elif args.command == "apply":
            answers = [line.rstrip("\n") for line in sys.stdin]
            apply_config(args.config, args.mode, answers, args.pin_file)
        elif args.command == "read":
            print(read_config(args.config).get(args.key, ""))
        elif args.command == "secure":
            secure_config(args.config)
        elif args.command == "ready":
            if not check_readiness(args.config):
                return 1
        elif args.command == "validate-value":
            validators = {
                "NFT_HOST": validate_host,
                "NFT_PORT": validate_port,
                "NFT_SECRET": validate_secret,
                "NFT_BACKEND": validate_backend,
                "NFT_BACKEND_ACK": validate_ack,
            }
            if args.key not in validators:
                raise ConfigError("Unsupported configuration key.")
            validators[args.key](args.value)
        elif args.command == "exec":
            command = args.argv
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                raise ConfigError("A command is required.")
            environment = os.environ.copy()
            environment.update({key: value for key, value in read_config(args.config).items()
                                if key.startswith("NFT_")})
            os.execvpe(command[0], command, environment)
    except (ConfigError, OSError) as exc:
        print(f"firewall-web configuration error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
