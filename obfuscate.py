#!/usr/bin/env python3
"""PyObf - AST-based Python script obfuscator."""

from __future__ import annotations

import argparse
import ast
import base64
import builtins
import configparser
import itertools
import keyword
import os
import random
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

DEFAULT_INI = "pyobf.ini"
DEFAULT_ENV_PATH = r"C:/Users/"


@dataclass
class ObfConfig:
    output_filename: str = ""

    name_length_min: int = 3
    name_length_max: int = 3

    junk_frequency: int = 6

    use_env_key: bool = True
    env_key_path: str = DEFAULT_ENV_PATH
    use_xor: bool = True
    use_swap: bool = True
    use_rotate: bool = True
    use_byte_shuffle: bool = True
    use_base85: bool = True

    rename: bool = True
    hide_imports: bool = True
    value_calc: bool = True
    encrypt_strings: bool = True

    seed: Optional[int] = None

    def junk_probability(self) -> float:
        return max(0.0, min(1.0, self.junk_frequency / 10.0))

    def middle_ops(self) -> list[str]:
        ops: list[str] = []
        if self.use_swap:
            ops.append("swap")
        if self.use_rotate:
            ops.append("rotate")
        if self.use_byte_shuffle:
            ops.append("shuffle")
        return ops

def _parse_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}

def _parse_name_length(spec: str) -> tuple[int, int]:
    spec = (spec or "3").strip()
    if "-" in spec:
        left, right = spec.split("-", 1)
        lo, hi = int(left.strip()), int(right.strip())
    else:
        lo = hi = int(spec)
    if lo < 1 or hi < lo:
        raise ValueError(f"Invalid name length spec: {spec!r}")
    return lo, hi

def load_config(ini_path: Optional[str] = None) -> ObfConfig:
    cfg = ObfConfig()
    path = Path(ini_path or DEFAULT_INI)
    if not path.is_file():
        return cfg

    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    def get(section: str, key: str, fallback: str = "") -> str:
        if parser.has_option(section, key):
            return parser.get(section, key)
        return fallback

    def getb(section: str, key: str, fallback: bool) -> bool:
        if parser.has_option(section, key):
            return _parse_bool(parser.get(section, key), fallback)
        return fallback

    def geti(section: str, key: str, fallback: int) -> int:
        if parser.has_option(section, key):
            return int(parser.get(section, key))
        return fallback

    cfg.output_filename = get("output", "filename", cfg.output_filename).strip()

    length_spec = get("names", "length", str(cfg.name_length_min))
    cfg.name_length_min, cfg.name_length_max = _parse_name_length(length_spec)

    cfg.junk_frequency = max(0, min(10, geti("junk", "frequency", cfg.junk_frequency)))

    cfg.use_env_key = getb("string", "env_key", cfg.use_env_key)
    cfg.env_key_path = get("string", "env_key_path", cfg.env_key_path) or DEFAULT_ENV_PATH
    cfg.use_xor = getb("string", "xor", cfg.use_xor)
    cfg.use_swap = getb("string", "swap", cfg.use_swap)
    cfg.use_rotate = getb("string", "rotate", cfg.use_rotate)
    cfg.use_byte_shuffle = getb("string", "byte_shuffle", cfg.use_byte_shuffle)
    cfg.use_base85 = getb("string", "base85", cfg.use_base85)

    cfg.rename = getb("obfuscation", "rename", cfg.rename)
    cfg.hide_imports = getb("obfuscation", "hide_imports", cfg.hide_imports)
    cfg.value_calc = getb("obfuscation", "value_calc", cfg.value_calc)
    cfg.encrypt_strings = getb("obfuscation", "encrypt_strings", cfg.encrypt_strings)

    seed_raw = get("obfuscation", "seed", "").strip()
    if seed_raw:
        cfg.seed = int(seed_raw)

    return cfg


class NameGen:
    def __init__(self, existing_names: Iterable[str], length_min: int = 3, length_max: int = 3):
        self.length_min = length_min
        self.length_max = length_max
        reserved = set(keyword.kwlist) | set(dir(builtins))
        self.used = set(existing_names) | reserved

    def new_name(self) -> str:
        while True:
            length = random.randint(self.length_min, self.length_max)
            name = "".join(random.choice(string.ascii_letters) for _ in range(length))
            if name not in self.used:
                self.used.add(name)
                return name

namegen = NameGen

def collectexisting(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name)
    return names

def isdunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")

def collectimported(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                names.add(alias.asname or alias.name)
    return names

def collectrenemablefuncs(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not isdunder(node.name):
                names.add(node.name)
    return names

def collectrenemablevars(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    imported = collectimported(tree)
    reserved = set(keyword.kwlist) | set(dir(builtins))

    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            if not isdunder(node.arg):
                names.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if not isdunder(node.id):
                names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            if not isdunder(node.name):
                names.add(node.name)
        elif isinstance(node, ast.MatchAs) and node.name:
            if not isdunder(node.name):
                names.add(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            if not isdunder(node.name):
                names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            if not isdunder(node.rest):
                names.add(node.rest)

    names -= imported
    names -= reserved
    return names

def collectrenemable(tree: ast.AST) -> set[str]:
    return collectrenemablefuncs(tree)

def names_defined_by_stmt(stmt: ast.AST) -> set[str]:
    """Names bound by a top-level statement (best-effort)."""
    out: set[str] = set()
    if isinstance(stmt, ast.Assign):
        for t in stmt.targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    out.add(n.id)
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        t = stmt.target
        if isinstance(t, ast.Name):
            out.add(t.id)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        out.add(stmt.name)
    elif isinstance(stmt, ast.For):
        for n in ast.walk(stmt.target):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                out.add(n.id)
    elif isinstance(stmt, ast.With):
        for item in stmt.items:
            if item.optional_vars:
                for n in ast.walk(item.optional_vars):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                        out.add(n.id)
    elif isinstance(stmt, ast.ExceptHandler) and stmt.name:
        out.add(stmt.name)
    elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
        for alias in stmt.names:
            if alias.name == "*":
                continue
            out.add(alias.asname or alias.name.split(".")[0])
    return out

class renameidents(ast.NodeTransformer):
    def __init__(self, name_map: dict[str, str], attr_names: Optional[set[str]] = None):
        self.name_map = name_map
        self.attr_names = attr_names if attr_names is not None else set(name_map)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self.generic_visit(node)
        if node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id in self.name_map:
            node.id = self.name_map[node.id]
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
        self.generic_visit(node)
        if node.attr in self.attr_names and node.attr in self.name_map:
            node.attr = self.name_map[node.attr]
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        if node.arg in self.name_map:
            node.arg = self.name_map[node.arg]
        if node.annotation is not None:
            node.annotation = self.visit(node.annotation)
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        local_func = False
        if isinstance(node.func, ast.Name) and node.func.id in self.attr_names:
            local_func = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in self.attr_names:
            local_func = True

        node.func = self.visit(node.func)
        node.args = [self.visit(a) for a in node.args]
        new_keywords = []
        for kw in node.keywords:
            arg = kw.arg
            if local_func and arg is not None and arg in self.name_map:
                arg = self.name_map[arg]
            new_keywords.append(ast.keyword(arg=arg, value=self.visit(kw.value)))
        node.keywords = new_keywords
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        self.generic_visit(node)
        if node.name is not None and node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    def visit_Global(self, node: ast.Global) -> ast.AST:
        node.names = [self.name_map.get(n, n) for n in node.names]
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
        node.names = [self.name_map.get(n, n) for n in node.names]
        return node

    def visit_MatchAs(self, node: ast.MatchAs) -> ast.AST:
        self.generic_visit(node)
        if node.name is not None and node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    def visit_MatchStar(self, node: ast.MatchStar) -> ast.AST:
        self.generic_visit(node)
        if node.name is not None and node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    def visit_MatchMapping(self, node: ast.MatchMapping) -> ast.AST:
        self.generic_visit(node)
        if node.rest is not None and node.rest in self.name_map:
            node.rest = self.name_map[node.rest]
        return node

renamefunc = renameidents

def _obf_int_expr(value: int) -> ast.expr:
    if value == 0:
        a = random.randint(2, 30)
        return ast.BinOp(left=ast.Constant(value=a), op=ast.Sub(), right=ast.Constant(value=a))
    if value == 1:
        a = random.randint(2, 20)
        return ast.BinOp(left=ast.Constant(value=a), op=ast.FloorDiv(), right=ast.Constant(value=a))
    if value == -1:
        a = random.randint(2, 20)
        return ast.UnaryOp(
            op=ast.USub(),
            operand=ast.BinOp(
                left=ast.Constant(value=a), op=ast.FloorDiv(), right=ast.Constant(value=a)
            ),
        )

    kind = random.randint(0, 4)
    if kind == 0 and abs(value) < 10**6:
        a = random.randint(1, 50)
        b = value - a
        return ast.BinOp(left=ast.Constant(value=a), op=ast.Add(), right=ast.Constant(value=b))
    if kind == 1 and abs(value) < 10**6:
        a = random.randint(1, 50)
        b = value + a
        return ast.BinOp(left=ast.Constant(value=b), op=ast.Sub(), right=ast.Constant(value=a))
    if kind == 2 and value != 0 and abs(value) < 10**5:
        factors = [d for d in range(2, min(abs(value), 40) + 1) if value % d == 0]
        if factors:
            a = random.choice(factors)
            b = value // a
            return ast.BinOp(left=ast.Constant(value=a), op=ast.Mult(), right=ast.Constant(value=b))
    if kind == 3 and abs(value) < 10**6:
        a = random.randint(2, 17)
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.Constant(value=value * a),
                op=ast.Add(),
                right=ast.Constant(value=a - 1),
            ),
            op=ast.FloorDiv(),
            right=ast.Constant(value=a),
        )
    if 0 <= value <= 255:
        a = random.randint(1, 255)
        b = value ^ a
        return ast.BinOp(left=ast.Constant(value=a), op=ast.BitXor(), right=ast.Constant(value=b))

    a = random.randint(1, 40)
    return ast.BinOp(left=ast.Constant(value=value + a), op=ast.Sub(), right=ast.Constant(value=a))


def _obf_byte_expr(b: int) -> ast.expr:
    b &= 0xFF
    kind = random.randint(0, 3)
    if kind == 0:
        a = random.randint(0, 255)
        return ast.BinOp(left=ast.Constant(value=a), op=ast.BitXor(), right=ast.Constant(value=b ^ a))
    if kind == 1:
        a = random.randint(0, b) if b else 0
        return ast.BinOp(left=ast.Constant(value=a), op=ast.Add(), right=ast.Constant(value=b - a))
    if kind == 2:
        a = random.randint(0, 64)
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.Constant(value=(b + a) & 0xFF),
                op=ast.Add(),
                right=ast.Constant(value=256 - a if a else 0),
            ),
            op=ast.BitAnd(),
            right=ast.Constant(value=255),
        )
    a = random.randint(1, 9)
    return ast.BinOp(
        left=ast.Constant(value=b + a * 256),
        op=ast.Mod(),
        right=ast.Constant(value=256),
    )


class ObfuscateValues(ast.NodeTransformer):
    def __init__(self):
        self._skip_ids: set[int] = set()

    def _mark_skip_tree(self, node: Optional[ast.AST]) -> None:
        if node is None:
            return
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant):
                self._skip_ids.add(id(sub))

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        new_values = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                new_values.append(self.visit(v))
            else:
                if isinstance(v, ast.Constant):
                    self._skip_ids.add(id(v))
                new_values.append(v)
        node.values = new_values
        return node

    def visit_FormattedValue(self, node: ast.FormattedValue) -> ast.AST:
        node.value = self.visit(node.value)
        if node.format_spec is not None:
            node.format_spec = self.visit(node.format_spec)
        return node

    def visit_Match(self, node: ast.Match) -> ast.AST:
        for case in node.cases:
            self._mark_skip_tree(case.pattern)
            if case.guard:
                case.guard = self.visit(case.guard)
            case.body = [self.visit(s) for s in case.body]
        node.subject = self.visit(node.subject)
        return node

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if id(node) in self._skip_ids:
            return node
        val = node.value
        if isinstance(val, bool) or val is None:
            return node
        if isinstance(val, int):
            return ast.copy_location(_obf_int_expr(val), node)
        if isinstance(val, float) and val == int(val) and abs(val) < 10**6:
            return ast.copy_location(
                ast.Call(
                    func=ast.Name(id="float", ctx=ast.Load()),
                    args=[_obf_int_expr(int(val))],
                    keywords=[],
                ),
                node,
            )
        return node

def _load_module_ast(module: str, fromlist: Optional[list[str]] = None) -> ast.expr:
    builtins_mod = ast.Call(
        func=ast.Name(id="__import__", ctx=ast.Load()),
        args=[ast.Constant(value="builtins")],
        keywords=[],
    )
    imp = ast.Call(
        func=ast.Name(id="getattr", ctx=ast.Load()),
        args=[builtins_mod, ast.Constant(value="__import__")],
        keywords=[],
    )
    args: list[ast.expr] = [ast.Constant(value=module)]
    keywords: list[ast.keyword] = []
    if fromlist:
        keywords.append(
            ast.keyword(
                arg="fromlist",
                value=ast.List(elts=[ast.Constant(value=x) for x in fromlist], ctx=ast.Load()),
            )
        )
    return ast.Call(func=imp, args=args, keywords=keywords)


def _getattr_ast(obj: ast.expr, name: str) -> ast.expr:
    return ast.Call(
        func=ast.Name(id="getattr", ctx=ast.Load()),
        args=[obj, ast.Constant(value=name)],
        keywords=[],
    )


class HideImports(ast.NodeTransformer):
    def visit_Module(self, node: ast.Module) -> ast.Module:
        new_body: list[ast.stmt] = []
        for stmt in node.body:
            replacement = self._convert_import(stmt)
            if replacement is not None:
                new_body.extend(replacement)
            else:
                new_body.append(self.visit(stmt))
        node.body = new_body
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._process_body_container(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        return self._process_body_container(node)

    def visit_For(self, node: ast.For) -> ast.AST:
        return self._process_body_container(node)

    def visit_While(self, node: ast.While) -> ast.AST:
        return self._process_body_container(node)

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)
        node.body = self._rewrite_body(node.body)
        node.orelse = self._rewrite_body(node.orelse)
        return node

    def visit_With(self, node: ast.With) -> ast.AST:
        return self._process_body_container(node)

    def visit_Try(self, node: ast.Try) -> ast.AST:
        self.generic_visit(node)
        node.body = self._rewrite_body(node.body)
        node.orelse = self._rewrite_body(node.orelse)
        node.finalbody = self._rewrite_body(node.finalbody)
        for h in node.handlers:
            h.body = self._rewrite_body(h.body)
        return node

    def _process_body_container(self, node: ast.AST) -> ast.AST:
        self.generic_visit(node)
        if hasattr(node, "body"):
            node.body = self._rewrite_body(node.body)
        if hasattr(node, "orelse"):
            node.orelse = self._rewrite_body(node.orelse)
        return node

    def _rewrite_body(self, body: list[ast.stmt]) -> list[ast.stmt]:
        new_body: list[ast.stmt] = []
        for stmt in body:
            replacement = self._convert_import(stmt)
            if replacement is not None:
                new_body.extend(replacement)
            else:
                new_body.append(stmt)
        return new_body

    def _convert_import(self, stmt: ast.stmt) -> Optional[list[ast.stmt]]:
        if isinstance(stmt, ast.Import):
            assigns: list[ast.stmt] = []
            for alias in stmt.names:
                mod = alias.name
                bind = alias.asname or mod.split(".")[0]
                if alias.asname:
                    expr = _load_module_ast(mod)
                else:
                    top = mod.split(".")[0]
                    expr = _load_module_ast(top)
                    bind = top
                assigns.append(
                    ast.fix_missing_locations(
                        ast.Assign(
                            targets=[ast.Name(id=bind, ctx=ast.Store())],
                            value=expr,
                        )
                    )
                )
            return assigns

        if isinstance(stmt, ast.ImportFrom):
            if stmt.module is None or stmt.level and stmt.level > 0:
                return None
            if any(a.name == "*" for a in stmt.names):
                return None
            assigns = []
            mod_expr = _load_module_ast(stmt.module, fromlist=[a.name for a in stmt.names])
            for alias in stmt.names:
                bind = alias.asname or alias.name
                expr = _getattr_ast(
                    _load_module_ast(stmt.module, fromlist=[alias.name]),
                    alias.name,
                )
                assigns.append(
                    ast.fix_missing_locations(
                        ast.Assign(
                            targets=[ast.Name(id=bind, ctx=ast.Store())],
                            value=expr,
                        )
                    )
                )
            return assigns

        return None

MIDDLE_OPS = ("swap", "rotate", "shuffle")


def _keystream(key: bytes, n: int) -> bytes:
    if not key:
        key = b"\x00"
    return bytes(key[i % len(key)] for i in range(n))


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    ks = _keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _swap_bytes(data: bytes) -> bytes:
    b = bytearray(data)
    for i in range(0, len(b) - 1, 2):
        b[i], b[i + 1] = b[i + 1], b[i]
    return bytes(b)


def _rotate_bytes(data: bytes, key: bytes) -> bytes:
    if not data:
        return data
    shift = (key[0] if key else 0) % len(data)
    return data[shift:] + data[:shift]


def _unrotate_bytes(data: bytes, key: bytes) -> bytes:
    if not data:
        return data
    shift = (key[0] if key else 0) % len(data)
    r = (-shift) % len(data)
    return data[r:] + data[:r]


def _shuffle_perm(n: int, key: bytes) -> list[int]:
    perm = list(range(n))
    if n <= 1:
        return perm
    state = 0
    for i, kb in enumerate(key or b"\x01"):
        state = (state * 131 + kb + i * 17) & 0xFFFFFFFF
    for i in range(n - 1, 0, -1):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        j = state % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def _shuffle_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) <= 1:
        return data
    perm = _shuffle_perm(len(data), key)
    return bytes(data[i] for i in perm)


def _unshuffle_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) <= 1:
        return data
    perm = _shuffle_perm(len(data), key)
    out = bytearray(len(data))
    for i, p in enumerate(perm):
        out[p] = data[i]
    return bytes(out)


def get_env_key_material(path: str = DEFAULT_ENV_PATH, length: int = 8) -> bytes:
    try:
        ctime_ms = int(os.path.getctime(path) * 1000)
    except OSError:
        ctime_ms = 0
    material = []
    x = ctime_ms ^ (ctime_ms >> 7) ^ (ctime_ms << 3)
    for i in range(length):
        material.append((x >> ((i * 5) % 24)) & 0xFF)
        x = (x * 1103515245 + 12345 + i) & 0xFFFFFFFF
    return bytes(material)


def mix_keys(rand_key: bytes, env_key: bytes) -> bytes:
    if not env_key:
        return rand_key
    n = max(len(rand_key), len(env_key))
    out = bytearray(n)
    for i in range(n):
        out[i] = rand_key[i % len(rand_key)] ^ env_key[i % len(env_key)]
    return bytes(out)


def encrypt_string(
    value: str,
    cfg: ObfConfig,
    pipeline: tuple[str, ...],
) -> tuple[str | list[int], bytes]:
    """
    Encrypt string.
    Returns (payload, rand_key).
    payload is base85 ascii str if use_base85 else list of int bytes.
    """
    data = value.encode("utf-8")
    rand_key = bytes(random.randint(0, 255) for _ in range(random.randint(4, 12)))
    env = get_env_key_material(cfg.env_key_path) if cfg.use_env_key else b""
    key = mix_keys(rand_key, env)

    if cfg.use_xor:
        data = _xor_bytes(data, key)

    for op in pipeline:
        if op == "swap":
            data = _swap_bytes(data)
        elif op == "rotate":
            data = _rotate_bytes(data, key)
        elif op == "shuffle":
            data = _shuffle_bytes(data, key)

    if cfg.use_base85:
        payload: str | list[int] = base64.b85encode(data).decode("ascii")
    else:
        payload = list(data)
    return payload, rand_key


def decrypt_string(
    payload: str | list[int],
    rand_key: bytes,
    cfg: ObfConfig,
    pipeline: tuple[str, ...],
) -> str:
    """Reference decrypt (for tests / validation)."""
    if cfg.use_base85:
        data = base64.b85decode(payload if isinstance(payload, str) else bytes(payload))
    else:
        data = bytes(payload)
    env = get_env_key_material(cfg.env_key_path) if cfg.use_env_key else b""
    key = mix_keys(rand_key, env)

    for op in reversed(pipeline):
        if op == "swap":
            data = _swap_bytes(data)
        elif op == "rotate":
            data = _unrotate_bytes(data, key)
        elif op == "shuffle":
            data = _unshuffle_bytes(data, key)

    if cfg.use_xor:
        data = _xor_bytes(data, key)
    return data.decode("utf-8")

def _bytes_literal_obf(data: bytes) -> ast.expr:
    """bytes([...obfuscated ints...])."""
    return ast.Call(
        func=ast.Name(id="bytes", ctx=ast.Load()),
        args=[ast.List(elts=[_obf_byte_expr(b) for b in data], ctx=ast.Load())],
        keywords=[],
    )

def _const_str_or_list_payload(payload: str | list[int]) -> ast.expr:
    if isinstance(payload, str):
        return ast.Constant(value=payload)
    return ast.List(elts=[ast.Constant(value=i) for i in payload], ctx=ast.Load())

class StringEncryptor(ast.NodeTransformer):
    def __init__(
        self,
        cfg: ObfConfig,
        name_gen: NameGen,
        decoder_names: dict[tuple[str, ...], str],
        env_func_name: Optional[str],
    ):
        self.cfg = cfg
        self.name_gen = name_gen
        self.decoder_names = decoder_names
        self.env_func_name = env_func_name
        self._skip_ids: set[int] = set()
        self.used_pipelines: set[tuple[str, ...]] = set()

    def _markdocstr(self, node: ast.AST) -> None:
        body = getattr(node, "body", None)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            self._skip_ids.add(id(body[0].value))

    def visit_Module(self, node: ast.Module) -> ast.AST:
        self._markdocstr(node)
        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self._markdocstr(node)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        self._markdocstr(node)
        self.generic_visit(node)
        return node

    def visit_Match(self, node: ast.Match) -> ast.AST:
        for case in node.cases:
            for sub in ast.walk(case.pattern):
                if isinstance(sub, ast.Constant):
                    self._skip_ids.add(id(sub))
            case.guard = self.visit(case.guard) if case.guard else None
            case.body = [self.visit(s) for s in case.body]
        node.subject = self.visit(node.subject)
        return node

    def _pick_pipeline(self) -> tuple[str, ...]:
        ops = self.cfg.middle_ops()
        if not ops:
            return tuple()
        chosen = list(ops)
        random.shuffle(chosen)
        return tuple(chosen)

    def _encode_str(self, value: str, template_node: Optional[ast.AST] = None) -> ast.expr:
        pipeline = self._pick_pipeline()
        self.used_pipelines.add(pipeline)
        if pipeline not in self.decoder_names:
            self.decoder_names[pipeline] = self.name_gen.new_name()
        dec_name = self.decoder_names[pipeline]

        payload, rand_key = encrypt_string(value, self.cfg, pipeline)
        key_expr = _bytes_literal_obf(rand_key)
        call = ast.Call(
            func=ast.Name(id=dec_name, ctx=ast.Load()),
            args=[_const_str_or_list_payload(payload), key_expr],
            keywords=[],
        )
        if template_node is not None:
            return ast.copy_location(call, template_node)
        return call

    def _formatted_value_to_str_expr(self, node: ast.FormattedValue) -> ast.expr:
        value = self.visit(node.value)

        if node.conversion == 115:
            value = ast.Call(func=ast.Name(id="str", ctx=ast.Load()), args=[value], keywords=[])
        elif node.conversion == 114:
            value = ast.Call(func=ast.Name(id="repr", ctx=ast.Load()), args=[value], keywords=[])
        elif node.conversion == 97:
            value = ast.Call(func=ast.Name(id="ascii", ctx=ast.Load()), args=[value], keywords=[])

        if node.format_spec is not None:
            spec = self.visit(node.format_spec)
            return ast.Call(
                func=ast.Name(id="format", ctx=ast.Load()),
                args=[value, spec],
                keywords=[],
            )

        if node.conversion in (115, 114, 97):
            return value
        return ast.Call(func=ast.Name(id="format", ctx=ast.Load()), args=[value], keywords=[])

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        parts: list[ast.expr] = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                parts.append(self._formatted_value_to_str_expr(v))
            elif isinstance(v, ast.Constant) and isinstance(v.value, str):
                if v.value != "":
                    parts.append(self._encode_str(v.value, v))
            else:
                parts.append(v)

        if not parts:
            return ast.copy_location(ast.Constant(value=""), node)

        result = parts[0]
        for part in parts[1:]:
            result = ast.BinOp(left=result, op=ast.Add(), right=part)
        return ast.copy_location(result, node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if (
            isinstance(node.value, str)
            and node.value != ""
            and id(node) not in self._skip_ids
        ):
            return self._encode_str(node.value, node)
        return node


def _name(id_: str, ctx: Optional[ast.expr_context] = None) -> ast.Name:
    return ast.Name(id=id_, ctx=ctx or ast.Load())


def _attr(value: ast.expr, attr: str) -> ast.Attribute:
    return ast.Attribute(value=value, attr=attr, ctx=ast.Load())


def _call(func: ast.expr, args: Optional[list] = None, keywords: Optional[list] = None) -> ast.Call:
    return ast.Call(func=func, args=args or [], keywords=keywords or [])


def build_env_key_func(func_name: str, path: str, length: int = 8) -> ast.FunctionDef:
    os_mod = _load_module_ast("os")
    getctime = _getattr_ast(_getattr_ast(os_mod, "path"), "getctime")
    path_expr = ast.Constant(value=path)

    try_body = [
        ast.Assign(
            targets=[_name("x", ast.Store())],
            value=ast.Call(
                func=_name("int"),
                args=[
                    ast.BinOp(
                        left=_call(getctime, [path_expr]),
                        op=ast.Mult(),
                        right=ast.Constant(value=1000),
                    )
                ],
                keywords=[],
            ),
        )
    ]
    except_handler = ast.ExceptHandler(
        type=_name("OSError"),
        name=None,
        body=[ast.Assign(targets=[_name("x", ast.Store())], value=ast.Constant(value=0))],
    )

    body: list[ast.stmt] = [
        ast.Try(body=try_body, handlers=[except_handler], orelse=[], finalbody=[]),
        ast.Assign(
            targets=[_name("x", ast.Store())],
            value=ast.BinOp(
                left=ast.BinOp(
                    left=_name("x"),
                    op=ast.BitXor(),
                    right=ast.BinOp(left=_name("x"), op=ast.RShift(), right=ast.Constant(value=7)),
                ),
                op=ast.BitXor(),
                right=ast.BinOp(left=_name("x"), op=ast.LShift(), right=ast.Constant(value=3)),
            ),
        ),
        ast.Assign(
            targets=[_name("m", ast.Store())],
            value=ast.List(elts=[], ctx=ast.Load()),
        ),
    ]

    loop_body = [
        ast.Expr(
            value=_call(
                _attr(_name("m"), "append"),
                [
                    ast.BinOp(
                        left=ast.BinOp(
                            left=_name("x"),
                            op=ast.RShift(),
                            right=ast.BinOp(
                                left=ast.BinOp(
                                    left=_name("i"), op=ast.Mult(), right=ast.Constant(value=5)
                                ),
                                op=ast.Mod(),
                                right=ast.Constant(value=24),
                            ),
                        ),
                        op=ast.BitAnd(),
                        right=ast.Constant(value=255),
                    )
                ],
            )
        ),
        ast.Assign(
            targets=[_name("x", ast.Store())],
            value=ast.BinOp(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=_name("x"),
                            op=ast.Mult(),
                            right=ast.Constant(value=1103515245),
                        ),
                        op=ast.Add(),
                        right=ast.Constant(value=12345),
                    ),
                    op=ast.Add(),
                    right=_name("i"),
                ),
                op=ast.BitAnd(),
                right=ast.Constant(value=0xFFFFFFFF),
            ),
        ),
    ]
    body.append(
        ast.For(
            target=_name("i", ast.Store()),
            iter=_call(_name("range"), [ast.Constant(value=length)]),
            body=loop_body,
            orelse=[],
        )
    )
    body.append(ast.Return(value=_call(_name("bytes"), [_name("m")])))

    return ast.fix_missing_locations(
        ast.FunctionDef(
            name=func_name,
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=body,
            decorator_list=[],
            returns=None,
        )
    )


def build_decoder_func(
    func_name: str,
    pipeline: tuple[str, ...],
    cfg: ObfConfig,
    env_func_name: Optional[str],
    helper_names: dict[str, str],
) -> ast.FunctionDef:
    s_name = "s"
    k_name = "k"
    d_name = "d"

    body: list[ast.stmt] = []

    if cfg.use_env_key and env_func_name:
        body.append(
            ast.Assign(
                targets=[_name("e", ast.Store())],
                value=_call(_name(env_func_name)),
            )
        )
        body.append(
            ast.Assign(
                targets=[_name("n", ast.Store())],
                value=_call(
                    _name("max"),
                    [_call(_name("len"), [_name(k_name)]), _call(_name("len"), [_name("e")])],
                ),
            )
        )
        body.append(
            ast.Assign(
                targets=[_name(k_name, ast.Store())],
                value=ast.Call(
                    func=_name("bytes"),
                    args=[
                        ast.ListComp(
                            elt=ast.BinOp(
                                left=ast.Subscript(
                                    value=_name(k_name),
                                    slice=ast.BinOp(
                                        left=_name("i"),
                                        op=ast.Mod(),
                                        right=_call(_name("len"), [_name(k_name)]),
                                    ),
                                    ctx=ast.Load(),
                                ),
                                op=ast.BitXor(),
                                right=ast.Subscript(
                                    value=_name("e"),
                                    slice=ast.BinOp(
                                        left=_name("i"),
                                        op=ast.Mod(),
                                        right=_call(_name("len"), [_name("e")]),
                                    ),
                                    ctx=ast.Load(),
                                ),
                            ),
                            generators=[
                                ast.comprehension(
                                    target=_name("i", ast.Store()),
                                    iter=_call(_name("range"), [_name("n")]),
                                    ifs=[],
                                    is_async=0,
                                )
                            ],
                        )
                    ],
                    keywords=[],
                ),
            )
        )

    if cfg.use_base85:
        b64 = _load_module_ast("base64")
        b85 = _getattr_ast(b64, "b85decode")
        body.append(
            ast.Assign(
                targets=[_name(d_name, ast.Store())],
                value=_call(b85, [_name(s_name)]),
            )
        )
    else:
        body.append(
            ast.Assign(
                targets=[_name(d_name, ast.Store())],
                value=_call(_name("bytes"), [_name(s_name)]),
            )
        )

    for op in reversed(pipeline):
        if op == "swap":
            body.extend(_ast_swap_inplace(d_name, helper_names))
        elif op == "rotate":
            body.extend(_ast_unrotate(d_name, k_name))
        elif op == "shuffle":
            body.extend(_ast_unshuffle(d_name, k_name, helper_names))

    if cfg.use_xor:
        body.extend(_ast_xor_inplace(d_name, k_name))

    body.append(
        ast.Return(
            value=_call(
                _attr(_name(d_name), "decode"),
                [ast.Constant(value="utf-8")],
            )
        )
    )

    return ast.fix_missing_locations(
        ast.FunctionDef(
            name=func_name,
            args=ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg=s_name), ast.arg(arg=k_name)],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=body,
            decorator_list=[],
            returns=None,
        )
    )


def _ast_swap_inplace(d_name: str, helper_names: dict[str, str]) -> list[ast.stmt]:
    return [
        ast.Assign(
            targets=[_name("b", ast.Store())],
            value=_call(_name("bytearray"), [_name(d_name)]),
        ),
        ast.For(
            target=_name("i", ast.Store()),
            iter=_call(
                _name("range"),
                [
                    ast.Constant(value=0),
                    ast.BinOp(
                        left=_call(_name("len"), [_name("b")]),
                        op=ast.Sub(),
                        right=ast.Constant(value=1),
                    ),
                    ast.Constant(value=2),
                ],
            ),
            body=[
                ast.Assign(
                    targets=[
                        ast.Tuple(
                            elts=[
                                ast.Subscript(
                                    value=_name("b"), slice=_name("i"), ctx=ast.Store()
                                ),
                                ast.Subscript(
                                    value=_name("b"),
                                    slice=ast.BinOp(
                                        left=_name("i"), op=ast.Add(), right=ast.Constant(value=1)
                                    ),
                                    ctx=ast.Store(),
                                ),
                            ],
                            ctx=ast.Store(),
                        )
                    ],
                    value=ast.Tuple(
                        elts=[
                            ast.Subscript(
                                value=_name("b"),
                                slice=ast.BinOp(
                                    left=_name("i"), op=ast.Add(), right=ast.Constant(value=1)
                                ),
                                ctx=ast.Load(),
                            ),
                            ast.Subscript(value=_name("b"), slice=_name("i"), ctx=ast.Load()),
                        ],
                        ctx=ast.Load(),
                    ),
                )
            ],
            orelse=[],
        ),
        ast.Assign(
            targets=[_name(d_name, ast.Store())],
            value=_call(_name("bytes"), [_name("b")]),
        ),
    ]


def _ast_unrotate(d_name: str, k_name: str) -> list[ast.stmt]:
    return [
        ast.If(
            test=_name(d_name),
            body=[
                ast.Assign(
                    targets=[_name("sh", ast.Store())],
                    value=ast.BinOp(
                        left=ast.Subscript(
                            value=_name(k_name), slice=ast.Constant(value=0), ctx=ast.Load()
                        ),
                        op=ast.Mod(),
                        right=_call(_name("len"), [_name(d_name)]),
                    ),
                ),
                ast.Assign(
                    targets=[_name("r", ast.Store())],
                    value=ast.BinOp(
                        left=ast.UnaryOp(op=ast.USub(), operand=_name("sh")),
                        op=ast.Mod(),
                        right=_call(_name("len"), [_name(d_name)]),
                    ),
                ),
                ast.Assign(
                    targets=[_name(d_name, ast.Store())],
                    value=ast.BinOp(
                        left=ast.Subscript(
                            value=_name(d_name),
                            slice=ast.Slice(lower=_name("r"), upper=None, step=None),
                            ctx=ast.Load(),
                        ),
                        op=ast.Add(),
                        right=ast.Subscript(
                            value=_name(d_name),
                            slice=ast.Slice(lower=None, upper=_name("r"), step=None),
                            ctx=ast.Load(),
                        ),
                    ),
                ),
            ],
            orelse=[],
        )
    ]


def _ast_unshuffle(d_name: str, k_name: str, helper_names: dict[str, str]) -> list[ast.stmt]:
    return [
        ast.Assign(
            targets=[_name("n", ast.Store())],
            value=_call(_name("len"), [_name(d_name)]),
        ),
        ast.If(
            test=ast.Compare(
                left=_name("n"), ops=[ast.Gt()], comparators=[ast.Constant(value=1)]
            ),
            body=[
                ast.Assign(
                    targets=[_name("perm", ast.Store())],
                    value=_call(_name("list"), [_call(_name("range"), [_name("n")])]),
                ),
                ast.Assign(targets=[_name("state", ast.Store())], value=ast.Constant(value=0)),
                ast.Assign(
                    targets=[_name("kk", ast.Store())],
                    value=ast.BoolOp(
                        op=ast.Or(),
                        values=[_name(k_name), ast.Constant(value=b"\x01")],
                    ),
                ),
                ast.For(
                    target=ast.Tuple(
                        elts=[_name("ii", ast.Store()), _name("kb", ast.Store())],
                        ctx=ast.Store(),
                    ),
                    iter=_call(_name("enumerate"), [_name("kk")]),
                    body=[
                        ast.Assign(
                            targets=[_name("state", ast.Store())],
                            value=ast.BinOp(
                                left=ast.BinOp(
                                    left=ast.BinOp(
                                        left=ast.BinOp(
                                            left=_name("state"),
                                            op=ast.Mult(),
                                            right=ast.Constant(value=131),
                                        ),
                                        op=ast.Add(),
                                        right=_name("kb"),
                                    ),
                                    op=ast.Add(),
                                    right=ast.BinOp(
                                        left=_name("ii"),
                                        op=ast.Mult(),
                                        right=ast.Constant(value=17),
                                    ),
                                ),
                                op=ast.BitAnd(),
                                right=ast.Constant(value=0xFFFFFFFF),
                            ),
                        )
                    ],
                    orelse=[],
                ),
                ast.For(
                    target=_name("i", ast.Store()),
                    iter=_call(
                        _name("range"),
                        [
                            ast.BinOp(
                                left=_name("n"), op=ast.Sub(), right=ast.Constant(value=1)
                            ),
                            ast.Constant(value=0),
                            ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=1)),
                        ],
                    ),
                    body=[
                        ast.Assign(
                            targets=[_name("state", ast.Store())],
                            value=ast.BinOp(
                                left=ast.BinOp(
                                    left=ast.BinOp(
                                        left=_name("state"),
                                        op=ast.Mult(),
                                        right=ast.Constant(value=1664525),
                                    ),
                                    op=ast.Add(),
                                    right=ast.Constant(value=1013904223),
                                ),
                                op=ast.BitAnd(),
                                right=ast.Constant(value=0xFFFFFFFF),
                            ),
                        ),
                        ast.Assign(
                            targets=[_name("j", ast.Store())],
                            value=ast.BinOp(
                                left=_name("state"),
                                op=ast.Mod(),
                                right=ast.BinOp(
                                    left=_name("i"), op=ast.Add(), right=ast.Constant(value=1)
                                ),
                            ),
                        ),
                        ast.Assign(
                            targets=[
                                ast.Tuple(
                                    elts=[
                                        ast.Subscript(
                                            value=_name("perm"),
                                            slice=_name("i"),
                                            ctx=ast.Store(),
                                        ),
                                        ast.Subscript(
                                            value=_name("perm"),
                                            slice=_name("j"),
                                            ctx=ast.Store(),
                                        ),
                                    ],
                                    ctx=ast.Store(),
                                )
                            ],
                            value=ast.Tuple(
                                elts=[
                                    ast.Subscript(
                                        value=_name("perm"), slice=_name("j"), ctx=ast.Load()
                                    ),
                                    ast.Subscript(
                                        value=_name("perm"), slice=_name("i"), ctx=ast.Load()
                                    ),
                                ],
                                ctx=ast.Load(),
                            ),
                        ),
                    ],
                    orelse=[],
                ),
                ast.Assign(
                    targets=[_name("out", ast.Store())],
                    value=_call(_name("bytearray"), [_name("n")]),
                ),
                ast.For(
                    target=ast.Tuple(
                        elts=[_name("i", ast.Store()), _name("p", ast.Store())],
                        ctx=ast.Store(),
                    ),
                    iter=_call(_name("enumerate"), [_name("perm")]),
                    body=[
                        ast.Assign(
                            targets=[
                                ast.Subscript(
                                    value=_name("out"), slice=_name("p"), ctx=ast.Store()
                                )
                            ],
                            value=ast.Subscript(
                                value=_name(d_name), slice=_name("i"), ctx=ast.Load()
                            ),
                        )
                    ],
                    orelse=[],
                ),
                ast.Assign(
                    targets=[_name(d_name, ast.Store())],
                    value=_call(_name("bytes"), [_name("out")]),
                ),
            ],
            orelse=[],
        ),
    ]


def _ast_xor_inplace(d_name: str, k_name: str) -> list[ast.stmt]:
    return [
        ast.Assign(
            targets=[_name(d_name, ast.Store())],
            value=_call(
                _name("bytes"),
                [
                    ast.ListComp(
                        elt=ast.BinOp(
                            left=ast.Subscript(
                                value=_name(d_name), slice=_name("i"), ctx=ast.Load()
                            ),
                            op=ast.BitXor(),
                            right=ast.Subscript(
                                value=_name(k_name),
                                slice=ast.BinOp(
                                    left=_name("i"),
                                    op=ast.Mod(),
                                    right=_call(_name("len"), [_name(k_name)]),
                                ),
                                ctx=ast.Load(),
                            ),
                        ),
                        generators=[
                            ast.comprehension(
                                target=_name("i", ast.Store()),
                                iter=_call(
                                    _name("range"),
                                    [_call(_name("len"), [_name(d_name)])],
                                ),
                                ifs=[],
                                is_async=0,
                            )
                        ],
                    )
                ],
            ),
        )
    ]

class InsertJunk(ast.NodeTransformer):

    _TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)

    def __init__(self, name_gen: NameGen, probability: float = 0.6):
        self.name_gen = name_gen
        self.probability = probability
        self.scope_stack: list[set[str]] = [set()]

    def _available(self) -> list[str]:
        seen: set[str] = set()
        for scope in self.scope_stack:
            seen |= scope
        return [n for n in seen if n and not isdunder(n)]

    def _push(self, extra: Optional[set[str]] = None) -> None:
        base = set(self.scope_stack[-1]) if self.scope_stack else set()
        if extra:
            base |= extra
        self.scope_stack.append(base)

    def _pop(self) -> None:
        if len(self.scope_stack) > 1:
            self.scope_stack.pop()

    def _bind(self, names: Iterable[str]) -> None:
        self.scope_stack[-1].update(n for n in names if n)

    def _make_junk_stmt(self) -> ast.stmt:
        avail = self._available()
        var = self.name_gen.new_name()
        kind = random.randint(0, 7)

        def ref() -> ast.expr:
            if avail:
                return _name(random.choice(avail))
            return ast.Constant(value=None)

        if kind == 0 and avail:
            r = ref()
            stmt: ast.stmt = ast.Assign(
                targets=[_name(var, ast.Store())],
                value=ast.BinOp(
                    left=_call(_name("id"), [r]),
                    op=ast.BitXor(),
                    right=_call(_name("id"), [ast.Name(id=r.id, ctx=ast.Load())]),
                ),
            )
        elif kind == 1 and avail:
            r = ref()
            rid = r.id
            stmt = ast.Assign(
                targets=[_name(var, ast.Store())],
                value=ast.Compare(
                    left=_name(rid),
                    ops=[ast.Is()],
                    comparators=[_name(rid)],
                ),
            )
        elif kind == 2 and avail:
            r = ref()
            rid = r.id
            stmt = ast.Assign(
                targets=[_name(var, ast.Store())],
                value=ast.IfExp(
                    test=ast.Compare(
                        left=_name(rid), ops=[ast.Is()], comparators=[_name(rid)]
                    ),
                    body=_call(_name("type"), [_name(rid)]),
                    orelse=_call(_name("type"), [ast.Constant(value=None)]),
                ),
            )
        elif kind == 3 and avail:
            r = ref()
            stmt = ast.Assign(
                targets=[_name(var, ast.Store())],
                value=ast.BinOp(
                    left=_call(
                        _name("len"),
                        [_call(_name("str"), [_call(_name("type"), [r])])],
                    ),
                    op=ast.Mult(),
                    right=ast.Constant(value=0),
                ),
            )
        elif kind == 4 and avail:
            r = ref()
            rid = r.id
            stmt = ast.If(
                test=ast.Compare(
                    left=ast.BinOp(
                        left=_call(_name("hash"), [_call(_name("id"), [_name(rid)])]),
                        op=ast.BitOr(),
                        right=ast.Constant(value=1),
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)],
                ),
                body=[
                    ast.Assign(
                        targets=[_name(var, ast.Store())],
                        value=ast.Constant(value=1),
                    )
                ],
                orelse=[
                    ast.Assign(
                        targets=[_name(var, ast.Store())],
                        value=ast.Compare(
                            left=_name(rid),
                            ops=[ast.IsNot()],
                            comparators=[_name(rid)],
                        ),
                    )
                ],
            )
        elif kind == 5 and avail:
            r = ref()
            stmt = ast.Try(
                body=[
                    ast.Assign(
                        targets=[_name(var, ast.Store())],
                        value=ast.BinOp(
                            left=ast.Tuple(elts=[r], ctx=ast.Load()),
                            op=ast.Mult(),
                            right=ast.Constant(value=0),
                        ),
                    )
                ],
                handlers=[
                    ast.ExceptHandler(
                        type=_name("Exception"),
                        name=None,
                        body=[
                            ast.Assign(
                                targets=[_name(var, ast.Store())],
                                value=ast.Constant(value=None),
                            )
                        ],
                    )
                ],
                orelse=[],
                finalbody=[],
            )
        elif kind == 6:
            extra = (
                ast.BinOp(
                    left=_call(_name("id"), [ref()]),
                    op=ast.Mult(),
                    right=ast.Constant(value=0),
                )
                if avail
                else ast.Constant(value=0)
            )
            stmt = ast.Assign(
                targets=[_name(var, ast.Store())],
                value=ast.BinOp(
                    left=_call(_name("sum"), [_call(_name("range"), [ast.Constant(value=0)])]),
                    op=ast.Add(),
                    right=extra,
                ),
            )
        else:
            a = random.randint(2, 20)
            stmt = ast.If(
                test=ast.Compare(
                    left=ast.BinOp(
                        left=ast.Constant(value=a),
                        op=ast.BitXor(),
                        right=ast.Constant(value=a),
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)],
                ),
                body=[
                    ast.Assign(
                        targets=[_name(var, ast.Store())],
                        value=(
                            _call(_name("repr"), [ref()])
                            if avail
                            else ast.Constant(value=random.randint(0, 9))
                        ),
                    )
                ],
                orelse=[
                    ast.Assign(
                        targets=[_name(var, ast.Store())],
                        value=ast.Constant(value=None),
                    )
                ],
            )

        self._bind({var})
        return ast.fix_missing_locations(stmt)

    def _insert_into(self, body: list[ast.stmt]) -> list[ast.stmt]:
        if not body or self.probability <= 0:
            for stmt in body:
                self._bind(names_defined_by_stmt(stmt))
            return body

        new_body: list[ast.stmt] = []
        for stmt in body:
            if random.random() < self.probability:
                new_body.append(self._make_junk_stmt())
            new_body.append(stmt)
            self._bind(names_defined_by_stmt(stmt))

        if body and not isinstance(body[-1], self._TERMINATORS) and random.random() < self.probability:
            new_body.append(self._make_junk_stmt())
        return new_body

    def _process_function(self, node: ast.AST) -> ast.AST:
        args_set: set[str] = set()
        arguments = getattr(node, "args", None)
        if arguments is not None:
            for a in list(arguments.posonlyargs) + list(arguments.args) + list(arguments.kwonlyargs):
                args_set.add(a.arg)
            if arguments.vararg:
                args_set.add(arguments.vararg.arg)
            if arguments.kwarg:
                args_set.add(arguments.kwarg.arg)
        self._push(args_set)

        for field_name, value in ast.iter_fields(node):
            if field_name == "body":
                continue
            if isinstance(value, list):
                setattr(
                    node,
                    field_name,
                    [self.visit(v) if isinstance(v, ast.AST) else v for v in value],
                )
            elif isinstance(value, ast.AST):
                setattr(node, field_name, self.visit(value))

        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            doc, rest = body[0], body[1:]
            rest = [self.visit(s) for s in rest]
            node.body = [doc] + self._insert_into(rest)
        else:
            body = [self.visit(s) for s in body]
            node.body = self._insert_into(body)

        self._pop()
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._process_function(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Module(self, node: ast.Module) -> ast.AST:
        new_body: list[ast.stmt] = []
        body = node.body
        i = 0
        for stmt in body:
            visited = self.visit(stmt)
            if self.probability > 0 and random.random() < self.probability * 0.5:
                if not isinstance(visited, (ast.Import, ast.ImportFrom)) and not (
                    isinstance(visited, ast.Expr)
                    and isinstance(visited.value, ast.Constant)
                    and isinstance(visited.value.value, str)
                ):
                    new_body.append(self._make_junk_stmt())
            new_body.append(visited)
            self._bind(names_defined_by_stmt(visited))
        node.body = new_body
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        self._push({node.name})
        self.generic_visit(node)
        self._pop()
        self._bind({node.name})
        return node

    def visit_For(self, node: ast.For) -> ast.AST:
        node.iter = self.visit(node.iter)
        node.target = self.visit(node.target)
        loop_names = set()
        for n in ast.walk(node.target):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                loop_names.add(n.id)
        self._push(loop_names)
        node.body = self._insert_into([self.visit(s) for s in node.body])
        self._pop()
        node.orelse = self._insert_into([self.visit(s) for s in node.orelse])
        return node

    def visit_While(self, node: ast.While) -> ast.AST:
        node.test = self.visit(node.test)
        self._push()
        node.body = self._insert_into([self.visit(s) for s in node.body])
        self._pop()
        node.orelse = self._insert_into([self.visit(s) for s in node.orelse])
        return node

    def visit_If(self, node: ast.If) -> ast.AST:
        node.test = self.visit(node.test)
        self._push()
        node.body = self._insert_into([self.visit(s) for s in node.body])
        self._pop()
        self._push()
        node.orelse = self._insert_into([self.visit(s) for s in node.orelse])
        self._pop()
        return node

    def visit_With(self, node: ast.With) -> ast.AST:
        for item in node.items:
            item.context_expr = self.visit(item.context_expr)
            if item.optional_vars:
                item.optional_vars = self.visit(item.optional_vars)
        bound = set()
        for item in node.items:
            if item.optional_vars:
                for n in ast.walk(item.optional_vars):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                        bound.add(n.id)
        self._push(bound)
        node.body = self._insert_into([self.visit(s) for s in node.body])
        self._pop()
        return node

    def visit_Try(self, node: ast.Try) -> ast.AST:
        self._push()
        node.body = self._insert_into([self.visit(s) for s in node.body])
        self._pop()
        for h in node.handlers:
            extra = {h.name} if h.name else set()
            self._push(extra)
            if h.type:
                h.type = self.visit(h.type)
            h.body = self._insert_into([self.visit(s) for s in h.body])
            self._pop()
        self._push()
        node.orelse = self._insert_into([self.visit(s) for s in node.orelse])
        self._pop()
        self._push()
        node.finalbody = self._insert_into([self.visit(s) for s in node.finalbody])
        self._pop()
        return node

insertjunk = InsertJunk


def insertafter(module_body: list[ast.stmt], new_stmts: list[ast.stmt]) -> list[ast.stmt]:
    idx = 0
    n = len(module_body)

    if (
        n > idx
        and isinstance(module_body[idx], ast.Expr)
        and isinstance(module_body[idx].value, ast.Constant)
        and isinstance(module_body[idx].value.value, str)
    ):
        idx += 1

    while (
        idx < n
        and isinstance(module_body[idx], ast.ImportFrom)
        and module_body[idx].module == "__future__"
    ):
        idx += 1

    return module_body[:idx] + new_stmts + module_body[idx:]


def all_middle_permutations(cfg: ObfConfig) -> list[tuple[str, ...]]:
    ops = cfg.middle_ops()
    if not ops:
        return [tuple()]
    return [tuple(p) for p in itertools.permutations(ops)]

def obfsource(source_code: str, cfg: Optional[ObfConfig] = None, junk_probability: Optional[float] = None) -> str:
    if cfg is None:
        cfg = ObfConfig()
    if junk_probability is not None:
        cfg.junk_frequency = int(round(max(0.0, min(1.0, junk_probability)) * 10))

    tree = ast.parse(source_code)
    existing = collectexisting(tree)
    name_gen = NameGen(existing, cfg.name_length_min, cfg.name_length_max)

    # Rename
    if cfg.rename:
        renamable_funcs = collectrenemablefuncs(tree)
        renamable_vars = collectrenemablevars(tree)
        renamable = renamable_funcs | renamable_vars
        name_map = {old: name_gen.new_name() for old in renamable}
        tree = renameidents(name_map, attr_names=renamable_funcs).visit(tree)
        ast.fix_missing_locations(tree)

    # Hide imports
    if cfg.hide_imports:
        tree = HideImports().visit(tree)
        ast.fix_missing_locations(tree)

    # Value calculation obfuscation
    if cfg.value_calc:
        tree = ObfuscateValues().visit(tree)
        ast.fix_missing_locations(tree)

    # String encryption
    decoder_names: dict[tuple[str, ...], str] = {}
    env_func_name: Optional[str] = None
    used_pipelines: set[tuple[str, ...]] = set()

    if cfg.encrypt_strings:
        for perm in all_middle_permutations(cfg):
            decoder_names[perm] = name_gen.new_name()
        if cfg.use_env_key:
            env_func_name = name_gen.new_name()

        encryptor = StringEncryptor(cfg, name_gen, decoder_names, env_func_name)
        tree = encryptor.visit(tree)
        used_pipelines = set(encryptor.used_pipelines)
        if not used_pipelines and decoder_names:
            used_pipelines = {next(iter(decoder_names))}
        ast.fix_missing_locations(tree)

    # Junk insertion
    if cfg.junk_frequency > 0:
        tree = InsertJunk(name_gen, probability=cfg.junk_probability()).visit(tree)
        ast.fix_missing_locations(tree)

    # Inject helpers
    helper_stmts: list[ast.stmt] = []
    if cfg.encrypt_strings:
        if cfg.use_env_key and env_func_name:
            helper_stmts.append(build_env_key_func(env_func_name, cfg.env_key_path))

        helper_names: dict[str, str] = {}
        pipelines_to_emit = used_pipelines or {tuple(cfg.middle_ops())}
        for pipeline in sorted(pipelines_to_emit, key=lambda p: decoder_names.get(p, "")):
            fname = decoder_names.get(pipeline) or name_gen.new_name()
            helper_stmts.append(
                build_decoder_func(fname, pipeline, cfg, env_func_name, helper_names)
            )

        if helper_stmts:
            tree.body = insertafter(tree.body, helper_stmts)

    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def resolve_output_path(target: str, output_arg: Optional[str], cfg: ObfConfig) -> str:
    if output_arg:
        return output_arg
    if cfg.output_filename:
        out = cfg.output_filename
        if not os.path.isabs(out):
            base_dir = os.path.dirname(os.path.abspath(target)) or "."
            return os.path.join(base_dir, out)
        return out
    if target.endswith(".py"):
        return target[: -len(".py")] + "_obf.py"
    return target + "_obf.py"


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Obfuscate Python scripts: rename, multi-stage string encryption, "
            "getattr import hiding, value wrapping, and opaque junk code."
        )
    )
    parser.add_argument("target", help="Target .py file to obfuscate")
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help="Output file (overrides pyobf.ini output.filename)",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_INI,
        help=f"Path to config file (Default: {DEFAULT_INI})",
    )
    parser.add_argument(
        "--junk-frequency",
        type=int,
        default=None,
        help="Junk insertion frequency 0-10 (overrides config)",
    )
    parser.add_argument(
        "--junk-probability",
        type=float,
        default=None,
        help="Deprecated: junk probability 0.0-1.0 (converted to frequency)",
    )
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument("--no-env-key", action="store_true", help="Disable environment-dependent keys")
    parser.add_argument("--no-hide-imports", action="store_true", help="Disable import hiding")
    parser.add_argument("--no-value-calc", action="store_true", help="Disable value calculation obfuscation")
    parser.add_argument("--no-rename", action="store_true", help="Disable identifier renaming")
    parser.add_argument("--no-strings", action="store_true", help="Disable string encryption")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)

    if args.seed is not None:
        cfg.seed = args.seed
    if cfg.seed is not None:
        random.seed(cfg.seed)

    if args.junk_frequency is not None:
        cfg.junk_frequency = max(0, min(10, args.junk_frequency))
    elif args.junk_probability is not None:
        cfg.junk_frequency = int(round(max(0.0, min(1.0, args.junk_probability)) * 10))

    if args.no_env_key:
        cfg.use_env_key = False
    if args.no_hide_imports:
        cfg.hide_imports = False
    if args.no_value_calc:
        cfg.value_calc = False
    if args.no_rename:
        cfg.rename = False
    if args.no_strings:
        cfg.encrypt_strings = False

    if not args.target.endswith(".py"):
        print(f"Warning: '{args.target}' is not a .py file. Continuing anyway.", file=sys.stderr)

    try:
        with open(args.target, "r", encoding="utf-8") as f:
            source_code = f.read()
    except OSError as e:
        print(f"Error: Failed to read file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        obfuscated = obfsource(source_code, cfg=cfg)
    except SyntaxError as e:
        print(f"Error: Failed to parse target file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Obfuscation failed: {e}", file=sys.stderr)
        raise

    output_path = resolve_output_path(args.target, args.output, cfg)

    header = (
        "# Format: UTF-8\n"
        "# Automatically obfuscated by PyObf (https://github.com/Konayukiw/PyObf).\n"
        "# Original file: {}\n\n"
    ).format(args.target)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write(obfuscated)
            f.write("\n")
    except OSError as e:
        print(f"Error: Failed to write output: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Obfuscation completed: {output_path}")


if __name__ == "__main__":
    main()
