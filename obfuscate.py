import argparse
import ast
import base64
import builtins
import keyword
import random
import string
import sys

class namegen:

    def __init__(self, existing_names, length=3):
        self.length = length
        reserved = set(keyword.kwlist) | set(dir(builtins))
        self.used = set(existing_names) | reserved

    def new_name(self):
        while True:
            name = "".join(random.choice(string.ascii_letters) for _ in range(self.length))
            if name not in self.used:
                self.used.add(name)
                return name

def collectexisting(tree):
    names = set()
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

def isdunder(name):
    return name.startswith("__") and name.endswith("__")

def collectimported(tree):
    names = set()
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

def collectrenemablefuncs(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not isdunder(node.name):
                names.add(node.name)
    return names

def collectrenemablevars(tree):
    names = set()
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

def collectrenemable(tree):
    return collectrenemablefuncs(tree)


class renameidents(ast.NodeTransformer):
    def __init__(self, name_map, attr_names=None):
        self.name_map = name_map
        self.attr_names = attr_names if attr_names is not None else set(name_map)

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Name(self, node):
        if node.id in self.name_map:
            node.id = self.name_map[node.id]
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if node.attr in self.attr_names and node.attr in self.name_map:
            node.attr = self.name_map[node.attr]
        return node

    def visit_arg(self, node):
        if node.arg in self.name_map:
            node.arg = self.name_map[node.arg]
        if node.annotation is not None:
            node.annotation = self.visit(node.annotation)
        return node

    def visit_Call(self, node):
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
            new_keywords.append(
                ast.keyword(arg=arg, value=self.visit(kw.value))
            )
        node.keywords = new_keywords
        return node

    def visit_ExceptHandler(self, node):
        self.generic_visit(node)
        if node.name is not None and node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    def visit_Global(self, node):
        node.names = [self.name_map.get(n, n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self.name_map.get(n, n) for n in node.names]
        return node

    def visit_MatchAs(self, node):
        self.generic_visit(node)
        if node.name is not None and node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    def visit_MatchStar(self, node):
        self.generic_visit(node)
        if node.name is not None and node.name in self.name_map:
            node.name = self.name_map[node.name]
        return node

    def visit_MatchMapping(self, node):
        self.generic_visit(node)
        if node.rest is not None and node.rest in self.name_map:
            node.rest = self.name_map[node.rest]
        return node

renamefunc = renameidents


class insertjunk(ast.NodeTransformer):
    def __init__(self, name_gen, probability=0.6):
        self.name_gen = name_gen
        self.probability = probability

    def _dummy_var(self):
        return self.name_gen.new_name()

    def _make_junk_stmt(self):
        var = self._dummy_var()
        kind = random.randint(0, 3)

        if kind == 0:
            stmt = ast.Assign(
                targets=[ast.Name(id=var, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Constant(value=random.randint(1, 999)),
                    op=random.choice([ast.Add(), ast.Sub(), ast.Mult()]),
                    right=ast.Constant(value=random.randint(1, 999)),
                ),
            )
        elif kind == 1:
            n = random.randint(1, 100)
            stmt = ast.If(
                test=ast.Compare(
                    left=ast.Constant(value=n),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=-abs(n) - 1)],
                ),
                body=[ast.Pass()],
                orelse=[],
            )
        elif kind == 2:
            stmt = ast.If(
                test=ast.Compare(
                    left=ast.Constant(value=1),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=1)],
                ),
                body=[
                    ast.Assign(
                        targets=[ast.Name(id=var, ctx=ast.Store())],
                        value=ast.List(
                            elts=[ast.Constant(value=random.randint(0, 9)) for _ in range(3)],
                            ctx=ast.Load(),
                        ),
                    )
                ],
                orelse=[],
            )
        else:
            stmt = ast.For(
                target=ast.Name(id=var, ctx=ast.Store()),
                iter=ast.Call(
                    func=ast.Name(id="range", ctx=ast.Load()),
                    args=[ast.Constant(value=0)],
                    keywords=[],
                ),
                body=[ast.Pass()],
                orelse=[],
            )

        return ast.fix_missing_locations(stmt)

    _TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)

    def _insertjunk(self, body):
        if not body:
            return body
        new_body = []
        for stmt in body:
            if random.random() < self.probability:
                new_body.append(self._make_junk_stmt())
            new_body.append(stmt)
        if not isinstance(body[-1], self._TERMINATORS) and random.random() < self.probability:
            new_body.append(self._make_junk_stmt())
        return new_body

    def _processbody(self, node):
        self.generic_visit(node)
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            doc, rest = body[0], body[1:]
            node.body = [doc] + self._insertjunk(rest)
        else:
            node.body = self._insertjunk(body)
        return node

    def visit_FunctionDef(self, node):
        return self._processbody(node)

    visit_AsyncFunctionDef = visit_FunctionDef

class obfstr(ast.NodeTransformer):
    def __init__(self, decode_func_name):
        self.decode_func_name = decode_func_name
        self._skip_ids = set()

    def _markdocstr(self, node):
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            self._skip_ids.add(id(node.body[0].value))

    def visit_Module(self, node):
        self._markdocstr(node)
        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node):
        self._markdocstr(node)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._markdocstr(node)
        self.generic_visit(node)
        return node

    def _encode_str(self, value, template_node=None):
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        new_node = ast.Call(
            func=ast.Name(id=self.decode_func_name, ctx=ast.Load()),
            args=[ast.Constant(value=encoded)],
            keywords=[],
        )
        if template_node is not None:
            return ast.copy_location(new_node, template_node)
        return new_node

    def _formatted_value_to_str_expr(self, node):
        value = self.visit(node.value)

        if node.conversion == 115:
            value = ast.Call(
                func=ast.Name(id="str", ctx=ast.Load()),
                args=[value],
                keywords=[],
            )
        elif node.conversion == 114:
            value = ast.Call(
                func=ast.Name(id="repr", ctx=ast.Load()),
                args=[value],
                keywords=[],
            )
        elif node.conversion == 97:
            value = ast.Call(
                func=ast.Name(id="ascii", ctx=ast.Load()),
                args=[value],
                keywords=[],
            )

        if node.format_spec is not None:
            spec = self.visit(node.format_spec)
            return ast.Call(
                func=ast.Name(id="format", ctx=ast.Load()),
                args=[value, spec],
                keywords=[],
            )

        if node.conversion in (115, 114, 97):
            return value
        return ast.Call(
            func=ast.Name(id="format", ctx=ast.Load()),
            args=[value],
            keywords=[],
        )

    def visit_JoinedStr(self, node):
        parts = []
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

    def visit_Match(self, node):
        for case in node.cases:
            for sub in ast.walk(case.pattern):
                if isinstance(sub, ast.Constant):
                    self._skip_ids.add(id(sub))
            case.guard = self.visit(case.guard) if case.guard else None
            case.body = [self.visit(s) for s in case.body]
        node.subject = self.visit(node.subject)
        return node

    def visit_Constant(self, node):
        if (
            isinstance(node.value, str)
            and node.value != ""
            and id(node) not in self._skip_ids
        ):
            return self._encode_str(node.value, node)
        return node

def decodehelper(alias_name, decode_func_name):
    import_stmt = ast.Import(names=[ast.alias(name="base64", asname=alias_name)])

    func_def = ast.FunctionDef(
        name=decode_func_name,
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="s", annotation=None)],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        ),
        body=[
            ast.Return(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id=alias_name, ctx=ast.Load()),
                                attr="b64decode",
                                ctx=ast.Load(),
                            ),
                            args=[
                                ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id="s", ctx=ast.Load()),
                                        attr="encode",
                                        ctx=ast.Load(),
                                    ),
                                    args=[ast.Constant(value="ascii")],
                                    keywords=[],
                                )
                            ],
                            keywords=[],
                        ),
                        attr="decode",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value="utf-8")],
                    keywords=[],
                )
            )
        ],
        decorator_list=[],
        returns=None,
    )
    return [import_stmt, func_def]


def insertafter(module_body, new_stmts):
    idx = 0
    n = len(module_body)

    if (
        n > idx
        and isinstance(module_body[idx], ast.Expr)
        and isinstance(module_body[idx].value, ast.Constant)
        and isinstance(module_body[idx].value.value, str)
    ):
        idx += 1

    while idx < n and isinstance(module_body[idx], ast.ImportFrom) and module_body[idx].module == "__future__":
        idx += 1

    return module_body[:idx] + new_stmts + module_body[idx:]


def obfsource(source_code, junk_probability=0.6):
    tree = ast.parse(source_code)

    existing = collectexisting(tree)
    name_gen = namegen(existing)

    renamable_funcs = collectrenemablefuncs(tree)
    renamable_vars = collectrenemablevars(tree)
    renamable = renamable_funcs | renamable_vars
    name_map = {old: name_gen.new_name() for old in renamable}
    tree = renameidents(name_map, attr_names=renamable_funcs).visit(tree)

    alias_name = name_gen.new_name()
    decode_func_name = name_gen.new_name()
    tree = obfstr(decode_func_name).visit(tree)

    tree = insertjunk(name_gen, probability=junk_probability).visit(tree)

    helper_stmts = decodehelper(alias_name, decode_func_name)
    tree.body = insertafter(tree.body, helper_stmts)

    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def main():
    parser = argparse.ArgumentParser(
        description="Obfuscate Python script by renaming functions/variables, inserting junk code, and obfuscating string literals."
    )
    parser.add_argument("target", help="Target .py file to obfuscate")
    parser.add_argument("output", nargs="?", default=None, help="Output file name (default: <target>_obf.py)")
    parser.add_argument(
        "--junk-probability",
        type=float,
        default=0.6,
        help="Probability of inserting junk code before and after each statement (0.0-1.0, default: 0.6)",
    )
    parser.add_argument("--seed", type=int, default=None, help="Random seed (specify to reproduce results)")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if not args.target.endswith(".py"):
        print(f"Warning: '{args.target}' is not a .py file. Continuing anyway.", file=sys.stderr)

    try:
        with open(args.target, "r", encoding="utf-8") as f:
            source_code = f.read()
    except OSError as e:
        print(f"Error: Failed to read file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        obfuscated = obfsource(source_code, junk_probability=args.junk_probability)
    except SyntaxError as e:
        print(f"Error: Failed to parse target file: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = args.output
    else:
        if args.target.endswith(".py"):
            output_path = args.target[: -len(".py")] + "_obf.py"
        else:
            output_path = args.target + "_obf.py"

    header = (
        "# Format: UTF-8\n"
        "# Automatically obfuscated by PyObf (https://github.com/Konayukiw/PyObf).\n"
        "# Original file: {}\n\n"
    ).format(args.target)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(obfuscated)
        f.write("\n")

    print(f"Obfuscation completed: {output_path}")


if __name__ == "__main__":
    main()