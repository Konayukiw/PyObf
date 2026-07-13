# PyObf

AST-based tool for obfuscating Python scripts.

## Features

1. **Identifier renaming** — functions, variables, and parameters become random alphabetic names (length configurable).
2. **Multi-stage string encryption** — per-string keys; pipeline: XOR → (Swap / Rotate / Byte Shuffle in random order) → Base85. Optional environment-dependent key material (e.g. `C:/Users/` creation time in millis).
3. **Multiple decoders** — each middle-op order gets its own decode function; keys at call sites are wrapped in arithmetic.
4. **Import hiding** — `import` / `from ... import` rewritten via `getattr` / `__import__`.
5. **Value wrapping** — numeric literals wrapped in trivial calculations.
6. **Opaque junk** — inserts side-effect-free code that references real in-scope names (does not alter program behavior).
7. **`pyobf.ini`** — strength and feature toggles.

## Usage

```text
python obfuscate.py <input.py>
python obfuscate.py <input.py> <output.py>
python obfuscate.py <input.py> -c pyobf.ini --junk-frequency 8 --seed 1
```

### Arguments Options

| Option | Description |
|--------|-------------|
| `-c` / `--config` | Config file path (default: `pyobf.ini`) |
| `--junk-frequency N` | Junk level 0–10 (overrides config) |
| `--seed N` | RNG seed |
| `--no-env-key` | Disable environment key mixing |
| `--no-hide-imports` | Keep normal import statements |
| `--no-value-calc` | Leave numeric literals plain |
| `--no-rename` | Skip renaming |
| `--no-strings` | Skip string encryption |

## Configuration (`pyobf.ini`)

```ini
[output]
filename =          # Leave this empty to use default: <target>_obf.py

[names]
length = 3          # 3-6

[junk]
frequency = 6       # 0–10

[string]
env_key = true
env_key_path = C:/Users/
xor = true
swap = true
rotate = true
byte_shuffle = true
base85 = true

[obfuscation]
rename = true
hide_imports = true
value_calc = true
encrypt_strings = true
seed =
```

### Environment-dependent keys

When `env_key = true`, each string key is mixed with material derived from the creation time of `env_key_path` (default `C:/Users/`). The same derivation runs at decode time, so the obfuscated script only decrypts correctly in environments where that path’s ctime matches the machine used for obfuscation.

## Notes

- Scope analysis is limited; renaming can break code that relies on dynamic attribute names, `eval`/`exec`, or external APIs sharing names with local functions.
- Relative imports and `from ... import *` are left unchanged when import hiding is on.
- Docstrings and `match` pattern literals are not string-encrypted.
- Always verify behavior after obfuscation.
