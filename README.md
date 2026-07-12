# PyObf
### Obfuscate Python script by renaming functions, inserting junk code, and obfuscating string literals.
=======

# PyObf

Tool for obfuscating Python scripts.

## Features:
1. Replaces function and method names with random 3-character alphabetic strings.
2. Inserts junk code (harmless dummy operations) to complicate the logic.
3. Base64-encodes string literals (using '' or "") and replaces them
with code that decodes themselves at runtime.

## Usage
1. pip install -r requirements.txt
2. python obfuscate.py (input).py
3.  To specify an output file:  
	python obfuscate.py (input).py (output).py 

**Output**
By default, the obfuscated result is saved as "(target)_obf.py".

## Notes
This tool performs simple AST-based obfuscation and does not
conduct rigorous scope analysis (tracking exactly which identifier
refers to which variable or function). Consequently, unintended
replacements may occur and break functionality in cases such as:
- When an external library object has a method or attribute
with the same name as a target for renaming.
- When the code relies on mechanisms that evaluate strings
(e.g., eval, exec, dynamic imports, or string references
in certain type hints).
- Strings used within f-string expressions (inside `{ }`) are
subject to conversion, whereas the literal parts of the
f-string itself are not.
Always verify the script's functionality after obfuscation.
