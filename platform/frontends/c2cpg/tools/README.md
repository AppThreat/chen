# c2cpg tools

Scripts that regenerate data files c2cpg ships in `src/main/resources`. Run them from this module's
directory; each writes its file in place and records its provenance in the file's header.

| Script | Writes | Source |
|---|---|---|
| `predefined-macros/generate.sh` | `predefined-macros/*.txt` | The macros real compilers predefine: GCC (the official `gcc` Docker image) and Clang for each target, and MSVC as Clang predefines it in MSVC compatibility mode. Used when a translation unit's compiler cannot be run. |
| `builtins/generate.py <edg-tree>` | `builtin-functions.txt` | The GCC and Clang builtin signatures in the EDG C/C++ front end's `src/builtin_defs.h`. |

The predefined macro tables use the format of the EDG front end's `predefined_macros.txt`. The
builtin signatures are derived from the EDG C/C++ front end (https://edgcpp.org), licensed under
the Apache License v2.0 with LLVM Exceptions (https://edgcpp.org/LICENSE.txt).
