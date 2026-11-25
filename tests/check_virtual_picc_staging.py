#!/usr/bin/env python3
"""Keep ownership of virtual PICC transport state in the code that bounds it.

Three classes of defect have reached review in the ISO-DEP path:

* a copy into the fixed retry buffer that nothing bounded;
* a card block number assigned from the wrong source;
* a command pointer read after the exchange had freed the buffer it pointed at.

Each came from state that any function could touch. This check makes the safe
shape the only shape that builds.

What this is, and is not. It is a lint over C source text, run on every build,
that stops accidental and careless regressions and makes deliberate ones show up
in review. It is not a proof: C has too many ways to reach memory for a text
check to close them all, and a determined author can always find a spelling it
misses. The real protection is the layers behind it: AddressSan and UBSan, the
property test (tests/test_dfc_iso_dep_frame_properties.c) and the regression
tests. So the lint fails closed wherever it can: code it cannot parse is an
error, never something it quietly skips.

It works on statements, not lines. Line splices, digraphs, `#if 0` regions,
comments and string/char literals are removed first (keeping offsets), so the
spellings people reach for first (a split line, compound assignment, increment,
address-of, a pointer alias, a cast that drops const) are all caught.

Rules for src/dfc_virtual_picc.c (other source files may not mention the
protected fields at all, and headers may not define macros that name them):

1. The `pending-command staging` section may contain only the functions listed
   in STAGING_FUNCTIONS. Outside it, the retry array `pending_command` may only
   be named inside sizeof(), and `pending_command_len` may be read but never
   assigned, incremented or have its address taken. The accessor
   `pending_command_data()` may not be cast to a writable pointer, and
   `offsetof` may not be used on the session.
2. Writes to the emulator's command-chain buffer or its length, aliases of it,
   and calls that allocate, free, copy into or wipe it, may only appear in the
   staging section or in the functions listed in CHAIN_WRITERS.
3. The card block number `picc_sequence` may only change by exactly
   `^= DFC_ISO_DEP_SEQUENCE_BIT` inside a transmitter, or `= 0` inside an
   activation reset, and the statement must be exactly that, with no comma
   expression around it. Taking its address is never allowed. A copy into the
   session through an address-of destination is refused.
4. Nothing that runs after the exchange may be handed the command bytes, because
   they can live in a buffer the exchange frees: `finalize_...` may not be passed
   `inf`, `command` or `frame`, the SDM facts must be captured before the
   exchange, `inf` may not be used after it in the frame function, and `inf` may
   not be copied into another variable.
5. Unbalanced braces, an unparseable function, or statements outside any known
   function are errors.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE_DIR = REPO / "src"
# Where C code that could reach the session struct lives.
SCAN_ROOTS = [d for d in (SOURCE_DIR, REPO / "port", REPO / "ffi", REPO / "examples") if d.is_dir()]
PICC = "dfc_virtual_picc.c"
PICC_HEADER = "dfc_virtual_picc.h"
BEGIN = "// BEGIN pending-command staging"
END = "// END pending-command staging"

STAGING_FUNCTIONS = {
    "truncate_pending_command",
    "pending_command_data",
    "pending_command_is_valid",
    "stage_pending_command",
    "command_can_use_large_iso_dep_storage",
    "reassemble_pending_command",
    "discard_pending_command",
}
# Native-command machinery that legitimately borrows the chain buffer for a
# wrapped command larger than the scratch area. It frees what it borrows.
CHAIN_WRITERS = {"handle_native_exchange_inner", "virtual_picc_iso_dep_exchange"}
TRANSMITTERS = {
    "build_iso_dep_i_block",
    "build_iso_dep_r_ack_advancing",
    "build_iso_dep_empty_i_block",
    "write_next_iso_dep_response_block",
}
RESETTERS = {"dfc_virtual_picc_iso_dep_frame_exchange", "clear_protocol"}
# Only the allocator may overwrite the whole struct, and only because the memory
# is brand new (nothing is staged in it yet).
SESSION_INITIALISERS = {"dfc_virtual_picc_session_alloc"}
FRAME_FUNCTION = "dfc_virtual_picc_iso_dep_frame_exchange"
COMMAND_NAMES = ("inf", "inf_len", "command", "command_len", "frame", "frame_len")
PROTECTED = r"pending_command\w*|picc_sequence|command_chain\w*"

WRITE = r"(?:=(?!=)|[-+*/%&|^]=|<<=|>>=|\+\+|--)"
PATH = r"[\w>.\-*()\s]*"
MEMORY_CALL = re.compile(
    r"\b(?:memcpy|memmove|memset|dfc_secure_wipe|dfc_platform_alloc|dfc_platform_free|"
    r"dfc_emulator_discard_command_chain)\b"
)
ADDRESS_OF = r"(?<!&)&(?!&)\s*"


class Source:
    """Source text with its removable parts blanked and a map back to line numbers."""

    def __init__(self, text: str) -> None:
        self.original = text
        spliced, origin = self._splice(text)
        spliced = self._digraphs(spliced)
        spliced = self._strip_if0(spliced)
        self.code = self._blank(spliced)
        self.origin = origin

    @staticmethod
    def _splice(text: str) -> tuple[str, list[int]]:
        out, origin, i = [], [], 0
        while i < len(text):
            if text[i] == "\\" and text[i + 1 : i + 2] == "\n":
                i += 2
                continue
            out.append(text[i])
            origin.append(i)
            i += 1
        return "".join(out), origin

    @staticmethod
    def _digraphs(text: str) -> str:
        for digraph, plain in (
            ("<%", "{ "),
            ("%>", "} "),
            ("<:", "[ "),
            (":>", "] "),
            ("%:", "# "),
        ):
            text = text.replace(digraph, plain)
        return text

    @staticmethod
    def _strip_if0(text: str) -> str:
        """Blank the dead part of `#if 0` (up to its #else or #endif, nesting aware).

        Dead text may hold unbalanced braces or apostrophes that would confuse the
        parse, and live code after it must still be seen.
        """
        lines = text.split("\n")
        depth = 0
        dead_start = None
        dead_depth = 0
        for index, line in enumerate(lines):
            directive = re.match(r"\s*#\s*(\w+)\s*(.*)", line)
            if not directive:
                continue
            word, rest = directive.groups()
            if word in ("if", "ifdef", "ifndef"):
                if dead_start is None and word == "if" and rest.split("//")[0].strip() == "0":
                    dead_start, dead_depth = index, depth
                depth += 1
            elif word in ("else", "elif") and dead_start is not None and depth - 1 == dead_depth:
                for k in range(dead_start, index + 1):
                    lines[k] = " " * len(lines[k])
                dead_start = None
            elif word == "endif":
                depth -= 1
                if dead_start is not None and depth == dead_depth:
                    for k in range(dead_start, index + 1):
                        lines[k] = " " * len(lines[k])
                    dead_start = None
        return "\n".join(lines)

    @staticmethod
    def _blank(text: str) -> str:
        out = list(text)
        i, n = 0, len(text)
        while i < n:
            two = text[i : i + 2]
            if two == "//":
                j = text.find("\n", i)
                j = n if j < 0 else j
                out[i:j] = " " * (j - i)
                i = j
            elif two == "/*":
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
                for k in range(i, j):
                    if text[k] != "\n":
                        out[k] = " "
                i = j
            elif text[i] in "\"'":
                quote, j = text[i], i + 1
                while j < n and text[j] != quote and text[j] != "\n":
                    j += 2 if text[j] == "\\" else 1
                for k in range(i + 1, min(j, n)):
                    out[k] = " "
                i = j + 1
            else:
                i += 1
        return "".join(out)

    def line_of(self, position: int) -> int:
        position = min(position, len(self.origin) - 1)
        return self.original.count("\n", 0, self.origin[position]) + 1


def functions(code: str) -> tuple[list[tuple[str, int, int]], list[int]]:
    """(name, start, end) of each top-level function, and the starts of braces left open."""
    found: list[list] = []
    depth, start, i, n = 0, 0, 0, len(code)
    while i < n:
        ch = code[i]
        if ch == "{":
            if depth == 0:
                header = code[start:i]
                names = re.findall(r"\b([A-Za-z_]\w*)\s*\(", header)
                if names and "=" not in header.split("(")[0]:
                    found.append([names[0], i, None])
                else:
                    found.append([None, i, None])
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                if found and found[-1][2] is None:
                    found[-1][2] = i
                start = i + 1
            depth = max(depth, 0)
        elif ch == ";" and depth == 0:
            start = i + 1
        elif ch == "#" and depth == 0 and (i == 0 or code[i - 1] == "\n"):
            j = code.find("\n", i)
            start = n if j < 0 else j
            i = start
            continue
        i += 1
    unclosed = [f[1] for f in found if f[2] is None]
    return [(f[0], f[1], f[2]) for f in found if f[0] is not None and f[2] is not None], unclosed


def statements(code: str) -> list[tuple[int, str, str]]:
    """(offset, text, terminator) for each statement; a `{` terminator marks a header."""
    out, begin = [], 0
    for index, ch in enumerate(code):
        if ch in ";{}":
            text = " ".join(code[begin:index].split())
            if text:
                out.append((begin, text, ch))
            begin = index + 1
    return out


def lint_picc(text: str) -> list[str]:
    errors: list[str] = []
    if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) > text.index(END):
        return [f"{PICC}: the staging section markers must appear exactly once, in order"]
    # A constant-false conditional (`#if 0`, `#if (0)`, `#if 1-1`...) is a place to
    # hide code from this lint, and a comment can open one too (the text between
    # a fake `#if 0` and `#endif` inside comments would be blanked as dead). The
    # guarded file has no use for dead blocks, so any constant condition is an error.
    # Checked on the raw text, so nothing can hide it.
    for constant in re.finditer(
        r"^[ \t]*[#%][ \t]*:?[ \t]*if[ \t]+[0-9uUlL \t()+\-*|&!~]*(?://.*)?$", text, re.MULTILINE
    ):
        line = text.count("\n", 0, constant.start()) + 1
        errors.append(f"{PICC}:{line}: a constant `#if` is not allowed in this file")
    source = Source(text)
    code = source.code
    # The markers are comments, so find the section in the original text and map
    # it onto the spliced offsets (they only differ where a line was spliced).
    marker_begin, marker_end = text.index(BEGIN), text.index(END)
    section = (
        next((i for i, o in enumerate(source.origin) if o >= marker_begin), 0),
        next((i for i, o in enumerate(source.origin) if o >= marker_end), len(code)),
    )

    def where(position: int, name: str) -> str:
        return f"{PICC}:{source.line_of(position)}: in {name}"

    for define in re.finditer(r"^[ \t]*#[ \t]*define[^\n]*", code, re.MULTILINE):
        if re.search(PROTECTED, define.group()):
            errors.append(
                f"{where(define.start(), '<macro>')}: a macro may not name a protected field"
            )

    # Ways to reach a protected field without writing its name or the variable
    # `session`: pasting tokens together in a macro, giving the session another
    # name, or casting it to another pointer type. Every session pointer in this
    # file is called `session`, so any other spelling is an alias to refuse.
    if "##" in code:
        errors.append(f"{PICC}: token pasting (##) is not allowed in this file")
    for declared in re.finditer(
        r"\bDfcVirtualPiccSession\s*\*\s*(?:const\s+)?(\w+)\s*([=;,)\[(])", code
    ):
        if declared.group(1) != "session" and declared.group(2) != "(":
            errors.append(
                f"{where(declared.start(), '<declaration>')}: the session pointer may only be "
                f"called `session` (found `{declared.group(1)}`)"
            )
    for cast in re.finditer(r"\(\s*[A-Za-z_][\w\s]*\*\s*(?:const\s*)?\)\s*session\b", code):
        errors.append(
            f"{where(cast.start(), '<cast>')}: the session may not be cast to another type"
        )

    parsed, unclosed = functions(code)
    for position in unclosed:
        errors.append(f"{where(position, '<file>')}: a brace is never closed (unparseable)")
    spans = [(name, start, end) for name, start, end in parsed]

    def owner(position: int) -> str:
        for name, start, end in spans:
            if start <= position <= end:
                return name
        return "<unknown>"

    for name, start, end in spans:
        if section[0] <= start <= section[1] and name not in STAGING_FUNCTIONS:
            errors.append(
                f"{where(start, name)}: inside the staging section but not one of its functions"
            )

    frame_exchange_call = None
    for position, statement, terminator in statements(code):
        name = owner(position)
        inside = section[0] <= position <= section[1]
        here = where(position, name)
        # A function header (ends in `{`) is not a statement; it may legitimately
        # contain a protected word in the function's own name.
        if name == "<unknown>" and terminator == ";" and re.search(PROTECTED, statement):
            errors.append(f"{here}: protected field named outside any parsed function")
        if not inside:
            for token in re.finditer(
                r"(?:->|\.)\s*pending_command\b|offsetof\s*\([^)]*\bpending_command\b", statement
            ):
                if not re.search(r"sizeof\s*\(\s*" + PATH + r"$", statement[: token.end()]):
                    errors.append(f"{here}: raw access to pending_command")
            if re.search(r"\boffsetof\s*\(", statement) and re.search(PROTECTED, statement):
                errors.append(f"{here}: offsetof on a protected field")
            if (
                # any cast applied directly to the accessor's result, whatever the type
                re.search(r"\)\s*pending_command_data\b", statement)
                # laundering the pointer through an integer, or into a non-const variable
                or (
                    "pending_command_data" in statement
                    and re.search(r"\buintptr_t\b|\bintptr_t\b", statement)
                )
                or re.search(
                    r"^(?![^=]*\bconst\b)[^=]*\*\s*\w+\s*=\s*pending_command_data\b",
                    statement,
                )
            ):
                errors.append(f"{here}: pending_command_data() result cast to a writable pointer")
            if (
                re.search(rf"\bpending_command_len\b\s*{WRITE}", statement)
                or re.search(rf"(?:\+\+|--)\s*{PATH}\bpending_command_len\b", statement)
                or re.search(ADDRESS_OF + PATH + r"\bpending_command_len\b", statement)
            ):
                errors.append(f"{here}: pending_command_len is written")
            overwrites_session = re.search(
                r"\b(?:memcpy|memmove|memset)\s*\(\s*(?:\(\s*[\w\s]*\*\s*\)\s*)?\*?\s*"
                r"(?:session|s)\s*[,)]",
                statement,
            ) or re.search(r"(?<![\w>.])\*\s*(?:session|s)\s*=(?!=)", statement)
            if overwrites_session and name not in SESSION_INITIALISERS:
                errors.append(f"{here}: the whole session struct is overwritten")
            if re.search(r"\b(?:memcpy|memmove|memset)\s*\(\s*&", statement):
                errors.append(f"{here}: copy into the address of a struct member")
        if not inside and name not in CHAIN_WRITERS and "command_chain" in statement:
            written = (
                re.search(rf"\bcommand_chain\w*\b\s*{WRITE}", statement)
                or re.search(rf"(?:\+\+|--)\s*{PATH}\bcommand_chain\w*\b", statement)
                or re.search(ADDRESS_OF + PATH + r"\bcommand_chain\w*\b", statement)
                # an alias: the chain pointer read into another variable
                or re.search(r"=\s*" + PATH + r"\bcommand_chain\b(?!_)", statement)
            )
            if written or MEMORY_CALL.search(statement):
                errors.append(f"{here}: command-chain buffer written or aliased outside its owners")
        if "picc_sequence" in statement:
            if re.search(ADDRESS_OF + PATH + r"\bpicc_sequence\b", statement):
                errors.append(f"{here}: address of picc_sequence taken")
            elif re.search(rf"\bpicc_sequence\b\s*{WRITE}", statement) or re.search(
                rf"(?:\+\+|--)\s*{PATH}\bpicc_sequence\b", statement
            ):
                toggle = re.fullmatch(
                    r"(?:\w+\s*->\s*)picc_sequence\s*\^=\s*DFC_ISO_DEP_SEQUENCE_BIT", statement
                )
                reset = re.fullmatch(r"(?:\w+\s*->\s*)picc_sequence\s*=\s*0", statement)
                if not ((toggle and name in TRANSMITTERS) or (reset and name in RESETTERS)):
                    errors.append(
                        f"{here}: picc_sequence may only be toggled by a transmitter "
                        "or reset to 0 at activation, as the whole statement"
                    )
        if "finalize_standard_iso_sdm_boundary" in statement:
            arguments = statement.split("finalize_standard_iso_sdm_boundary", 1)[1]
            if any(re.search(rf"\b{n}\b", arguments) for n in COMMAND_NAMES):
                errors.append(f"{here}: command bytes passed to the SDM boundary")
        if name == FRAME_FUNCTION:
            if re.search(r"=\s*(?:inf|inf_len)\s*$", statement):
                errors.append(f"{here}: the command bytes are copied into another variable")
            if re.search(r"\bvirtual_picc_iso_dep_exchange\s*\(\s*session\s*,\s*inf\b", statement):
                frame_exchange_call = position
                if "capture_sdm_boundary_facts" not in code[:position][-4000:]:
                    errors.append(f"{here}: SDM facts must be captured before the exchange")
            elif frame_exchange_call is not None and re.search(r"\b(?:inf|inf_len)\b", statement):
                errors.append(f"{here}: inf is used after the exchange that may free it")
    if frame_exchange_call is None:
        errors.append(f"{PICC}: could not find the frame function's exchange call")
    return errors


COMMANDS = "dfc_emulator_commands.c"
HANDLER = "dfc_emulator_handle_command"


def lint_commands(text: str) -> list[str]:
    """The command handler may not read its command buffer after dispatching.

    A handler can end the session (a failed integrity check) and that frees the
    command-chain buffer the command may live in, so anything still needed from
    the command must be copied out before the dispatch.
    """
    code = Source(text).code
    header = re.search(rf"\b{HANDLER}\s*\([^;{{]*\)\s*\{{", code)
    if not header:
        return [f"{COMMANDS}: could not find {HANDLER}"]
    depth, end = 1, header.end()
    while end < len(code) and depth:
        depth += {"{": 1, "}": -1}.get(code[end], 0)
        end += 1
    body = code[header.end() : end]
    dispatch = re.search(r"\bdispatch_native_command\s*\(\s*emulator\s*,\s*buffer\b", body)
    if not dispatch:
        return [f"{COMMANDS}: could not find the dispatch call in {HANDLER}"]
    after = body[dispatch.end() :]
    errors = []
    # Any mention of the bare identifier `buffer` after the dispatch, however it is
    # spelled or passed (an alias, a later call argument, a cast); `buffer_len` and
    # the like are different identifiers and are not matched.
    for use in re.finditer(r"\bbuffer\b", after):
        line = code[: header.end() + dispatch.end() + use.start()].count("\n") + 1
        errors.append(f"{COMMANDS}:{line}: the command buffer is read after the dispatch")
    return errors


def lint_other(name: str, text: str, header: bool = False) -> list[str]:
    code = Source(text).code
    problems = [
        f"{name}: mentions {token}, which only {PICC} may touch"
        for token in ("pending_command", "picc_sequence")
        if re.search(rf"\b{token}\w*\b", code) and not header
    ]
    # Token pasting can build a protected field name out of pieces, so a paste
    # that touches a fragment of one is refused wherever it is.
    for paste in re.finditer(r"[^\n]*##[^\n]*", code):
        if re.search(r"pending|picc_|command_chain|_sequence", paste.group()):
            problems.append(f"{name}: token pasting that could build a protected field name")
    if header:
        # The session struct declares the fields; nothing else may name them.
        for define in re.finditer(r"^[ \t]*#[ \t]*define[^\n]*", code, re.MULTILINE):
            if re.search(PROTECTED, define.group()):
                problems.append(f"{name}: a macro names a protected field")
        for opening in re.finditer(r"\)\s*\{", code):
            depth, end = 1, opening.end()
            while end < len(code) and depth:
                depth += {"{": 1, "}": -1}.get(code[end], 0)
                end += 1
            # an unbalanced body is checked up to the end of the text
            if re.search(PROTECTED, code[opening.end() : end]):
                problems.append(f"{name}: a function body names a protected field")
    return problems


def main() -> int:
    errors = lint_picc((SOURCE_DIR / PICC).read_text())
    errors += lint_commands((SOURCE_DIR / COMMANDS).read_text())
    # Every C source, header and include file anywhere under src/, and the
    # other source trees: an include file or a subdirectory is not exempt.
    seen = 0
    for root in SCAN_ROOTS:
        for path in sorted(p for p in root.rglob("*") if p.suffix in (".c", ".h", ".inc")):
            if path == SOURCE_DIR / PICC:
                continue
            seen += 1
            errors += lint_other(
                str(path.relative_to(REPO)), path.read_text(), header=(path.name == PICC_HEADER)
            )
    if seen == 0:
        errors.append("no source files found to scan")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("virtual PICC staging and block-number ownership hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
