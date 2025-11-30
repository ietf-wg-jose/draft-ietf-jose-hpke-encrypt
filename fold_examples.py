#!/usr/bin/env python3
import sys
import re
from pathlib import Path

MAX_WIDTH = 72

HEADER = "   =============== NOTE: '\\' line wrapping per RFC 8792 ================"

BEGIN_RE = re.compile(r'<!--\s*BEGIN-FOLD:(?P<name>[^>]+)\s*-->')
END_RE   = re.compile(r'<!--\s*END-FOLD:(?P<name>[^>]+)\s*-->')


def fold_rfc8792_block(text: str, width: int) -> str:
    """
    Fold a single logical block of text using RFC 8792-style '\' line wrapping.

    - Any line longer than `width` is split into multiple physical lines.
    - All but the last physical line end with a backslash '\'.
    - The logical line is the concatenation of these segments with '\' removed.
    - If any wrapping is performed and the header is not already present as
      the first non-empty line, the RFC 8792 header line is inserted at the top.
    """
    lines = text.splitlines()

    # Find first non-empty line to check for existing header
    first_nonempty_idx = None
    for idx, l in enumerate(lines):
        if l.strip():
            first_nonempty_idx = idx
            break

    has_header = (
        first_nonempty_idx is not None
        and lines[first_nonempty_idx].strip() == HEADER.strip()
    )

    out_lines = []
    wrapped_any = False

    for line in lines:
        # Lines within limit: keep as-is
        if len(line) <= width:
            out_lines.append(line)
            continue

        wrapped_any = True

        # Preserve leading indentation
        indent_len = len(line) - len(line.lstrip(" "))
        indent = line[:indent_len]
        content = line[indent_len:]

        # Reserve one column for '\' on continuation lines
        max_part_len = width - indent_len - 1
        if max_part_len <= 0:
            # Pathological case where indentation alone exceeds width
            out_lines.append(line)
            continue

        while len(content) > max_part_len:
            part = content[:max_part_len]
            content = content[max_part_len:]
            out_lines.append(indent + part + "\\")
        out_lines.append(indent + content)

    # If we wrapped anything and header is not present, add it at top
    if wrapped_any and not has_header:
        # Insert header as the first line of the block, with a blank line after
        # (you can drop the blank line if you prefer)
        return HEADER + "\n\n" + "\n".join(out_lines) + "\n"

    return "\n".join(out_lines) + "\n"


def process_markdown(path: Path):
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    out = []
    i = 0
    changed = False

    while i < len(lines):
        begin_match = BEGIN_RE.search(lines[i])
        if not begin_match:
            out.append(lines[i])
            i += 1
            continue

        block_name = begin_match.group("name").strip()
        out.append(lines[i])  # keep BEGIN-FOLD line
        i += 1

        # Collect block lines until matching END-FOLD
        block_lines = []
        end_found = False

        while i < len(lines):
            end_match = END_RE.search(lines[i])
            if end_match:
                end_name = end_match.group("name").strip()
                if end_name != block_name:
                    print(
                        f"Warning: mismatched END-FOLD name '{end_name}' "
                        f"(expected '{block_name}') in {path}"
                    )
                end_found = True
                break
            block_lines.append(lines[i])
            i += 1

        # Fold the collected block
        original_block = "\n".join(block_lines) + ("\n" if block_lines else "")
        folded_block = fold_rfc8792_block(original_block, MAX_WIDTH)

        if folded_block != original_block:
            changed = True

        # Append folded block lines (without introducing extra markers)
        out.extend(folded_block.rstrip("\n").splitlines())

        # Append END-FOLD line (if present)
        if end_found:
            out.append(lines[i])  # END-FOLD line
            i += 1
        else:
            print(f"Warning: no matching END-FOLD for '{block_name}' in {path}")
            # no END-FOLD line; just continue

    new_text = "\n".join(out) + "\n"
    if changed:
        print(f"Updating (RFC 8792 fold) {path}")
        path.write_text(new_text, encoding="utf-8")
    else:
        print(f"No changes needed for {path}")


def main():
    if len(sys.argv) != 2:
        print("Usage: fold_examples.py <draft-markdown-filename>")
        sys.exit(1)

    md_path = Path(sys.argv[1])
    if not md_path.exists():
        print(f"Error: file not found: {md_path}")
        sys.exit(1)

    process_markdown(md_path)


if __name__ == "__main__":
    main()
