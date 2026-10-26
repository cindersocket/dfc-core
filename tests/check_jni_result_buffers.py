"""Keep bounded JNI result decoding to one native scratch allocation."""

import re
from pathlib import Path

SOURCE = Path(__file__).parents[1] / "bindings" / "jni" / "dfc_jni.c"


def decode_list_body(source: str) -> str:
    match = re.search(
        r"static jbyteArray decode_list\(.*?\n}\n",
        source,
        re.DOTALL,
    )
    if match is None:
        raise ValueError("missing decode_list")
    return match.group()


def problems(source: str) -> list[str]:
    try:
        body = decode_list_body(source)
    except ValueError as error:
        return [str(error)]

    failures: list[str] = []
    if body.count("copy_array(") != 1:
        failures.append("decode_list must make exactly one native input copy")
    if re.search(r"\bmalloc\s*\(", body):
        failures.append("decode_list allocates a second native result buffer")
    if not re.search(
        r"decoder\(\s*response_bytes,\s*response_len,\s*response_bytes,\s*response_len,",
        body,
        re.DOTALL,
    ):
        failures.append("decode_list does not decode in place")
    if body.count("secure_free(response_bytes, response_len);") != 3:
        failures.append("decode_list does not wipe its scratch on every exit")
    if "if(output_len > response_len)" not in body:
        failures.append("decode_list does not reject an expanding decoder result")
    return failures


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    failures = problems(source)
    mutants = (
        source.replace(
            "decoder(response_bytes, response_len, response_bytes, response_len,",
            "decoder(response_bytes, response_len, NULL, 0,",
            1,
        ),
        source.replace("if(output_len > response_len)", "if(false)", 1),
        source.replace("secure_free(response_bytes, response_len);", "", 1),
    )
    if any(not problems(mutant) for mutant in mutants):
        failures.append("JNI result-buffer policy failed its mutation self-test")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
