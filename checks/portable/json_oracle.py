"""Validate an isolated JSON encoder against Python's standard JSON/UTF-8 decoders."""

import json
import random
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: json_oracle.py TEST_EXECUTABLE")
    generator = random.Random(0xC0FFEE)
    pairs = [(bytes([value]), chr(value)) for value in range(256)]
    pairs.extend([
        (b'\xc0\xaf', '\u00c0\u00af'),
        (b'\xed\xa0\x80', '\u00ed\u00a0\u0080'),
        (b'\xf4\x90\x80\x80', '\u00f4\u0090\u0080\u0080'),
        (b'\xe2\x82', '\u00e2\u0082'),
        (b'\xe2\x28\xa1', '\u00e2(\u00a1'),
        (b'', ''),
    ])
    # Unicode scalars near every encoding boundary, plus deterministic full-range sampling.
    points = [0, 0x1F, 0x20, 0x7F, 0x80, 0x7FF, 0x800, 0xD7FF,
              0xE000, 0xFFFF, 0x10000, 0x10FFFF]
    points.extend(generator.randrange(0x110000) for _ in range(5000))
    for point in points:
        if 0xD800 <= point <= 0xDFFF:
            continue
        value = chr(point)
        pairs.append((value.encode('utf-8'), value))
    # Arbitrary malformed byte streams must always produce valid UTF-8 containing one JSON string.
    random_inputs = [bytes(generator.randrange(256) for _ in range(generator.randrange(65)))
                     for _ in range(2000)]
    inputs = [raw for raw, _ in pairs] + random_inputs
    payload = ''.join(raw.hex() + '\n' for raw in inputs).encode('ascii')
    result = subprocess.run([sys.argv[1], '--encode-lines'], input=payload,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    if result.stderr:
        raise AssertionError("unexpected encoder diagnostic output")
    text = result.stdout.decode('utf-8', errors='strict')
    if not text.endswith('\n'):
        raise AssertionError("missing final record terminator")
    output = text[:-1].split('\n')
    if len(output) != len(inputs):
        raise AssertionError("encoder emitted an unexpected record count")
    for index, line in enumerate(output):
        value = json.loads(line)
        if not isinstance(value, str):
            raise AssertionError("encoder output is not a JSON string")
        if index < len(pairs) and value != pairs[index][1]:
            raise AssertionError("JSON roundtrip mismatch for synthetic case " + str(index))
    print("PASS:", len(pairs), "exact JSON roundtrips and", len(random_inputs), "arbitrary byte-stream validity cases")


if __name__ == '__main__':
    main()
