# Portable fragment checks

This directory tests two standalone utility fragments: encoding a byte string as a valid JSON string, and reading a bounded regular file through the same descriptor or handle that was inspected. The fragments contain no application model, command-line application, installer, service, network client or device control logic.

`checks.cpp` exercises UTF-8 boundary conditions and invalid sequences, binary inputs across the read-buffer boundary, exact and excessive file sizes, empty and invalid filenames, Unicode paths, directories and symbolic links. Linux additionally verifies that FIFOs and character devices are rejected without blocking. Windows exercises reserved device namespaces. A Windows token that cannot create symlinks produces an explicit capability skip rather than a fabricated pass.

`json_oracle.py` sends synthetic inputs through the encoder and validates the results with the independent Python standard JSON and strict UTF-8 decoders. Valid Unicode and selected malformed sequences must decode to exact expected values; deterministic arbitrary byte streams must always produce a valid JSON string.

These checks cover only the listed functions. They do not establish application integration or correctness of other modules. All file mutations are confined to an automatically removed temporary fixture directory. Output contains counts and test outcomes, not file contents or collected hardware identifiers.
