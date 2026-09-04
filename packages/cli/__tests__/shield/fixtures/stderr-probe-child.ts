// Probe child for OPA-01.AC3: writes one fixed line to stderr and exits 0.
// At base 5cb201b the harness discarded the stderr of a child that exited 0,
// so a fail-open `shield: lock-timeout` warning left no trace in a round's
// assertion message. The test asserts this line is retained on exit 0.
process.stderr.write('stderr-probe: retained on exit 0\n');
process.exit(0);
