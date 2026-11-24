/**
 * The words a CLI prints for a version with no Registry scan result
 * (`scanStatus` null or absent). One home for both forms, so every CLI
 * that imports them prints the same words.
 */

/** Block form: the check block's Trust line, where a line has room. */
export const NO_SCAN_RESULT_TEXT = "not scanned, no score";

/** Short form: a table's scan cell, and the rich block's score line. */
export const NO_SCAN_RESULT_SHORT_TEXT = "not scanned";
