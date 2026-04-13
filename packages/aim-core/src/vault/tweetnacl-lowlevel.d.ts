/**
 * Typed interface for tweetnacl's lowlevel Galois field operations.
 *
 * tweetnacl ships these functions at runtime (nacl.lowlevel) but the
 * published type definitions do not declare them. We access them via
 * a typed wrapper to keep the vault crypto module type-safe.
 */

export interface NaclLowlevel {
  /** Create a new GF (Galois field) element (Float64Array of length 16) */
  gf(init?: number[]): Float64Array;
  /** a = b */
  set25519(a: Float64Array, b: Float64Array): void;
  /** o = a + b (mod p) */
  A(o: Float64Array, a: Float64Array, b: Float64Array): void;
  /** o = a - b (mod p) */
  Z(o: Float64Array, a: Float64Array, b: Float64Array): void;
  /** o = a * b (mod p) */
  M(o: Float64Array, a: Float64Array, b: Float64Array): void;
  /** o = a^2 (mod p) */
  S(o: Float64Array, a: Float64Array): void;
  /** Unpack 32 bytes (little-endian) into a GF element */
  unpack25519(o: Float64Array, n: Uint8Array): void;
  /** Pack a GF element into 32 bytes (little-endian, reduced mod p) */
  pack25519(o: Uint8Array, n: Float64Array): void;
}
