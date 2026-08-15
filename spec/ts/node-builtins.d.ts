/**
 * The handful of node built-ins `vectors.test.ts` uses, declared here so that
 * `tsc --noEmit -p spec/ts` type-checks the whole directory WITHOUT
 * `@types/node` — this tree has no `node_modules` and no `package.json`, and
 * keeping it that way is part of the point.
 *
 * Nothing in the published decoder (`borsh-subset.ts`, `primitives.ts`) uses
 * any of this: they are plain ECMAScript over `DataView` and `Uint8Array`,
 * and run unchanged in a browser, a worker or Deno.
 */

declare module 'node:test' {
  export function test(name: string, fn: () => void | Promise<void>): void;
}

declare module 'node:assert/strict' {
  interface Assert {
    (value: unknown, message?: string): void;
    ok(value: unknown, message?: string): void;
    equal(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    throws(fn: () => unknown, expected?: RegExp, message?: string): void;
  }
  const assert: Assert;
  export default assert;
}

declare module 'node:fs' {
  export function readdirSync(path: string): string[];
  export function readFileSync(path: string, encoding: 'utf8'): string;
}

declare module 'node:path' {
  export function join(...parts: string[]): string;
}

declare module 'node:crypto' {
  interface Hash {
    update(data: Uint8Array): Hash;
    digest(encoding: 'hex'): string;
  }
  export function createHash(algorithm: string): Hash;
}

interface ImportMeta {
  /** The directory of the current module — node 21.2+. */
  readonly dirname: string;
}
