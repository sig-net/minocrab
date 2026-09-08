#!/usr/bin/env python3
"""Per-circuit inventory of CHECKED ledger reads (Impact `popeq`) in a
compactc-compiled contract — the contention audit.

    tools/compact-reads.py <contract.compact> <managed/contract/index.js>

Every `popeq` in a circuit's public transcript is compared against the
ledger when the transaction lands (onchain-vm/src/vm.rs: the `cached`
flag is deprecated, no effect), so two transactions proven against one
state both apply only if neither reads a value the other writes.
Reads are named from the ledger declaration order: the compiler puts the
LAST 15 fields in chunk 1 and the rest, after one reserved slot, in
chunk 0. `[key]` = a map/set read on a caller-chosen key (contends only
on that key); `[SHARED]` = a counter or cell every transaction of that
kind reads; `[admin]` = a cell only an admin circuit writes.
"""
import collections, re, sys

SHARED = {'signetRequestNonce', 'vaultEvmNonce', 'issuedSlots'}
ADMIN = {'vaultMaxFeePerGas', 'vaultMaxPriorityFeePerGas', 'vaultGasLimits'}
CONST = {'signetSigner', 'mpcResponseKey', 'initialised', 'vaultEvmAddress', 'evmChainId',
         'caip2Id', 'deployer', 'uniswapRouter', 'stataUnderlying', 'stataToken', 'evmNonceBase'}


def main(compact, index_js):
    src = open(compact).read()
    decls = re.findall(r'^\s*(?:export |sealed )*ledger ([A-Za-z0-9_]+)\s*:', src, re.M)
    names = {(0, i): d for i, d in enumerate(decls[:-15])}
    names.update({(1, i): d for i, d in enumerate(decls[-15:])})
    lines = open(index_js).read().split('\n')
    ledger_fn = next(i for i, l in enumerate(lines) if re.match(r'\s*(?:export )?function ledger\(', l))
    heads = [(i, m.group(1)) for i, l in enumerate(lines)
             if (m := re.match(r'\s+(?:async )?_([A-Za-z0-9]+)_0\(context', l))]
    heads.append((ledger_fn, 'END'))
    for (s, name), (e, _) in zip(heads, heads[1:]):
        reads = collections.Counter()
        for i in range(s, e):
            if 'popeq' not in lines[i]:
                continue
            j = i
            while j > s and 'queryLedgerState' not in lines[j]:
                j -= 1
            seg = '\n'.join(lines[j:i + 1])
            nums = [int(v) for v in re.findall(r'toValue\((\d+)n\)', seg)]
            if len(nums) < 2:
                reads['kernel/self'] += 1
                continue
            nm = names.get((nums[0], nums[1]), f'?{nums[:2]}')
            if nm in SHARED:
                tag = ' [SHARED]'
            elif nm in ADMIN:
                tag = ' [admin]'
            elif nm in CONST:
                tag = ''
            else:
                tag = ' [key]' if ("'member'" in seg or 'push:' in seg) else ' [?]'
            reads[nm + tag] += 1
        if not reads:
            continue
        flag = '!!' if any('SHARED' in k for k in reads) else '  '
        order = sorted(reads.items(), key=lambda kv: ('SHARED' not in kv[0], 'admin' not in kv[0], kv[0]))
        print(f"{name:26s} {flag} " + ', '.join(f'{k}×{v}' if v > 1 else k for k, v in order))


if __name__ == '__main__':
    main(*sys.argv[1:3])
