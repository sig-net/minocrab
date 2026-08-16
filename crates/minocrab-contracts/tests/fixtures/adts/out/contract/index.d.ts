import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
}

export type ImpureCircuits<PS> = {
  setInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setMember(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setRemove(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setSize(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  setIsEmpty(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFront(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPopFront(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listHead(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, { is_some: boolean,
                                                                                                        value: Uint8Array
                                                                                                      }>>;
  listLength(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  listIsEmpty(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  listReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertDefault(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertIndex(context: __compactRuntime.CircuitContext<PS>,
                x_0: Uint8Array,
                i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertHash(context: __compactRuntime.CircuitContext<PS>, h_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertHashIndex(context: __compactRuntime.CircuitContext<PS>,
                    h_0: Uint8Array,
                    i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertIndexDefault(context: __compactRuntime.CircuitContext<PS>, i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
              r_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtIsFull(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertIndex(context: __compactRuntime.CircuitContext<PS>,
                 x_0: Uint8Array,
                 i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertHash(context: __compactRuntime.CircuitContext<PS>, h_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertHashIndex(context: __compactRuntime.CircuitContext<PS>,
                     h_0: Uint8Array,
                     i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertIndexDefault(context: __compactRuntime.CircuitContext<PS>,
                        i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
               r_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  hmtIsFull(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  hmtResetHistory(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type ProvableCircuits<PS> = {
  setInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setMember(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setRemove(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setSize(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  setIsEmpty(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFront(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPopFront(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listHead(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, { is_some: boolean,
                                                                                                        value: Uint8Array
                                                                                                      }>>;
  listLength(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  listIsEmpty(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  listReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertDefault(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertIndex(context: __compactRuntime.CircuitContext<PS>,
                x_0: Uint8Array,
                i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertHash(context: __compactRuntime.CircuitContext<PS>, h_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertHashIndex(context: __compactRuntime.CircuitContext<PS>,
                    h_0: Uint8Array,
                    i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertIndexDefault(context: __compactRuntime.CircuitContext<PS>, i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
              r_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtIsFull(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertIndex(context: __compactRuntime.CircuitContext<PS>,
                 x_0: Uint8Array,
                 i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertHash(context: __compactRuntime.CircuitContext<PS>, h_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertHashIndex(context: __compactRuntime.CircuitContext<PS>,
                     h_0: Uint8Array,
                     i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertIndexDefault(context: __compactRuntime.CircuitContext<PS>,
                        i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
               r_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  hmtIsFull(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  hmtResetHistory(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  setInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setMember(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setRemove(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setSize(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  setIsEmpty(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFront(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPopFront(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listHead(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, { is_some: boolean,
                                                                                                        value: Uint8Array
                                                                                                      }>>;
  listLength(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  listIsEmpty(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  listReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertDefault(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertIndex(context: __compactRuntime.CircuitContext<PS>,
                x_0: Uint8Array,
                i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertHash(context: __compactRuntime.CircuitContext<PS>, h_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertHashIndex(context: __compactRuntime.CircuitContext<PS>,
                    h_0: Uint8Array,
                    i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsertIndexDefault(context: __compactRuntime.CircuitContext<PS>, i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
              r_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtIsFull(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsert(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertIndex(context: __compactRuntime.CircuitContext<PS>,
                 x_0: Uint8Array,
                 i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertHash(context: __compactRuntime.CircuitContext<PS>, h_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertHashIndex(context: __compactRuntime.CircuitContext<PS>,
                     h_0: Uint8Array,
                     i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsertIndexDefault(context: __compactRuntime.CircuitContext<PS>,
                        i_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
               r_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  hmtIsFull(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  hmtResetHistory(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtReset(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type Ledger = {
  readonly dummy: bigint;
  s: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: Uint8Array): boolean;
    [Symbol.iterator](): Iterator<Uint8Array>
  };
  l: {
    isEmpty(): boolean;
    length(): bigint;
    head(): { is_some: boolean, value: Uint8Array };
    [Symbol.iterator](): Iterator<Uint8Array>
  };
  m: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): bigint;
    [Symbol.iterator](): Iterator<[Uint8Array, bigint]>
  };
  mt: {
    isFull(): boolean;
    checkRoot(rt_0: { field: bigint }): boolean;
    root(): __compactRuntime.MerkleTreeDigest;
    firstFree(): bigint;
    pathForLeaf(index_0: bigint, leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array>;
    findPathForLeaf(leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array> | undefined
  };
  hmt: {
    isFull(): boolean;
    checkRoot(rt_0: { field: bigint }): boolean;
    root(): __compactRuntime.MerkleTreeDigest;
    firstFree(): bigint;
    pathForLeaf(index_0: bigint, leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array>;
    findPathForLeaf(leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array> | undefined;
    history(): Iterator<__compactRuntime.MerkleTreeDigest>
  };
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): Promise<__compactRuntime.ConstructorResult<PS>>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
export declare const expectedVk: Record<string, string>;
