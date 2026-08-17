import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
}

export type ImpureCircuits<PS> = {
  mapInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array,
            v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertDefault(context: __compactRuntime.CircuitContext<PS>,
                   k_0: Uint8Array,
                   k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapLookup(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  mapMember(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mapRemove(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapSize(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  mapIsEmpty(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mapReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  outerInsertDefault(context: __compactRuntime.CircuitContext<PS>,
                     k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFront(context: __compactRuntime.CircuitContext<PS>,
                k_0: Uint8Array,
                v_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPopFront(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listLength(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  listHead(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, { is_some: boolean,
                                                                                                                         value: Uint8Array
                                                                                                                       }>>;
  listIsEmpty(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  listReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setRemove(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setMember(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  counterIncrement(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  counterRead(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  counterReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsert(context: __compactRuntime.CircuitContext<PS>,
           k_0: Uint8Array,
           item_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
              k_0: Uint8Array,
              rt_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            item_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtResetHistory(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  deepInsert(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             k2_0: Uint8Array,
             k3_0: Uint8Array,
             v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  deepLookup(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             k2_0: Uint8Array,
             k3_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
}

export type ProvableCircuits<PS> = {
  mapInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array,
            v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertDefault(context: __compactRuntime.CircuitContext<PS>,
                   k_0: Uint8Array,
                   k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapLookup(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  mapMember(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mapRemove(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapSize(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  mapIsEmpty(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mapReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  outerInsertDefault(context: __compactRuntime.CircuitContext<PS>,
                     k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFront(context: __compactRuntime.CircuitContext<PS>,
                k_0: Uint8Array,
                v_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPopFront(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listLength(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  listHead(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, { is_some: boolean,
                                                                                                                         value: Uint8Array
                                                                                                                       }>>;
  listIsEmpty(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  listReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setRemove(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setMember(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  counterIncrement(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  counterRead(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  counterReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsert(context: __compactRuntime.CircuitContext<PS>,
           k_0: Uint8Array,
           item_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
              k_0: Uint8Array,
              rt_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            item_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtResetHistory(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  deepInsert(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             k2_0: Uint8Array,
             k3_0: Uint8Array,
             v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  deepLookup(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             k2_0: Uint8Array,
             k3_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  mapInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array,
            v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertDefault(context: __compactRuntime.CircuitContext<PS>,
                   k_0: Uint8Array,
                   k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapLookup(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  mapMember(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mapRemove(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            k2_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapSize(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  mapIsEmpty(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mapReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  outerInsertDefault(context: __compactRuntime.CircuitContext<PS>,
                     k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFront(context: __compactRuntime.CircuitContext<PS>,
                k_0: Uint8Array,
                v_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPopFront(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listLength(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  listHead(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, { is_some: boolean,
                                                                                                                         value: Uint8Array
                                                                                                                       }>>;
  listIsEmpty(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  listReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setRemove(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  setMember(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            e_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  setReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  counterIncrement(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  counterRead(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  counterReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtInsert(context: __compactRuntime.CircuitContext<PS>,
           k_0: Uint8Array,
           item_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mtCheckRoot(context: __compactRuntime.CircuitContext<PS>,
              k_0: Uint8Array,
              rt_0: { field: bigint }): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  mtReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtInsert(context: __compactRuntime.CircuitContext<PS>,
            k_0: Uint8Array,
            item_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtResetHistory(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  hmtReset(context: __compactRuntime.CircuitContext<PS>, k_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  deepInsert(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             k2_0: Uint8Array,
             k3_0: Uint8Array,
             v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  deepLookup(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             k2_0: Uint8Array,
             k3_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
}

export type Ledger = {
  mm: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): {
      isEmpty(): boolean;
      size(): bigint;
      member(key_1: Uint8Array): boolean;
      lookup(key_1: Uint8Array): bigint;
      [Symbol.iterator](): Iterator<[Uint8Array, bigint]>
    }
  };
  ml: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): {
      isEmpty(): boolean;
      length(): bigint;
      head(): { is_some: boolean, value: Uint8Array };
      [Symbol.iterator](): Iterator<Uint8Array>
    }
  };
  ms: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): {
      isEmpty(): boolean;
      size(): bigint;
      member(elem_0: Uint8Array): boolean;
      [Symbol.iterator](): Iterator<Uint8Array>
    }
  };
  mc: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): { read(): bigint }
  };
  mt: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): {
      isFull(): boolean;
      checkRoot(rt_0: { field: bigint }): boolean;
      root(): __compactRuntime.MerkleTreeDigest;
      firstFree(): bigint;
      pathForLeaf(index_0: bigint, leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array>;
      findPathForLeaf(leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array> | undefined
    }
  };
  mh: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): {
      isFull(): boolean;
      checkRoot(rt_0: { field: bigint }): boolean;
      root(): __compactRuntime.MerkleTreeDigest;
      firstFree(): bigint;
      pathForLeaf(index_0: bigint, leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array>;
      findPathForLeaf(leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array> | undefined;
      history(): Iterator<__compactRuntime.MerkleTreeDigest>
    }
  };
  mmm: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): {
      isEmpty(): boolean;
      size(): bigint;
      member(key_1: Uint8Array): boolean;
      lookup(key_1: Uint8Array): {
        isEmpty(): boolean;
        size(): bigint;
        member(key_2: Uint8Array): boolean;
        lookup(key_2: Uint8Array): bigint;
        [Symbol.iterator](): Iterator<[Uint8Array, bigint]>
      }
    }
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
