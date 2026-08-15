import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
  w_name(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, string];
}

export type ImpureCircuits<PS> = {
  opArg(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opRet(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, string>>;
  opEq(context: __compactRuntime.CircuitContext<PS>, a_0: string, b_0: string): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  opDefault(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opCell(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opWitness(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opMapValue(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             v_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opMapKey(context: __compactRuntime.CircuitContext<PS>, k_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opSet(context: __compactRuntime.CircuitContext<PS>, k_0: string): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  opMaybe(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opBytes(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opStruct(context: __compactRuntime.CircuitContext<PS>,
           w_0: { tag: bigint, name: string }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opPoint(context: __compactRuntime.CircuitContext<PS>,
          p_0: __compactRuntime.Secp256k1Point): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opJubjub(context: __compactRuntime.CircuitContext<PS>,
           p_0: __compactRuntime.JubjubPoint): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type ProvableCircuits<PS> = {
  opArg(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opRet(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, string>>;
  opEq(context: __compactRuntime.CircuitContext<PS>, a_0: string, b_0: string): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  opDefault(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opCell(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opWitness(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opMapValue(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             v_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opMapKey(context: __compactRuntime.CircuitContext<PS>, k_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opSet(context: __compactRuntime.CircuitContext<PS>, k_0: string): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  opMaybe(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opBytes(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opStruct(context: __compactRuntime.CircuitContext<PS>,
           w_0: { tag: bigint, name: string }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opPoint(context: __compactRuntime.CircuitContext<PS>,
          p_0: __compactRuntime.Secp256k1Point): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opJubjub(context: __compactRuntime.CircuitContext<PS>,
           p_0: __compactRuntime.JubjubPoint): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  opArg(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opRet(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, string>>;
  opEq(context: __compactRuntime.CircuitContext<PS>, a_0: string, b_0: string): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  opDefault(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opCell(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opWitness(context: __compactRuntime.CircuitContext<PS>): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opMapValue(context: __compactRuntime.CircuitContext<PS>,
             k_0: Uint8Array,
             v_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opMapKey(context: __compactRuntime.CircuitContext<PS>, k_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opSet(context: __compactRuntime.CircuitContext<PS>, k_0: string): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  opMaybe(context: __compactRuntime.CircuitContext<PS>, x_0: string): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opBytes(context: __compactRuntime.CircuitContext<PS>, x_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opStruct(context: __compactRuntime.CircuitContext<PS>,
           w_0: { tag: bigint, name: string }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opPoint(context: __compactRuntime.CircuitContext<PS>,
          p_0: __compactRuntime.Secp256k1Point): Promise<__compactRuntime.CircuitResults<PS, []>>;
  opJubjub(context: __compactRuntime.CircuitContext<PS>,
           p_0: __compactRuntime.JubjubPoint): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type Ledger = {
  readonly dummy: bigint;
  readonly cell: string;
  readonly bytes_cell: Uint8Array;
  readonly maybe: { is_some: boolean, value: string };
  names: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  by_hash: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): string;
    [Symbol.iterator](): Iterator<[Uint8Array, string]>
  };
  by_name: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: string): boolean;
    lookup(key_0: string): bigint;
    [Symbol.iterator](): Iterator<[string, bigint]>
  };
  readonly response_key: __compactRuntime.Secp256k1Point;
  readonly jubjub_key: __compactRuntime.JubjubPoint;
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
