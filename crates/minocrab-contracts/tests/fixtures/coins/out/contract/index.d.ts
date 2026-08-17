import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
}

export type ImpureCircuits<PS> = {
  setInsertCoin(context: __compactRuntime.CircuitContext<PS>,
                coin_0: { nonce: Uint8Array, color: Uint8Array, value: bigint },
                recipient_0: { is_left: boolean,
                               left: { bytes: Uint8Array },
                               right: { bytes: Uint8Array }
                             }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertCoin(context: __compactRuntime.CircuitContext<PS>,
                k_0: Uint8Array,
                coin_0: { nonce: Uint8Array, color: Uint8Array, value: bigint },
                recipient_0: { is_left: boolean,
                               left: { bytes: Uint8Array },
                               right: { bytes: Uint8Array }
                             }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFrontCoin(context: __compactRuntime.CircuitContext<PS>,
                    coin_0: { nonce: Uint8Array,
                              color: Uint8Array,
                              value: bigint
                            },
                    recipient_0: { is_left: boolean,
                                   left: { bytes: Uint8Array },
                                   right: { bytes: Uint8Array }
                                 }): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type ProvableCircuits<PS> = {
  setInsertCoin(context: __compactRuntime.CircuitContext<PS>,
                coin_0: { nonce: Uint8Array, color: Uint8Array, value: bigint },
                recipient_0: { is_left: boolean,
                               left: { bytes: Uint8Array },
                               right: { bytes: Uint8Array }
                             }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertCoin(context: __compactRuntime.CircuitContext<PS>,
                k_0: Uint8Array,
                coin_0: { nonce: Uint8Array, color: Uint8Array, value: bigint },
                recipient_0: { is_left: boolean,
                               left: { bytes: Uint8Array },
                               right: { bytes: Uint8Array }
                             }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFrontCoin(context: __compactRuntime.CircuitContext<PS>,
                    coin_0: { nonce: Uint8Array,
                              color: Uint8Array,
                              value: bigint
                            },
                    recipient_0: { is_left: boolean,
                                   left: { bytes: Uint8Array },
                                   right: { bytes: Uint8Array }
                                 }): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  setInsertCoin(context: __compactRuntime.CircuitContext<PS>,
                coin_0: { nonce: Uint8Array, color: Uint8Array, value: bigint },
                recipient_0: { is_left: boolean,
                               left: { bytes: Uint8Array },
                               right: { bytes: Uint8Array }
                             }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  mapInsertCoin(context: __compactRuntime.CircuitContext<PS>,
                k_0: Uint8Array,
                coin_0: { nonce: Uint8Array, color: Uint8Array, value: bigint },
                recipient_0: { is_left: boolean,
                               left: { bytes: Uint8Array },
                               right: { bytes: Uint8Array }
                             }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  listPushFrontCoin(context: __compactRuntime.CircuitContext<PS>,
                    coin_0: { nonce: Uint8Array,
                              color: Uint8Array,
                              value: bigint
                            },
                    recipient_0: { is_left: boolean,
                                   left: { bytes: Uint8Array },
                                   right: { bytes: Uint8Array }
                                 }): Promise<__compactRuntime.CircuitResults<PS, []>>;
}

export type Ledger = {
  s: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: { nonce: Uint8Array,
                     color: Uint8Array,
                     value: bigint,
                     mt_index: bigint
                   }): boolean;
    [Symbol.iterator](): Iterator<{ nonce: Uint8Array, color: Uint8Array, value: bigint, mt_index: bigint }>
  };
  m: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): { nonce: Uint8Array,
                                 color: Uint8Array,
                                 value: bigint,
                                 mt_index: bigint
                               };
    [Symbol.iterator](): Iterator<[Uint8Array, { nonce: Uint8Array, color: Uint8Array, value: bigint, mt_index: bigint }]>
  };
  l: {
    isEmpty(): boolean;
    length(): bigint;
    head(): { is_some: boolean,
              value: { nonce: Uint8Array,
                       color: Uint8Array,
                       value: bigint,
                       mt_index: bigint
                     }
            };
    [Symbol.iterator](): Iterator<{ nonce: Uint8Array, color: Uint8Array, value: bigint, mt_index: bigint }>
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
