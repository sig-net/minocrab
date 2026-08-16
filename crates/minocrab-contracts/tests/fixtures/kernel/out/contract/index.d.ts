import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
}

export type ImpureCircuits<PS> = {
  kMintUnshielded(context: __compactRuntime.CircuitContext<PS>,
                  ds_0: Uint8Array,
                  amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kClaimUnshieldedCoinSpend(context: __compactRuntime.CircuitContext<PS>,
                            color_0: Uint8Array,
                            addr_0: { is_left: boolean,
                                      left: { bytes: Uint8Array },
                                      right: { bytes: Uint8Array }
                                    },
                            amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kIncUnshieldedOutputs(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kIncUnshieldedInputs(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kBalance(context: __compactRuntime.CircuitContext<PS>, color_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  kBalanceLessThan(context: __compactRuntime.CircuitContext<PS>,
                   color_0: Uint8Array,
                   amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBalanceGreaterThan(context: __compactRuntime.CircuitContext<PS>,
                      color_0: Uint8Array,
                      amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBlockTimeLessThan(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBlockTimeGreaterThan(context: __compactRuntime.CircuitContext<PS>,
                        t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeLt(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeGte(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeGt(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeLte(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalance(context: __compactRuntime.CircuitContext<PS>,
                     color_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  sUnshieldedBalanceLt(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceGte(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceGt(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceLte(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sReceiveUnshielded(context: __compactRuntime.CircuitContext<PS>,
                     color_0: Uint8Array,
                     a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sSendUnshielded(context: __compactRuntime.CircuitContext<PS>,
                  color_0: Uint8Array,
                  a_0: bigint,
                  r_0: { is_left: boolean,
                         left: { bytes: Uint8Array },
                         right: { bytes: Uint8Array }
                       }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sMintUnshieldedToken(context: __compactRuntime.CircuitContext<PS>,
                       ds_0: Uint8Array,
                       a_0: bigint,
                       r_0: { is_left: boolean,
                              left: { bytes: Uint8Array },
                              right: { bytes: Uint8Array }
                            }): Promise<__compactRuntime.CircuitResults<PS, Uint8Array>>;
  sMergeCoin(context: __compactRuntime.CircuitContext<PS>,
             a_0: { nonce: Uint8Array,
                    color: Uint8Array,
                    value: bigint,
                    mt_index: bigint
                  },
             b_0: { nonce: Uint8Array,
                    color: Uint8Array,
                    value: bigint,
                    mt_index: bigint
                  }): Promise<__compactRuntime.CircuitResults<PS, { nonce: Uint8Array,
                                                                    color: Uint8Array,
                                                                    value: bigint
                                                                  }>>;
  sMergeCoinImmediate(context: __compactRuntime.CircuitContext<PS>,
                      a_0: { nonce: Uint8Array,
                             color: Uint8Array,
                             value: bigint,
                             mt_index: bigint
                           },
                      b_0: { nonce: Uint8Array, color: Uint8Array, value: bigint
                           }): Promise<__compactRuntime.CircuitResults<PS, { nonce: Uint8Array,
                                                                             color: Uint8Array,
                                                                             value: bigint
                                                                           }>>;
  sSendShielded(context: __compactRuntime.CircuitContext<PS>,
                input_0: { nonce: Uint8Array,
                           color: Uint8Array,
                           value: bigint,
                           mt_index: bigint
                         },
                r_0: { is_left: boolean,
                       left: { bytes: Uint8Array },
                       right: { bytes: Uint8Array }
                     },
                v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, { change: { is_some: boolean,
                                                                                      value: { nonce: Uint8Array,
                                                                                               color: Uint8Array,
                                                                                               value: bigint
                                                                                             }
                                                                                    },
                                                                            sent: { nonce: Uint8Array,
                                                                                    color: Uint8Array,
                                                                                    value: bigint
                                                                                  }
                                                                          }>>;
}

export type ProvableCircuits<PS> = {
  kMintUnshielded(context: __compactRuntime.CircuitContext<PS>,
                  ds_0: Uint8Array,
                  amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kClaimUnshieldedCoinSpend(context: __compactRuntime.CircuitContext<PS>,
                            color_0: Uint8Array,
                            addr_0: { is_left: boolean,
                                      left: { bytes: Uint8Array },
                                      right: { bytes: Uint8Array }
                                    },
                            amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kIncUnshieldedOutputs(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kIncUnshieldedInputs(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kBalance(context: __compactRuntime.CircuitContext<PS>, color_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  kBalanceLessThan(context: __compactRuntime.CircuitContext<PS>,
                   color_0: Uint8Array,
                   amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBalanceGreaterThan(context: __compactRuntime.CircuitContext<PS>,
                      color_0: Uint8Array,
                      amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBlockTimeLessThan(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBlockTimeGreaterThan(context: __compactRuntime.CircuitContext<PS>,
                        t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeLt(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeGte(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeGt(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeLte(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalance(context: __compactRuntime.CircuitContext<PS>,
                     color_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  sUnshieldedBalanceLt(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceGte(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceGt(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceLte(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sReceiveUnshielded(context: __compactRuntime.CircuitContext<PS>,
                     color_0: Uint8Array,
                     a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sSendUnshielded(context: __compactRuntime.CircuitContext<PS>,
                  color_0: Uint8Array,
                  a_0: bigint,
                  r_0: { is_left: boolean,
                         left: { bytes: Uint8Array },
                         right: { bytes: Uint8Array }
                       }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sMintUnshieldedToken(context: __compactRuntime.CircuitContext<PS>,
                       ds_0: Uint8Array,
                       a_0: bigint,
                       r_0: { is_left: boolean,
                              left: { bytes: Uint8Array },
                              right: { bytes: Uint8Array }
                            }): Promise<__compactRuntime.CircuitResults<PS, Uint8Array>>;
  sMergeCoin(context: __compactRuntime.CircuitContext<PS>,
             a_0: { nonce: Uint8Array,
                    color: Uint8Array,
                    value: bigint,
                    mt_index: bigint
                  },
             b_0: { nonce: Uint8Array,
                    color: Uint8Array,
                    value: bigint,
                    mt_index: bigint
                  }): Promise<__compactRuntime.CircuitResults<PS, { nonce: Uint8Array,
                                                                    color: Uint8Array,
                                                                    value: bigint
                                                                  }>>;
  sMergeCoinImmediate(context: __compactRuntime.CircuitContext<PS>,
                      a_0: { nonce: Uint8Array,
                             color: Uint8Array,
                             value: bigint,
                             mt_index: bigint
                           },
                      b_0: { nonce: Uint8Array, color: Uint8Array, value: bigint
                           }): Promise<__compactRuntime.CircuitResults<PS, { nonce: Uint8Array,
                                                                             color: Uint8Array,
                                                                             value: bigint
                                                                           }>>;
  sSendShielded(context: __compactRuntime.CircuitContext<PS>,
                input_0: { nonce: Uint8Array,
                           color: Uint8Array,
                           value: bigint,
                           mt_index: bigint
                         },
                r_0: { is_left: boolean,
                       left: { bytes: Uint8Array },
                       right: { bytes: Uint8Array }
                     },
                v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, { change: { is_some: boolean,
                                                                                      value: { nonce: Uint8Array,
                                                                                               color: Uint8Array,
                                                                                               value: bigint
                                                                                             }
                                                                                    },
                                                                            sent: { nonce: Uint8Array,
                                                                                    color: Uint8Array,
                                                                                    value: bigint
                                                                                  }
                                                                          }>>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  kMintUnshielded(context: __compactRuntime.CircuitContext<PS>,
                  ds_0: Uint8Array,
                  amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kClaimUnshieldedCoinSpend(context: __compactRuntime.CircuitContext<PS>,
                            color_0: Uint8Array,
                            addr_0: { is_left: boolean,
                                      left: { bytes: Uint8Array },
                                      right: { bytes: Uint8Array }
                                    },
                            amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kIncUnshieldedOutputs(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kIncUnshieldedInputs(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  kBalance(context: __compactRuntime.CircuitContext<PS>, color_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  kBalanceLessThan(context: __compactRuntime.CircuitContext<PS>,
                   color_0: Uint8Array,
                   amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBalanceGreaterThan(context: __compactRuntime.CircuitContext<PS>,
                      color_0: Uint8Array,
                      amount_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBlockTimeLessThan(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  kBlockTimeGreaterThan(context: __compactRuntime.CircuitContext<PS>,
                        t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeLt(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeGte(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeGt(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sBlockTimeLte(context: __compactRuntime.CircuitContext<PS>, t_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalance(context: __compactRuntime.CircuitContext<PS>,
                     color_0: Uint8Array): Promise<__compactRuntime.CircuitResults<PS, bigint>>;
  sUnshieldedBalanceLt(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceGte(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceGt(context: __compactRuntime.CircuitContext<PS>,
                       color_0: Uint8Array,
                       a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sUnshieldedBalanceLte(context: __compactRuntime.CircuitContext<PS>,
                        color_0: Uint8Array,
                        a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, boolean>>;
  sReceiveUnshielded(context: __compactRuntime.CircuitContext<PS>,
                     color_0: Uint8Array,
                     a_0: bigint): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sSendUnshielded(context: __compactRuntime.CircuitContext<PS>,
                  color_0: Uint8Array,
                  a_0: bigint,
                  r_0: { is_left: boolean,
                         left: { bytes: Uint8Array },
                         right: { bytes: Uint8Array }
                       }): Promise<__compactRuntime.CircuitResults<PS, []>>;
  sMintUnshieldedToken(context: __compactRuntime.CircuitContext<PS>,
                       ds_0: Uint8Array,
                       a_0: bigint,
                       r_0: { is_left: boolean,
                              left: { bytes: Uint8Array },
                              right: { bytes: Uint8Array }
                            }): Promise<__compactRuntime.CircuitResults<PS, Uint8Array>>;
  sMergeCoin(context: __compactRuntime.CircuitContext<PS>,
             a_0: { nonce: Uint8Array,
                    color: Uint8Array,
                    value: bigint,
                    mt_index: bigint
                  },
             b_0: { nonce: Uint8Array,
                    color: Uint8Array,
                    value: bigint,
                    mt_index: bigint
                  }): Promise<__compactRuntime.CircuitResults<PS, { nonce: Uint8Array,
                                                                    color: Uint8Array,
                                                                    value: bigint
                                                                  }>>;
  sMergeCoinImmediate(context: __compactRuntime.CircuitContext<PS>,
                      a_0: { nonce: Uint8Array,
                             color: Uint8Array,
                             value: bigint,
                             mt_index: bigint
                           },
                      b_0: { nonce: Uint8Array, color: Uint8Array, value: bigint
                           }): Promise<__compactRuntime.CircuitResults<PS, { nonce: Uint8Array,
                                                                             color: Uint8Array,
                                                                             value: bigint
                                                                           }>>;
  sSendShielded(context: __compactRuntime.CircuitContext<PS>,
                input_0: { nonce: Uint8Array,
                           color: Uint8Array,
                           value: bigint,
                           mt_index: bigint
                         },
                r_0: { is_left: boolean,
                       left: { bytes: Uint8Array },
                       right: { bytes: Uint8Array }
                     },
                v_0: bigint): Promise<__compactRuntime.CircuitResults<PS, { change: { is_some: boolean,
                                                                                      value: { nonce: Uint8Array,
                                                                                               color: Uint8Array,
                                                                                               value: bigint
                                                                                             }
                                                                                    },
                                                                            sent: { nonce: Uint8Array,
                                                                                    color: Uint8Array,
                                                                                    value: bigint
                                                                                  }
                                                                          }>>;
}

export type Ledger = {
  readonly dummy: bigint;
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
