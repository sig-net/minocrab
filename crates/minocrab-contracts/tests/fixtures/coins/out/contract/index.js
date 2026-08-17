import * as __compactRuntime from '@midnight-ntwrk/compact-runtime';
__compactRuntime.checkRuntimeVersion('0.18.0-rc.1');

const _descriptor_0 = new __compactRuntime.CompactTypeBytes(32);

const _descriptor_1 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

const _descriptor_2 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

class _QualifiedShieldedCoinInfo_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_1.alignment().concat(_descriptor_2.alignment())));
  }
  fromValue(value_0) {
    return {
      nonce: _descriptor_0.fromValue(value_0),
      color: _descriptor_0.fromValue(value_0),
      value: _descriptor_1.fromValue(value_0),
      mt_index: _descriptor_2.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.nonce).concat(_descriptor_0.toValue(value_0.color).concat(_descriptor_1.toValue(value_0.value).concat(_descriptor_2.toValue(value_0.mt_index))));
  }
}

const _descriptor_3 = new _QualifiedShieldedCoinInfo_0();

class _ShieldedCoinInfo_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      nonce: _descriptor_0.fromValue(value_0),
      color: _descriptor_0.fromValue(value_0),
      value: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.nonce).concat(_descriptor_0.toValue(value_0.color).concat(_descriptor_1.toValue(value_0.value)));
  }
}

const _descriptor_4 = new _ShieldedCoinInfo_0();

const _descriptor_5 = __compactRuntime.CompactTypeBoolean;

class _ZswapCoinPublicKey_0 {
  alignment() {
    return _descriptor_0.alignment();
  }
  fromValue(value_0) {
    return {
      bytes: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.bytes);
  }
}

const _descriptor_6 = new _ZswapCoinPublicKey_0();

class _ContractAddress_0 {
  alignment() {
    return _descriptor_0.alignment();
  }
  fromValue(value_0) {
    return {
      bytes: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.bytes);
  }
}

const _descriptor_7 = new _ContractAddress_0();

class _Either_0 {
  alignment() {
    return _descriptor_5.alignment().concat(_descriptor_6.alignment().concat(_descriptor_7.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_5.fromValue(value_0),
      left: _descriptor_6.fromValue(value_0),
      right: _descriptor_7.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_5.toValue(value_0.is_left).concat(_descriptor_6.toValue(value_0.left).concat(_descriptor_7.toValue(value_0.right)));
  }
}

const _descriptor_8 = new _Either_0();

class _Either_1 {
  alignment() {
    return _descriptor_5.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_5.fromValue(value_0),
      left: _descriptor_0.fromValue(value_0),
      right: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_5.toValue(value_0.is_left).concat(_descriptor_0.toValue(value_0.left).concat(_descriptor_0.toValue(value_0.right)));
  }
}

const _descriptor_9 = new _Either_1();

class _Maybe_0 {
  alignment() {
    return _descriptor_5.alignment().concat(_descriptor_3.alignment());
  }
  fromValue(value_0) {
    return {
      is_some: _descriptor_5.fromValue(value_0),
      value: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_5.toValue(value_0.is_some).concat(_descriptor_3.toValue(value_0.value));
  }
}

const _descriptor_10 = new _Maybe_0();

const _descriptor_11 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

const _descriptor_12 = new __compactRuntime.CompactTypeUnsignedInteger(4294967295n, 4);

export class Contract {
  witnesses;
  constructor(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract constructor: expected 1 argument, received ${args_0.length}`);
    }
    const witnesses_0 = args_0[0];
    if (typeof(witnesses_0) !== 'object') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor is not an object');
    }
    this.witnesses = witnesses_0;
    this.circuits = {
      setInsertCoin: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`setInsertCoin: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const coin_0 = args_1[1];
        const recipient_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('setInsertCoin',
                                     'argument 1 (as invoked from Typescript)',
                                     'coins.compact line 23 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(coin_0) === 'object' && coin_0.nonce.buffer instanceof ArrayBuffer && coin_0.nonce.BYTES_PER_ELEMENT === 1 && coin_0.nonce.length === 32 && coin_0.color.buffer instanceof ArrayBuffer && coin_0.color.BYTES_PER_ELEMENT === 1 && coin_0.color.length === 32 && typeof(coin_0.value) === 'bigint' && coin_0.value >= 0n && coin_0.value <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('setInsertCoin',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'coins.compact line 23 char 1',
                                     'struct ShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>>',
                                     coin_0)
        }
        if (!(typeof(recipient_0) === 'object' && typeof(recipient_0.is_left) === 'boolean' && typeof(recipient_0.left) === 'object' && recipient_0.left.bytes.buffer instanceof ArrayBuffer && recipient_0.left.bytes.BYTES_PER_ELEMENT === 1 && recipient_0.left.bytes.length === 32 && typeof(recipient_0.right) === 'object' && recipient_0.right.bytes.buffer instanceof ArrayBuffer && recipient_0.right.bytes.BYTES_PER_ELEMENT === 1 && recipient_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('setInsertCoin',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'coins.compact line 23 char 1',
                                     'struct Either<is_left: Boolean, left: struct ZswapCoinPublicKey<bytes: Bytes<32>>, right: struct ContractAddress<bytes: Bytes<32>>>',
                                     recipient_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_4.toValue(coin_0).concat(_descriptor_8.toValue(recipient_0)),
            alignment: _descriptor_4.alignment().concat(_descriptor_8.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._setInsertCoin_0(context,
                                                     partialProofData,
                                                     coin_0,
                                                     recipient_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapInsertCoin: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`mapInsertCoin: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const coin_0 = args_1[2];
        const recipient_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapInsertCoin',
                                     'argument 1 (as invoked from Typescript)',
                                     'coins.compact line 30 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapInsertCoin',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'coins.compact line 30 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(typeof(coin_0) === 'object' && coin_0.nonce.buffer instanceof ArrayBuffer && coin_0.nonce.BYTES_PER_ELEMENT === 1 && coin_0.nonce.length === 32 && coin_0.color.buffer instanceof ArrayBuffer && coin_0.color.BYTES_PER_ELEMENT === 1 && coin_0.color.length === 32 && typeof(coin_0.value) === 'bigint' && coin_0.value >= 0n && coin_0.value <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('mapInsertCoin',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'coins.compact line 30 char 1',
                                     'struct ShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>>',
                                     coin_0)
        }
        if (!(typeof(recipient_0) === 'object' && typeof(recipient_0.is_left) === 'boolean' && typeof(recipient_0.left) === 'object' && recipient_0.left.bytes.buffer instanceof ArrayBuffer && recipient_0.left.bytes.BYTES_PER_ELEMENT === 1 && recipient_0.left.bytes.length === 32 && typeof(recipient_0.right) === 'object' && recipient_0.right.bytes.buffer instanceof ArrayBuffer && recipient_0.right.bytes.BYTES_PER_ELEMENT === 1 && recipient_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('mapInsertCoin',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'coins.compact line 30 char 1',
                                     'struct Either<is_left: Boolean, left: struct ZswapCoinPublicKey<bytes: Bytes<32>>, right: struct ContractAddress<bytes: Bytes<32>>>',
                                     recipient_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_4.toValue(coin_0).concat(_descriptor_8.toValue(recipient_0))),
            alignment: _descriptor_0.alignment().concat(_descriptor_4.alignment().concat(_descriptor_8.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapInsertCoin_0(context,
                                                     partialProofData,
                                                     k_0,
                                                     coin_0,
                                                     recipient_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listPushFrontCoin: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`listPushFrontCoin: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const coin_0 = args_1[1];
        const recipient_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listPushFrontCoin',
                                     'argument 1 (as invoked from Typescript)',
                                     'coins.compact line 38 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(coin_0) === 'object' && coin_0.nonce.buffer instanceof ArrayBuffer && coin_0.nonce.BYTES_PER_ELEMENT === 1 && coin_0.nonce.length === 32 && coin_0.color.buffer instanceof ArrayBuffer && coin_0.color.BYTES_PER_ELEMENT === 1 && coin_0.color.length === 32 && typeof(coin_0.value) === 'bigint' && coin_0.value >= 0n && coin_0.value <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('listPushFrontCoin',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'coins.compact line 38 char 1',
                                     'struct ShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>>',
                                     coin_0)
        }
        if (!(typeof(recipient_0) === 'object' && typeof(recipient_0.is_left) === 'boolean' && typeof(recipient_0.left) === 'object' && recipient_0.left.bytes.buffer instanceof ArrayBuffer && recipient_0.left.bytes.BYTES_PER_ELEMENT === 1 && recipient_0.left.bytes.length === 32 && typeof(recipient_0.right) === 'object' && recipient_0.right.bytes.buffer instanceof ArrayBuffer && recipient_0.right.bytes.BYTES_PER_ELEMENT === 1 && recipient_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('listPushFrontCoin',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'coins.compact line 38 char 1',
                                     'struct Either<is_left: Boolean, left: struct ZswapCoinPublicKey<bytes: Bytes<32>>, right: struct ContractAddress<bytes: Bytes<32>>>',
                                     recipient_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_4.toValue(coin_0).concat(_descriptor_8.toValue(recipient_0)),
            alignment: _descriptor_4.alignment().concat(_descriptor_8.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listPushFrontCoin_0(context,
                                                         partialProofData,
                                                         coin_0,
                                                         recipient_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      }
    };
    this.impureCircuits = {
      setInsertCoin: this.circuits.setInsertCoin,
      mapInsertCoin: this.circuits.mapInsertCoin,
      listPushFrontCoin: this.circuits.listPushFrontCoin
    };
    this.provableCircuits = {
      setInsertCoin: this.circuits.setInsertCoin,
      mapInsertCoin: this.circuits.mapInsertCoin,
      listPushFrontCoin: this.circuits.listPushFrontCoin
    };
  }
  async initialState(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const constructorContext_0 = args_0[0];
    if (typeof(constructorContext_0) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'constructorContext' in argument 1 (as invoked from Typescript) to be an object`);
    }
    if (!('initialZswapLocalState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript)`);
    }
    if (typeof(constructorContext_0.initialZswapLocalState) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript) to be an object`);
    }
    const state_0 = new __compactRuntime.ContractState();
    let stateValue_0 = __compactRuntime.StateValue.newArray();
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    state_0.setOperation('setInsertCoin', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapInsertCoin', new __compactRuntime.ContractOperation());
    state_0.setOperation('listPushFrontCoin', new __compactRuntime.ContractOperation());
    const context = __compactRuntime.createCircuitContext('constructor', __compactRuntime.dummyContractAddress(), constructorContext_0.initialZswapLocalState.coinPublicKey, state_0.data, constructorContext_0.initialPrivateState);
    const partialProofData = {
      input: { value: [], alignment: [] },
      output: undefined,
      publicTranscript: [],
      privateTranscriptOutputs: []
    };
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(0n),
                                                                                              alignment: _descriptor_11.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(1n),
                                                                                              alignment: _descriptor_11.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(2n),
                                                                                              alignment: _descriptor_11.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                                                                                                                                                             alignment: _descriptor_2.alignment() }))
                                                          .encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    state_0.data = new __compactRuntime.ChargedState(context.callContext.currentQueryContext.state.state);
    return {
      currentContractState: state_0,
      currentPrivateState: context.callContext.currentPrivateState,
      currentZswapLocalState: context.callContext.currentZswapLocalState
    }
  }
  async _setInsertCoin_0(context, partialProofData, coin_0, recipient_0) {
    __compactRuntime.hasCoinCommitment(context, coin_0, recipient_0) ? __compactRuntime.queryLedgerState(context,
                                                                                                         partialProofData,
                                                                                                         [
                                                                                                          { idx: { cached: false,
                                                                                                                   pushPath: true,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(0n),
                                                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                                                          { dup: { n: 4 } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell(__compactRuntime.runtimeCoinCommitment(
                                                                                                                                                                 { value: _descriptor_4.toValue(coin_0),
                                                                                                                                                                   alignment: _descriptor_4.alignment() },
                                                                                                                                                                 { value: _descriptor_8.toValue(recipient_0),
                                                                                                                                                                   alignment: _descriptor_8.alignment() }
                                                                                                                                                               )).encode() } },
                                                                                                          { idx: { cached: true,
                                                                                                                   pushPath: false,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                                                     alignment: _descriptor_11.alignment() } },
                                                                                                                          { tag: 'stack' }] } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_4.toValue(coin_0),
                                                                                                                                                                 alignment: _descriptor_4.alignment() }).encode() } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { concat: { cached: true,
                                                                                                                      n: 91 } },
                                                                                                          { push: { storage: true,
                                                                                                                    value: __compactRuntime.StateValue.newNull().encode() } },
                                                                                                          { ins: { cached: false,
                                                                                                                   n: 1 } },
                                                                                                          { ins: { cached: true,
                                                                                                                   n: 1 } }]) : (() => { throw new __compactRuntime.CompactError(`coins.compact line 27 char 3: Coin commitment not found. Check the coin has been received (or call 'createZswapOutput')`); })();
    return [];
  }
  async _mapInsertCoin_0(context, partialProofData, k_0, coin_0, recipient_0) {
    __compactRuntime.hasCoinCommitment(context, coin_0, recipient_0) ? __compactRuntime.queryLedgerState(context,
                                                                                                         partialProofData,
                                                                                                         [
                                                                                                          { idx: { cached: false,
                                                                                                                   pushPath: true,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                                                                                                 alignment: _descriptor_0.alignment() }).encode() } },
                                                                                                          { dup: { n: 5 } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell(__compactRuntime.runtimeCoinCommitment(
                                                                                                                                                                 { value: _descriptor_4.toValue(coin_0),
                                                                                                                                                                   alignment: _descriptor_4.alignment() },
                                                                                                                                                                 { value: _descriptor_8.toValue(recipient_0),
                                                                                                                                                                   alignment: _descriptor_8.alignment() }
                                                                                                                                                               )).encode() } },
                                                                                                          { idx: { cached: true,
                                                                                                                   pushPath: false,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                                                     alignment: _descriptor_11.alignment() } },
                                                                                                                          { tag: 'stack' }] } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_4.toValue(coin_0),
                                                                                                                                                                 alignment: _descriptor_4.alignment() }).encode() } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { concat: { cached: true,
                                                                                                                      n: 91 } },
                                                                                                          { ins: { cached: false,
                                                                                                                   n: 1 } },
                                                                                                          { ins: { cached: true,
                                                                                                                   n: 1 } }]) : (() => { throw new __compactRuntime.CompactError(`coins.compact line 35 char 3: Coin commitment not found. Check the coin has been received (or call 'createZswapOutput')`); })();
    return [];
  }
  async _listPushFrontCoin_0(context, partialProofData, coin_0, recipient_0) {
    __compactRuntime.hasCoinCommitment(context, coin_0, recipient_0) ? __compactRuntime.queryLedgerState(context,
                                                                                                         partialProofData,
                                                                                                         [
                                                                                                          { idx: { cached: false,
                                                                                                                   pushPath: true,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(2n),
                                                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                                                          { dup: { n: 0 } },
                                                                                                          { idx: { cached: false,
                                                                                                                   pushPath: false,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(2n),
                                                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                                                          { addi: { immediate: 1 } },
                                                                                                          { push: { storage: true,
                                                                                                                    value: __compactRuntime.StateValue.newArray()
                                                                                                                             .arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newNull())
                                                                                                                             .encode() } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(0n),
                                                                                                                                                                 alignment: _descriptor_11.alignment() }).encode() } },
                                                                                                          { dup: { n: 7 } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell(__compactRuntime.runtimeCoinCommitment(
                                                                                                                                                                 { value: _descriptor_4.toValue(coin_0),
                                                                                                                                                                   alignment: _descriptor_4.alignment() },
                                                                                                                                                                 { value: _descriptor_8.toValue(recipient_0),
                                                                                                                                                                   alignment: _descriptor_8.alignment() }
                                                                                                                                                               )).encode() } },
                                                                                                          { idx: { cached: true,
                                                                                                                   pushPath: false,
                                                                                                                   path: [
                                                                                                                          { tag: 'value',
                                                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                                                     alignment: _descriptor_11.alignment() } },
                                                                                                                          { tag: 'stack' }] } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_4.toValue(coin_0),
                                                                                                                                                                 alignment: _descriptor_4.alignment() }).encode() } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { concat: { cached: true,
                                                                                                                      n: 91 } },
                                                                                                          { ins: { cached: true,
                                                                                                                   n: 1 } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(2n),
                                                                                                                                                                 alignment: _descriptor_11.alignment() }).encode() } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { ins: { cached: true,
                                                                                                                   n: 1 } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { push: { storage: false,
                                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(1n),
                                                                                                                                                                 alignment: _descriptor_11.alignment() }).encode() } },
                                                                                                          { swap: { n: 0 } },
                                                                                                          { ins: { cached: true,
                                                                                                                   n: 2 } }]) : (() => { throw new __compactRuntime.CompactError(`coins.compact line 42 char 3: Coin commitment not found. Check the coin has been received (or call 'createZswapOutput')`); })();
    return [];
  }
}
export function ledger(stateOrChargedState) {
  const state = stateOrChargedState instanceof __compactRuntime.StateValue ? stateOrChargedState : stateOrChargedState.state;
  const chargedState = stateOrChargedState instanceof __compactRuntime.StateValue ? new __compactRuntime.ChargedState(stateOrChargedState) : stateOrChargedState;
  const context = {
    callContext: { currentQueryContext: new __compactRuntime.QueryContext(chargedState, __compactRuntime.dummyContractAddress()), currentGasCost: __compactRuntime.emptyRunningCost() },
    costModel: __compactRuntime.CostModel.initialCostModel()
  };
  const partialProofData = {
    input: { value: [], alignment: [] },
    output: undefined,
    publicTranscript: [],
    privateTranscriptOutputs: []
  };
  return {
    s: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(0n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                                                                                 alignment: _descriptor_2.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(0n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        if (!(typeof(elem_0) === 'object' && elem_0.nonce.buffer instanceof ArrayBuffer && elem_0.nonce.BYTES_PER_ELEMENT === 1 && elem_0.nonce.length === 32 && elem_0.color.buffer instanceof ArrayBuffer && elem_0.color.BYTES_PER_ELEMENT === 1 && elem_0.color.length === 32 && typeof(elem_0.value) === 'bigint' && elem_0.value >= 0n && elem_0.value <= 340282366920938463463374607431768211455n && typeof(elem_0.mt_index) === 'bigint' && elem_0.mt_index >= 0n && elem_0.mt_index <= 18446744073709551615n)) {
          __compactRuntime.typeError('member',
                                     'argument 1',
                                     'coins.compact line 19 char 1',
                                     'struct QualifiedShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>, mt_index: Uint<0..18446744073709551616>>',
                                     elem_0)
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(0n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[0];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    m: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                                                                                 alignment: _descriptor_2.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const key_0 = args_0[0];
        if (!(key_0.buffer instanceof ArrayBuffer && key_0.BYTES_PER_ELEMENT === 1 && key_0.length === 32)) {
          __compactRuntime.typeError('member',
                                     'argument 1',
                                     'coins.compact line 20 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(key_0),
                                                                                                                                 alignment: _descriptor_0.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      lookup(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`lookup: expected 1 argument, received ${args_0.length}`);
        }
        const key_0 = args_0[0];
        if (!(key_0.buffer instanceof ArrayBuffer && key_0.BYTES_PER_ELEMENT === 1 && key_0.length === 32)) {
          __compactRuntime.typeError('lookup',
                                     'argument 1',
                                     'coins.compact line 20 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_3.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_0.toValue(key_0),
                                                                                                     alignment: _descriptor_0.alignment() } }] } },
                                                                          { popeq: { cached: false,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1];
        return self_0.asMap().keys().map(  (key) => {    const value = self_0.asMap().get(key).asCell();    return [      _descriptor_0.fromValue(key.value),      _descriptor_3.fromValue(value.value)    ];  })[Symbol.iterator]();
      }
    },
    l: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(2n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(1n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          'type',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(1n),
                                                                                                                                 alignment: _descriptor_11.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      length(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`length: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(2n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_11.toValue(2n),
                                                                                                     alignment: _descriptor_11.alignment() } }] } },
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      head(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`head: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_10.fromValue(__compactRuntime.queryLedgerState(context,
                                                                          partialProofData,
                                                                          [
                                                                           { dup: { n: 0 } },
                                                                           { idx: { cached: false,
                                                                                    pushPath: false,
                                                                                    path: [
                                                                                           { tag: 'value',
                                                                                             value: { value: _descriptor_11.toValue(2n),
                                                                                                      alignment: _descriptor_11.alignment() } }] } },
                                                                           { idx: { cached: false,
                                                                                    pushPath: false,
                                                                                    path: [
                                                                                           { tag: 'value',
                                                                                             value: { value: _descriptor_11.toValue(0n),
                                                                                                      alignment: _descriptor_11.alignment() } }] } },
                                                                           { dup: { n: 0 } },
                                                                           'type',
                                                                           { push: { storage: false,
                                                                                     value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(1n),
                                                                                                                                  alignment: _descriptor_11.alignment() }).encode() } },
                                                                           'eq',
                                                                           { branch: { skip: 4 } },
                                                                           { push: { storage: false,
                                                                                     value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(1n),
                                                                                                                                  alignment: _descriptor_11.alignment() }).encode() } },
                                                                           { swap: { n: 0 } },
                                                                           { concat: { cached: false,
                                                                                       n: (2+Number(__compactRuntime.maxAlignedSize(
                                                                                               _descriptor_3
                                                                                               .alignment()
                                                                                             ))) } },
                                                                           { jmp: { skip: 2 } },
                                                                           'pop',
                                                                           { push: { storage: false,
                                                                                     value: __compactRuntime.StateValue.newCell(__compactRuntime.alignedConcat(
                                                                                                                                  { value: _descriptor_11.toValue(0n),
                                                                                                                                    alignment: _descriptor_11.alignment() },
                                                                                                                                  { value: _descriptor_3.toValue({ nonce: new Uint8Array(32), color: new Uint8Array(32), value: 0n, mt_index: 0n }),
                                                                                                                                    alignment: _descriptor_3.alignment() }
                                                                                                                                )).encode() } },
                                                                           { popeq: { cached: true,
                                                                                      result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[2];
        return (() => {  var iter = { curr: self_0 };  iter.next = () => {    const arr = iter.curr.asArray();    const head = arr[0];    if(head.type() == "null") {      return { done: true };    } else {      iter.curr = arr[1];      return { value: _descriptor_3.fromValue(head.asCell().value), done: false };    }  };  return iter;})();
      }
    }
  };
}
const _emptyContext = {
  callContext: { currentQueryContext: new __compactRuntime.QueryContext(new __compactRuntime.ContractState().data, __compactRuntime.dummyContractAddress()), currentGasCost: __compactRuntime.emptyRunningCost() }
};
const _dummyContract = new Contract({ });
export const pureCircuits = {};
export const contractReferenceLocations =
  { tag: 'publicLedgerArray', indices: { } };
export const expectedVk = {};

//# sourceMappingURL=index.js.map
