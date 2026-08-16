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

const _descriptor_4 = __compactRuntime.CompactTypeBoolean;

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

const _descriptor_5 = new _ZswapCoinPublicKey_0();

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

const _descriptor_6 = new _ContractAddress_0();

class _Either_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_5.alignment().concat(_descriptor_6.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_4.fromValue(value_0),
      left: _descriptor_5.fromValue(value_0),
      right: _descriptor_6.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.is_left).concat(_descriptor_5.toValue(value_0.left).concat(_descriptor_6.toValue(value_0.right)));
  }
}

const _descriptor_7 = new _Either_0();

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

const _descriptor_8 = new _ShieldedCoinInfo_0();

class _Maybe_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_8.alignment());
  }
  fromValue(value_0) {
    return {
      is_some: _descriptor_4.fromValue(value_0),
      value: _descriptor_8.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.is_some).concat(_descriptor_8.toValue(value_0.value));
  }
}

const _descriptor_9 = new _Maybe_0();

class _ShieldedSendResult_0 {
  alignment() {
    return _descriptor_9.alignment().concat(_descriptor_8.alignment());
  }
  fromValue(value_0) {
    return {
      change: _descriptor_9.fromValue(value_0),
      sent: _descriptor_8.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_9.toValue(value_0.change).concat(_descriptor_8.toValue(value_0.sent));
  }
}

const _descriptor_10 = new _ShieldedSendResult_0();

class _UserAddress_0 {
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

const _descriptor_11 = new _UserAddress_0();

class _Either_1 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_6.alignment().concat(_descriptor_11.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_4.fromValue(value_0),
      left: _descriptor_6.fromValue(value_0),
      right: _descriptor_11.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.is_left).concat(_descriptor_6.toValue(value_0.left).concat(_descriptor_11.toValue(value_0.right)));
  }
}

const _descriptor_12 = new _Either_1();

class _Either_2 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_4.fromValue(value_0),
      left: _descriptor_0.fromValue(value_0),
      right: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.is_left).concat(_descriptor_0.toValue(value_0.left).concat(_descriptor_0.toValue(value_0.right)));
  }
}

const _descriptor_13 = new _Either_2();

const _descriptor_14 = __compactRuntime.CompactTypeField;

const _descriptor_15 = new __compactRuntime.CompactTypeVector(2, _descriptor_0);

const _descriptor_16 = new __compactRuntime.CompactTypeVector(2, _descriptor_14);

const _descriptor_17 = new __compactRuntime.CompactTypeBytes(21);

class _CoinPreimage_0 {
  alignment() {
    return _descriptor_17.alignment().concat(_descriptor_8.alignment().concat(_descriptor_4.alignment().concat(_descriptor_0.alignment())));
  }
  fromValue(value_0) {
    return {
      domain_sep: _descriptor_17.fromValue(value_0),
      info: _descriptor_8.fromValue(value_0),
      dataType: _descriptor_4.fromValue(value_0),
      data: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_17.toValue(value_0.domain_sep).concat(_descriptor_8.toValue(value_0.info).concat(_descriptor_4.toValue(value_0.dataType).concat(_descriptor_0.toValue(value_0.data))));
  }
}

const _descriptor_18 = new _CoinPreimage_0();

const _descriptor_19 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

const _descriptor_20 = new __compactRuntime.CompactTypeUnsignedInteger(4294967295n, 4);

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
      kMintUnshielded: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`kMintUnshielded: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const ds_0 = args_1[1];
        const amount_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kMintUnshielded',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 27 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(ds_0.buffer instanceof ArrayBuffer && ds_0.BYTES_PER_ELEMENT === 1 && ds_0.length === 32)) {
          __compactRuntime.typeError('kMintUnshielded',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 27 char 1',
                                     'Bytes<32>',
                                     ds_0)
        }
        if (!(typeof(amount_0) === 'bigint' && amount_0 >= 0n && amount_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('kMintUnshielded',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 27 char 1',
                                     'Uint<0..18446744073709551616>',
                                     amount_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(ds_0).concat(_descriptor_2.toValue(amount_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_2.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kMintUnshielded_0(context,
                                                       partialProofData,
                                                       ds_0,
                                                       amount_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kClaimUnshieldedCoinSpend: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`kClaimUnshieldedCoinSpend: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const addr_0 = args_1[2];
        const amount_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kClaimUnshieldedCoinSpend',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 31 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('kClaimUnshieldedCoinSpend',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 31 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(addr_0) === 'object' && typeof(addr_0.is_left) === 'boolean' && typeof(addr_0.left) === 'object' && addr_0.left.bytes.buffer instanceof ArrayBuffer && addr_0.left.bytes.BYTES_PER_ELEMENT === 1 && addr_0.left.bytes.length === 32 && typeof(addr_0.right) === 'object' && addr_0.right.bytes.buffer instanceof ArrayBuffer && addr_0.right.bytes.BYTES_PER_ELEMENT === 1 && addr_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('kClaimUnshieldedCoinSpend',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 31 char 1',
                                     'struct Either<is_left: Boolean, left: struct ContractAddress<bytes: Bytes<32>>, right: struct UserAddress<bytes: Bytes<32>>>',
                                     addr_0)
        }
        if (!(typeof(amount_0) === 'bigint' && amount_0 >= 0n && amount_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('kClaimUnshieldedCoinSpend',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'kernel.compact line 31 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     amount_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_12.toValue(addr_0).concat(_descriptor_1.toValue(amount_0))),
            alignment: _descriptor_0.alignment().concat(_descriptor_12.alignment().concat(_descriptor_1.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kClaimUnshieldedCoinSpend_0(context,
                                                                 partialProofData,
                                                                 color_0,
                                                                 addr_0,
                                                                 amount_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kIncUnshieldedOutputs: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`kIncUnshieldedOutputs: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const amount_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kIncUnshieldedOutputs',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 40 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('kIncUnshieldedOutputs',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 40 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(amount_0) === 'bigint' && amount_0 >= 0n && amount_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('kIncUnshieldedOutputs',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 40 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     amount_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(amount_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kIncUnshieldedOutputs_0(context,
                                                             partialProofData,
                                                             color_0,
                                                             amount_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kIncUnshieldedInputs: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`kIncUnshieldedInputs: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const amount_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kIncUnshieldedInputs',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 44 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('kIncUnshieldedInputs',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 44 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(amount_0) === 'bigint' && amount_0 >= 0n && amount_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('kIncUnshieldedInputs',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 44 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     amount_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(amount_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kIncUnshieldedInputs_0(context,
                                                            partialProofData,
                                                            color_0,
                                                            amount_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kBalance: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`kBalance: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kBalance',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 48 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('kBalance',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 48 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kBalance_0(context,
                                                partialProofData,
                                                color_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kBalanceLessThan: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`kBalanceLessThan: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const amount_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kBalanceLessThan',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 52 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('kBalanceLessThan',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 52 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(amount_0) === 'bigint' && amount_0 >= 0n && amount_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('kBalanceLessThan',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 52 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     amount_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(amount_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kBalanceLessThan_0(context,
                                                        partialProofData,
                                                        color_0,
                                                        amount_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kBalanceGreaterThan: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`kBalanceGreaterThan: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const amount_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kBalanceGreaterThan',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 56 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('kBalanceGreaterThan',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 56 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(amount_0) === 'bigint' && amount_0 >= 0n && amount_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('kBalanceGreaterThan',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 56 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     amount_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(amount_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kBalanceGreaterThan_0(context,
                                                           partialProofData,
                                                           color_0,
                                                           amount_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kBlockTimeLessThan: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`kBlockTimeLessThan: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const t_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kBlockTimeLessThan',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 60 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(t_0) === 'bigint' && t_0 >= 0n && t_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('kBlockTimeLessThan',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 60 char 1',
                                     'Uint<0..18446744073709551616>',
                                     t_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_2.toValue(t_0),
            alignment: _descriptor_2.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kBlockTimeLessThan_0(context,
                                                          partialProofData,
                                                          t_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      kBlockTimeGreaterThan: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`kBlockTimeGreaterThan: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const t_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('kBlockTimeGreaterThan',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 64 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(t_0) === 'bigint' && t_0 >= 0n && t_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('kBlockTimeGreaterThan',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 64 char 1',
                                     'Uint<0..18446744073709551616>',
                                     t_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_2.toValue(t_0),
            alignment: _descriptor_2.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._kBlockTimeGreaterThan_0(context,
                                                             partialProofData,
                                                             t_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sBlockTimeLt: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`sBlockTimeLt: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const t_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sBlockTimeLt',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 70 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(t_0) === 'bigint' && t_0 >= 0n && t_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sBlockTimeLt',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 70 char 1',
                                     'Uint<0..18446744073709551616>',
                                     t_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_2.toValue(t_0),
            alignment: _descriptor_2.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sBlockTimeLt_0(context,
                                                    partialProofData,
                                                    t_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sBlockTimeGte: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`sBlockTimeGte: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const t_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sBlockTimeGte',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 71 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(t_0) === 'bigint' && t_0 >= 0n && t_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sBlockTimeGte',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 71 char 1',
                                     'Uint<0..18446744073709551616>',
                                     t_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_2.toValue(t_0),
            alignment: _descriptor_2.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sBlockTimeGte_0(context,
                                                     partialProofData,
                                                     t_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sBlockTimeGt: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`sBlockTimeGt: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const t_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sBlockTimeGt',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 72 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(t_0) === 'bigint' && t_0 >= 0n && t_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sBlockTimeGt',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 72 char 1',
                                     'Uint<0..18446744073709551616>',
                                     t_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_2.toValue(t_0),
            alignment: _descriptor_2.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sBlockTimeGt_0(context,
                                                    partialProofData,
                                                    t_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sBlockTimeLte: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`sBlockTimeLte: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const t_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sBlockTimeLte',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 73 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(t_0) === 'bigint' && t_0 >= 0n && t_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sBlockTimeLte',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 73 char 1',
                                     'Uint<0..18446744073709551616>',
                                     t_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_2.toValue(t_0),
            alignment: _descriptor_2.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sBlockTimeLte_0(context,
                                                     partialProofData,
                                                     t_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sUnshieldedBalance: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`sUnshieldedBalance: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sUnshieldedBalance',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 75 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sUnshieldedBalance',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 75 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sUnshieldedBalance_0(context,
                                                          partialProofData,
                                                          color_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sUnshieldedBalanceLt: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sUnshieldedBalanceLt: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const a_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sUnshieldedBalanceLt',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 78 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sUnshieldedBalanceLt',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 78 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sUnshieldedBalanceLt',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 78 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     a_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(a_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sUnshieldedBalanceLt_0(context,
                                                            partialProofData,
                                                            color_0,
                                                            a_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sUnshieldedBalanceGte: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sUnshieldedBalanceGte: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const a_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sUnshieldedBalanceGte',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 81 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sUnshieldedBalanceGte',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 81 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sUnshieldedBalanceGte',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 81 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     a_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(a_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sUnshieldedBalanceGte_0(context,
                                                             partialProofData,
                                                             color_0,
                                                             a_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sUnshieldedBalanceGt: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sUnshieldedBalanceGt: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const a_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sUnshieldedBalanceGt',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 84 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sUnshieldedBalanceGt',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 84 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sUnshieldedBalanceGt',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 84 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     a_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(a_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sUnshieldedBalanceGt_0(context,
                                                            partialProofData,
                                                            color_0,
                                                            a_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sUnshieldedBalanceLte: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sUnshieldedBalanceLte: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const a_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sUnshieldedBalanceLte',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 87 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sUnshieldedBalanceLte',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 87 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sUnshieldedBalanceLte',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 87 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     a_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(a_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sUnshieldedBalanceLte_0(context,
                                                             partialProofData,
                                                             color_0,
                                                             a_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sReceiveUnshielded: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sReceiveUnshielded: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const a_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sReceiveUnshielded',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 91 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sReceiveUnshielded',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 91 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sReceiveUnshielded',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 91 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     a_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(a_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sReceiveUnshielded_0(context,
                                                          partialProofData,
                                                          color_0,
                                                          a_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sSendUnshielded: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`sSendUnshielded: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const color_0 = args_1[1];
        const a_0 = args_1[2];
        const r_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sSendUnshielded',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 95 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(color_0.buffer instanceof ArrayBuffer && color_0.BYTES_PER_ELEMENT === 1 && color_0.length === 32)) {
          __compactRuntime.typeError('sSendUnshielded',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 95 char 1',
                                     'Bytes<32>',
                                     color_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sSendUnshielded',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 95 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     a_0)
        }
        if (!(typeof(r_0) === 'object' && typeof(r_0.is_left) === 'boolean' && typeof(r_0.left) === 'object' && r_0.left.bytes.buffer instanceof ArrayBuffer && r_0.left.bytes.BYTES_PER_ELEMENT === 1 && r_0.left.bytes.length === 32 && typeof(r_0.right) === 'object' && r_0.right.bytes.buffer instanceof ArrayBuffer && r_0.right.bytes.BYTES_PER_ELEMENT === 1 && r_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('sSendUnshielded',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'kernel.compact line 95 char 1',
                                     'struct Either<is_left: Boolean, left: struct ContractAddress<bytes: Bytes<32>>, right: struct UserAddress<bytes: Bytes<32>>>',
                                     r_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(color_0).concat(_descriptor_1.toValue(a_0).concat(_descriptor_12.toValue(r_0))),
            alignment: _descriptor_0.alignment().concat(_descriptor_1.alignment().concat(_descriptor_12.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sSendUnshielded_0(context,
                                                       partialProofData,
                                                       color_0,
                                                       a_0,
                                                       r_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sMintUnshieldedToken: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`sMintUnshieldedToken: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const ds_0 = args_1[1];
        const a_0 = args_1[2];
        const r_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sMintUnshieldedToken',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 101 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(ds_0.buffer instanceof ArrayBuffer && ds_0.BYTES_PER_ELEMENT === 1 && ds_0.length === 32)) {
          __compactRuntime.typeError('sMintUnshieldedToken',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 101 char 1',
                                     'Bytes<32>',
                                     ds_0)
        }
        if (!(typeof(a_0) === 'bigint' && a_0 >= 0n && a_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('sMintUnshieldedToken',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 101 char 1',
                                     'Uint<0..18446744073709551616>',
                                     a_0)
        }
        if (!(typeof(r_0) === 'object' && typeof(r_0.is_left) === 'boolean' && typeof(r_0.left) === 'object' && r_0.left.bytes.buffer instanceof ArrayBuffer && r_0.left.bytes.BYTES_PER_ELEMENT === 1 && r_0.left.bytes.length === 32 && typeof(r_0.right) === 'object' && r_0.right.bytes.buffer instanceof ArrayBuffer && r_0.right.bytes.BYTES_PER_ELEMENT === 1 && r_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('sMintUnshieldedToken',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'kernel.compact line 101 char 1',
                                     'struct Either<is_left: Boolean, left: struct ContractAddress<bytes: Bytes<32>>, right: struct UserAddress<bytes: Bytes<32>>>',
                                     r_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(ds_0).concat(_descriptor_2.toValue(a_0).concat(_descriptor_12.toValue(r_0))),
            alignment: _descriptor_0.alignment().concat(_descriptor_2.alignment().concat(_descriptor_12.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sMintUnshieldedToken_0(context,
                                                            partialProofData,
                                                            ds_0,
                                                            a_0,
                                                            r_0);
        partialProofData.output = { value: _descriptor_0.toValue(result_0), alignment: _descriptor_0.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sMergeCoin: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sMergeCoin: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const a_0 = args_1[1];
        const b_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sMergeCoin',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 107 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(a_0) === 'object' && a_0.nonce.buffer instanceof ArrayBuffer && a_0.nonce.BYTES_PER_ELEMENT === 1 && a_0.nonce.length === 32 && a_0.color.buffer instanceof ArrayBuffer && a_0.color.BYTES_PER_ELEMENT === 1 && a_0.color.length === 32 && typeof(a_0.value) === 'bigint' && a_0.value >= 0n && a_0.value <= 340282366920938463463374607431768211455n && typeof(a_0.mt_index) === 'bigint' && a_0.mt_index >= 0n && a_0.mt_index <= 18446744073709551615n)) {
          __compactRuntime.typeError('sMergeCoin',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 107 char 1',
                                     'struct QualifiedShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>, mt_index: Uint<0..18446744073709551616>>',
                                     a_0)
        }
        if (!(typeof(b_0) === 'object' && b_0.nonce.buffer instanceof ArrayBuffer && b_0.nonce.BYTES_PER_ELEMENT === 1 && b_0.nonce.length === 32 && b_0.color.buffer instanceof ArrayBuffer && b_0.color.BYTES_PER_ELEMENT === 1 && b_0.color.length === 32 && typeof(b_0.value) === 'bigint' && b_0.value >= 0n && b_0.value <= 340282366920938463463374607431768211455n && typeof(b_0.mt_index) === 'bigint' && b_0.mt_index >= 0n && b_0.mt_index <= 18446744073709551615n)) {
          __compactRuntime.typeError('sMergeCoin',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 107 char 1',
                                     'struct QualifiedShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>, mt_index: Uint<0..18446744073709551616>>',
                                     b_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(a_0).concat(_descriptor_3.toValue(b_0)),
            alignment: _descriptor_3.alignment().concat(_descriptor_3.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sMergeCoin_0(context,
                                                  partialProofData,
                                                  a_0,
                                                  b_0);
        partialProofData.output = { value: _descriptor_8.toValue(result_0), alignment: _descriptor_8.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sMergeCoinImmediate: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`sMergeCoinImmediate: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const a_0 = args_1[1];
        const b_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sMergeCoinImmediate',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 113 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(a_0) === 'object' && a_0.nonce.buffer instanceof ArrayBuffer && a_0.nonce.BYTES_PER_ELEMENT === 1 && a_0.nonce.length === 32 && a_0.color.buffer instanceof ArrayBuffer && a_0.color.BYTES_PER_ELEMENT === 1 && a_0.color.length === 32 && typeof(a_0.value) === 'bigint' && a_0.value >= 0n && a_0.value <= 340282366920938463463374607431768211455n && typeof(a_0.mt_index) === 'bigint' && a_0.mt_index >= 0n && a_0.mt_index <= 18446744073709551615n)) {
          __compactRuntime.typeError('sMergeCoinImmediate',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 113 char 1',
                                     'struct QualifiedShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>, mt_index: Uint<0..18446744073709551616>>',
                                     a_0)
        }
        if (!(typeof(b_0) === 'object' && b_0.nonce.buffer instanceof ArrayBuffer && b_0.nonce.BYTES_PER_ELEMENT === 1 && b_0.nonce.length === 32 && b_0.color.buffer instanceof ArrayBuffer && b_0.color.BYTES_PER_ELEMENT === 1 && b_0.color.length === 32 && typeof(b_0.value) === 'bigint' && b_0.value >= 0n && b_0.value <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sMergeCoinImmediate',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 113 char 1',
                                     'struct ShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>>',
                                     b_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(a_0).concat(_descriptor_8.toValue(b_0)),
            alignment: _descriptor_3.alignment().concat(_descriptor_8.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sMergeCoinImmediate_0(context,
                                                           partialProofData,
                                                           a_0,
                                                           b_0);
        partialProofData.output = { value: _descriptor_8.toValue(result_0), alignment: _descriptor_8.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      sSendShielded: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`sSendShielded: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const input_0 = args_1[1];
        const r_0 = args_1[2];
        const v_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('sSendShielded',
                                     'argument 1 (as invoked from Typescript)',
                                     'kernel.compact line 119 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(input_0) === 'object' && input_0.nonce.buffer instanceof ArrayBuffer && input_0.nonce.BYTES_PER_ELEMENT === 1 && input_0.nonce.length === 32 && input_0.color.buffer instanceof ArrayBuffer && input_0.color.BYTES_PER_ELEMENT === 1 && input_0.color.length === 32 && typeof(input_0.value) === 'bigint' && input_0.value >= 0n && input_0.value <= 340282366920938463463374607431768211455n && typeof(input_0.mt_index) === 'bigint' && input_0.mt_index >= 0n && input_0.mt_index <= 18446744073709551615n)) {
          __compactRuntime.typeError('sSendShielded',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'kernel.compact line 119 char 1',
                                     'struct QualifiedShieldedCoinInfo<nonce: Bytes<32>, color: Bytes<32>, value: Uint<0..340282366920938463463374607431768211456>, mt_index: Uint<0..18446744073709551616>>',
                                     input_0)
        }
        if (!(typeof(r_0) === 'object' && typeof(r_0.is_left) === 'boolean' && typeof(r_0.left) === 'object' && r_0.left.bytes.buffer instanceof ArrayBuffer && r_0.left.bytes.BYTES_PER_ELEMENT === 1 && r_0.left.bytes.length === 32 && typeof(r_0.right) === 'object' && r_0.right.bytes.buffer instanceof ArrayBuffer && r_0.right.bytes.BYTES_PER_ELEMENT === 1 && r_0.right.bytes.length === 32)) {
          __compactRuntime.typeError('sSendShielded',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'kernel.compact line 119 char 1',
                                     'struct Either<is_left: Boolean, left: struct ZswapCoinPublicKey<bytes: Bytes<32>>, right: struct ContractAddress<bytes: Bytes<32>>>',
                                     r_0)
        }
        if (!(typeof(v_0) === 'bigint' && v_0 >= 0n && v_0 <= 340282366920938463463374607431768211455n)) {
          __compactRuntime.typeError('sSendShielded',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'kernel.compact line 119 char 1',
                                     'Uint<0..340282366920938463463374607431768211456>',
                                     v_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(input_0).concat(_descriptor_7.toValue(r_0).concat(_descriptor_1.toValue(v_0))),
            alignment: _descriptor_3.alignment().concat(_descriptor_7.alignment().concat(_descriptor_1.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._sSendShielded_0(context,
                                                     partialProofData,
                                                     input_0,
                                                     r_0,
                                                     v_0);
        partialProofData.output = { value: _descriptor_10.toValue(result_0), alignment: _descriptor_10.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      }
    };
    this.impureCircuits = {
      kMintUnshielded: this.circuits.kMintUnshielded,
      kClaimUnshieldedCoinSpend: this.circuits.kClaimUnshieldedCoinSpend,
      kIncUnshieldedOutputs: this.circuits.kIncUnshieldedOutputs,
      kIncUnshieldedInputs: this.circuits.kIncUnshieldedInputs,
      kBalance: this.circuits.kBalance,
      kBalanceLessThan: this.circuits.kBalanceLessThan,
      kBalanceGreaterThan: this.circuits.kBalanceGreaterThan,
      kBlockTimeLessThan: this.circuits.kBlockTimeLessThan,
      kBlockTimeGreaterThan: this.circuits.kBlockTimeGreaterThan,
      sBlockTimeLt: this.circuits.sBlockTimeLt,
      sBlockTimeGte: this.circuits.sBlockTimeGte,
      sBlockTimeGt: this.circuits.sBlockTimeGt,
      sBlockTimeLte: this.circuits.sBlockTimeLte,
      sUnshieldedBalance: this.circuits.sUnshieldedBalance,
      sUnshieldedBalanceLt: this.circuits.sUnshieldedBalanceLt,
      sUnshieldedBalanceGte: this.circuits.sUnshieldedBalanceGte,
      sUnshieldedBalanceGt: this.circuits.sUnshieldedBalanceGt,
      sUnshieldedBalanceLte: this.circuits.sUnshieldedBalanceLte,
      sReceiveUnshielded: this.circuits.sReceiveUnshielded,
      sSendUnshielded: this.circuits.sSendUnshielded,
      sMintUnshieldedToken: this.circuits.sMintUnshieldedToken,
      sMergeCoin: this.circuits.sMergeCoin,
      sMergeCoinImmediate: this.circuits.sMergeCoinImmediate,
      sSendShielded: this.circuits.sSendShielded
    };
    this.provableCircuits = {
      kMintUnshielded: this.circuits.kMintUnshielded,
      kClaimUnshieldedCoinSpend: this.circuits.kClaimUnshieldedCoinSpend,
      kIncUnshieldedOutputs: this.circuits.kIncUnshieldedOutputs,
      kIncUnshieldedInputs: this.circuits.kIncUnshieldedInputs,
      kBalance: this.circuits.kBalance,
      kBalanceLessThan: this.circuits.kBalanceLessThan,
      kBalanceGreaterThan: this.circuits.kBalanceGreaterThan,
      kBlockTimeLessThan: this.circuits.kBlockTimeLessThan,
      kBlockTimeGreaterThan: this.circuits.kBlockTimeGreaterThan,
      sBlockTimeLt: this.circuits.sBlockTimeLt,
      sBlockTimeGte: this.circuits.sBlockTimeGte,
      sBlockTimeGt: this.circuits.sBlockTimeGt,
      sBlockTimeLte: this.circuits.sBlockTimeLte,
      sUnshieldedBalance: this.circuits.sUnshieldedBalance,
      sUnshieldedBalanceLt: this.circuits.sUnshieldedBalanceLt,
      sUnshieldedBalanceGte: this.circuits.sUnshieldedBalanceGte,
      sUnshieldedBalanceGt: this.circuits.sUnshieldedBalanceGt,
      sUnshieldedBalanceLte: this.circuits.sUnshieldedBalanceLte,
      sReceiveUnshielded: this.circuits.sReceiveUnshielded,
      sSendUnshielded: this.circuits.sSendUnshielded,
      sMintUnshieldedToken: this.circuits.sMintUnshieldedToken,
      sMergeCoin: this.circuits.sMergeCoin,
      sMergeCoinImmediate: this.circuits.sMergeCoinImmediate,
      sSendShielded: this.circuits.sSendShielded
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
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    state_0.setOperation('kMintUnshielded', new __compactRuntime.ContractOperation());
    state_0.setOperation('kClaimUnshieldedCoinSpend', new __compactRuntime.ContractOperation());
    state_0.setOperation('kIncUnshieldedOutputs', new __compactRuntime.ContractOperation());
    state_0.setOperation('kIncUnshieldedInputs', new __compactRuntime.ContractOperation());
    state_0.setOperation('kBalance', new __compactRuntime.ContractOperation());
    state_0.setOperation('kBalanceLessThan', new __compactRuntime.ContractOperation());
    state_0.setOperation('kBalanceGreaterThan', new __compactRuntime.ContractOperation());
    state_0.setOperation('kBlockTimeLessThan', new __compactRuntime.ContractOperation());
    state_0.setOperation('kBlockTimeGreaterThan', new __compactRuntime.ContractOperation());
    state_0.setOperation('sBlockTimeLt', new __compactRuntime.ContractOperation());
    state_0.setOperation('sBlockTimeGte', new __compactRuntime.ContractOperation());
    state_0.setOperation('sBlockTimeGt', new __compactRuntime.ContractOperation());
    state_0.setOperation('sBlockTimeLte', new __compactRuntime.ContractOperation());
    state_0.setOperation('sUnshieldedBalance', new __compactRuntime.ContractOperation());
    state_0.setOperation('sUnshieldedBalanceLt', new __compactRuntime.ContractOperation());
    state_0.setOperation('sUnshieldedBalanceGte', new __compactRuntime.ContractOperation());
    state_0.setOperation('sUnshieldedBalanceGt', new __compactRuntime.ContractOperation());
    state_0.setOperation('sUnshieldedBalanceLte', new __compactRuntime.ContractOperation());
    state_0.setOperation('sReceiveUnshielded', new __compactRuntime.ContractOperation());
    state_0.setOperation('sSendUnshielded', new __compactRuntime.ContractOperation());
    state_0.setOperation('sMintUnshieldedToken', new __compactRuntime.ContractOperation());
    state_0.setOperation('sMergeCoin', new __compactRuntime.ContractOperation());
    state_0.setOperation('sMergeCoinImmediate', new __compactRuntime.ContractOperation());
    state_0.setOperation('sSendShielded', new __compactRuntime.ContractOperation());
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
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_19.toValue(0n),
                                                                                              alignment: _descriptor_19.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(0n),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    state_0.data = new __compactRuntime.ChargedState(context.callContext.currentQueryContext.state.state);
    return {
      currentContractState: state_0,
      currentPrivateState: context.callContext.currentPrivateState,
      currentZswapLocalState: context.callContext.currentZswapLocalState
    }
  }
  _some_0(value_0) { return { is_some: true, value: value_0 }; }
  _none_0() {
    return { is_some: false,
             value:
               { nonce: new Uint8Array(32), color: new Uint8Array(32), value: 0n } };
  }
  _left_0(value_0) {
    return { is_left: true, left: value_0, right: new Uint8Array(32) };
  }
  _right_0(value_0) {
    return { is_left: false, left: { bytes: new Uint8Array(32) }, right: value_0 };
  }
  _tokenType_0(domain_sep_0, contractAddress_0) {
    return this._persistentCommit_0([domain_sep_0, contractAddress_0.bytes],
                                    new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 100, 101, 114, 105, 118, 101, 95, 116, 111, 107, 101, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
  }
  async _sendShielded_0(context, partialProofData, input_0, recipient_0, value_0)
  {
    const selfAddr_0 = _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                 partialProofData,
                                                                                 [
                                                                                  { dup: { n: 2 } },
                                                                                  { idx: { cached: true,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_19.toValue(0n),
                                                                                                             alignment: _descriptor_19.alignment() } }] } },
                                                                                  { popeq: { cached: true,
                                                                                             result: undefined } }]).value);
    this._createZswapInput_0(context, partialProofData, input_0);
    const tmp_0 = this._coinNullifier_0(this._downcastQualifiedCoin_0(input_0),
                                        selfAddr_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(0n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(tmp_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    let t_0;
    const change_0 = (t_0 = input_0.value,
                      (__compactRuntime.assert(t_0 >= value_0,
                                               'result of subtraction would be negative'),
                       t_0 - value_0));
    const output_0 = { nonce:
                         this._upgradeFromTransient_0(this._transientHash_0([__compactRuntime.convertBytesToUint(52435875175126190479447740508185965837690552500527637822603658699938581184512n,
                                                                                                                 28,
                                                                                                                 new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 107, 101, 114, 110, 101, 108, 58, 110, 111, 110, 99, 101, 95, 101, 118, 111, 108, 118, 101]),
                                                                                                                 'Field',
                                                                                                                 '<standard library>'),
                                                                             this._degradeToTransient_0(input_0.nonce)])),
                       color: input_0.color,
                       value: value_0 };
    this._createZswapOutput_0(context, partialProofData, output_0, recipient_0);
    const tmp_1 = this._coinCommitment_0(output_0, recipient_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(2n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(tmp_1),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    if (!recipient_0.is_left
        &&
        this._equal_0(recipient_0.right.bytes, selfAddr_0.bytes))
    {
      const tmp_2 = this._coinCommitment_0(output_0, recipient_0);
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { swap: { n: 0 } },
                                         { idx: { cached: true,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_19.toValue(1n),
                                                                    alignment: _descriptor_19.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(tmp_2),
                                                                                                alignment: _descriptor_0.alignment() }).encode() } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newNull().encode() } },
                                         { ins: { cached: true, n: 2 } },
                                         { swap: { n: 0 } }]);
    }
    if (change_0 === 0n) {
      return { change: this._none_0(), sent: output_0 };
    } else {
      const changeCoin_0 = { nonce:
                               this._upgradeFromTransient_0(this._transientHash_0([__compactRuntime.convertBytesToUint(52435875175126190479447740508185965837690552500527637822603658699938581184512n,
                                                                                                                       30,
                                                                                                                       new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 107, 101, 114, 110, 101, 108, 58, 110, 111, 110, 99, 101, 95, 101, 118, 111, 108, 118, 101, 47, 50]),
                                                                                                                       'Field',
                                                                                                                       '<standard library>'),
                                                                                   this._degradeToTransient_0(input_0.nonce)])),
                             color: input_0.color,
                             value: change_0 };
      this._createZswapOutput_0(context,
                                partialProofData,
                                changeCoin_0,
                                this._right_0(selfAddr_0));
      const cm_0 = this._coinCommitment_0(changeCoin_0,
                                          this._right_0(selfAddr_0));
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { swap: { n: 0 } },
                                         { idx: { cached: true,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_19.toValue(2n),
                                                                    alignment: _descriptor_19.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(cm_0),
                                                                                                alignment: _descriptor_0.alignment() }).encode() } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newNull().encode() } },
                                         { ins: { cached: true, n: 2 } },
                                         { swap: { n: 0 } }]);
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { swap: { n: 0 } },
                                         { idx: { cached: true,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_19.toValue(1n),
                                                                    alignment: _descriptor_19.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(cm_0),
                                                                                                alignment: _descriptor_0.alignment() }).encode() } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newNull().encode() } },
                                         { ins: { cached: true, n: 2 } },
                                         { swap: { n: 0 } }]);
      return { change: this._some_0(changeCoin_0), sent: output_0 };
    }
  }
  async _mergeCoin_0(context, partialProofData, a_0, b_0) {
    const selfAddr_0 = _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                 partialProofData,
                                                                                 [
                                                                                  { dup: { n: 2 } },
                                                                                  { idx: { cached: true,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_19.toValue(0n),
                                                                                                             alignment: _descriptor_19.alignment() } }] } },
                                                                                  { popeq: { cached: true,
                                                                                             result: undefined } }]).value);
    this._createZswapInput_0(context, partialProofData, a_0);
    const tmp_0 = this._coinNullifier_0(this._downcastQualifiedCoin_0(a_0),
                                        selfAddr_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(0n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(tmp_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    this._createZswapInput_0(context, partialProofData, b_0);
    const tmp_1 = this._coinNullifier_0(this._downcastQualifiedCoin_0(b_0),
                                        selfAddr_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(0n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(tmp_1),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    __compactRuntime.assert(this._equal_1(a_0.color, b_0.color),
                            'Can only merge coins of the same color');
    const newCoin_0 = { nonce:
                          this._upgradeFromTransient_0(this._transientHash_0([__compactRuntime.convertBytesToUint(52435875175126190479447740508185965837690552500527637822603658699938581184512n,
                                                                                                                  28,
                                                                                                                  new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 107, 101, 114, 110, 101, 108, 58, 110, 111, 110, 99, 101, 95, 101, 118, 111, 108, 118, 101]),
                                                                                                                  'Field',
                                                                                                                  '<standard library>'),
                                                                              this._degradeToTransient_0(a_0.nonce)])),
                        color: a_0.color,
                        value:
                          ((t1) => {
                            if (t1 > 340282366920938463463374607431768211455n) {
                              throw new __compactRuntime.CompactError('<standard library>: cast from Field or Uint value to smaller Uint value failed: ' + t1 + ' is greater than 340282366920938463463374607431768211455');
                            }
                            return t1;
                          })(a_0.value + b_0.value) };
    this._createZswapOutput_0(context,
                              partialProofData,
                              newCoin_0,
                              this._right_0(selfAddr_0));
    const cm_0 = this._coinCommitment_0(newCoin_0, this._right_0(selfAddr_0));
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(2n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(cm_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(1n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(cm_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    return newCoin_0;
  }
  async _mergeCoinImmediate_0(context, partialProofData, a_0, b_0) {
    return await this._mergeCoin_0(context,
                                   partialProofData,
                                   a_0,
                                   this._upcastQualifiedCoin_0(b_0));
  }
  _downcastQualifiedCoin_0(coin_0) {
    return { nonce: coin_0.nonce, color: coin_0.color, value: coin_0.value };
  }
  _upcastQualifiedCoin_0(coin_0) {
    return { nonce: coin_0.nonce,
             color: coin_0.color,
             value: coin_0.value,
             mt_index: 0n };
  }
  _coinCommitment_0(coin_0, recipient_0) {
    return this._persistentHash_0({ domain_sep:
                                      new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 122, 115, 119, 97, 112, 45, 99, 99, 91, 118, 49, 93]),
                                    info: coin_0,
                                    dataType: recipient_0.is_left,
                                    data:
                                      recipient_0.is_left ?
                                      recipient_0.left.bytes :
                                      recipient_0.right.bytes });
  }
  _coinNullifier_0(coin_0, addr_0) {
    return this._persistentHash_0({ domain_sep:
                                      new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 122, 115, 119, 97, 112, 45, 99, 110, 91, 118, 49, 93]),
                                    info: coin_0,
                                    dataType: false,
                                    data: addr_0.bytes });
  }
  async _blockTimeLt_0(context, partialProofData, time_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 2 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(2n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(time_0),
                                                                                                                             alignment: _descriptor_2.alignment() }).encode() } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _blockTimeGte_0(context, partialProofData, time_0) {
    return !await this._blockTimeLt_0(context, partialProofData, time_0);
  }
  async _blockTimeGt_0(context, partialProofData, time_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(time_0),
                                                                                                                             alignment: _descriptor_2.alignment() }).encode() } },
                                                                      { dup: { n: 3 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(2n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _blockTimeLte_0(context, partialProofData, time_0) {
    return !await this._blockTimeGt_0(context, partialProofData, time_0);
  }
  async _mintUnshieldedToken_0(context,
                               partialProofData,
                               domainSep_0,
                               amount_0,
                               recipient_0)
  {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(5n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(domainSep_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(amount_0),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    const color_0 = this._tokenType_0(domainSep_0,
                                      _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                partialProofData,
                                                                                                [
                                                                                                 { dup: { n: 2 } },
                                                                                                 { idx: { cached: true,
                                                                                                          pushPath: false,
                                                                                                          path: [
                                                                                                                 { tag: 'value',
                                                                                                                   value: { value: _descriptor_19.toValue(0n),
                                                                                                                            alignment: _descriptor_19.alignment() } }] } },
                                                                                                 { popeq: { cached: true,
                                                                                                            result: undefined } }]).value));
    const tmp_0 = this._left_0(color_0);
    const tmp_1 = amount_0;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(8n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell(__compactRuntime.alignedConcat(
                                                                                              { value: _descriptor_13.toValue(tmp_0),
                                                                                                alignment: _descriptor_13.alignment() },
                                                                                              { value: _descriptor_12.toValue(recipient_0),
                                                                                                alignment: _descriptor_12.alignment() }
                                                                                            )).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(tmp_1),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    if (recipient_0.is_left
        &&
        this._equal_2(recipient_0.left.bytes,
                      _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                partialProofData,
                                                                                [
                                                                                 { dup: { n: 2 } },
                                                                                 { idx: { cached: true,
                                                                                          pushPath: false,
                                                                                          path: [
                                                                                                 { tag: 'value',
                                                                                                   value: { value: _descriptor_19.toValue(0n),
                                                                                                            alignment: _descriptor_19.alignment() } }] } },
                                                                                 { popeq: { cached: true,
                                                                                            result: undefined } }]).value).bytes))
    {
      const tmp_2 = this._left_0(color_0);
      const tmp_3 = amount_0;
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { swap: { n: 0 } },
                                         { idx: { cached: true,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_19.toValue(6n),
                                                                    alignment: _descriptor_19.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_2),
                                                                                                alignment: _descriptor_13.alignment() }).encode() } },
                                         { dup: { n: 1 } },
                                         { dup: { n: 1 } },
                                         'member',
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(tmp_3),
                                                                                                alignment: _descriptor_1.alignment() }).encode() } },
                                         { swap: { n: 0 } },
                                         'neg',
                                         { branch: { skip: 4 } },
                                         { dup: { n: 2 } },
                                         { dup: { n: 2 } },
                                         { idx: { cached: true,
                                                  pushPath: false,
                                                  path: [ { tag: 'stack' }] } },
                                         'add',
                                         { ins: { cached: true, n: 2 } },
                                         { swap: { n: 0 } }]);
    }
    return color_0;
  }
  async _sendUnshielded_0(context,
                          partialProofData,
                          color_0,
                          amount_0,
                          recipient_0)
  {
    const tmp_0 = this._left_0(color_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(7n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                              alignment: _descriptor_13.alignment() }).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    const tmp_1 = this._left_0(color_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(8n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell(__compactRuntime.alignedConcat(
                                                                                              { value: _descriptor_13.toValue(tmp_1),
                                                                                                alignment: _descriptor_13.alignment() },
                                                                                              { value: _descriptor_12.toValue(recipient_0),
                                                                                                alignment: _descriptor_12.alignment() }
                                                                                            )).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    if (recipient_0.is_left
        &&
        this._equal_3(recipient_0.left.bytes,
                      _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                partialProofData,
                                                                                [
                                                                                 { dup: { n: 2 } },
                                                                                 { idx: { cached: true,
                                                                                          pushPath: false,
                                                                                          path: [
                                                                                                 { tag: 'value',
                                                                                                   value: { value: _descriptor_19.toValue(0n),
                                                                                                            alignment: _descriptor_19.alignment() } }] } },
                                                                                 { popeq: { cached: true,
                                                                                            result: undefined } }]).value).bytes))
    {
      const tmp_2 = this._left_0(color_0);
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { swap: { n: 0 } },
                                         { idx: { cached: true,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_19.toValue(6n),
                                                                    alignment: _descriptor_19.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_2),
                                                                                                alignment: _descriptor_13.alignment() }).encode() } },
                                         { dup: { n: 1 } },
                                         { dup: { n: 1 } },
                                         'member',
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                                alignment: _descriptor_1.alignment() }).encode() } },
                                         { swap: { n: 0 } },
                                         'neg',
                                         { branch: { skip: 4 } },
                                         { dup: { n: 2 } },
                                         { dup: { n: 2 } },
                                         { idx: { cached: true,
                                                  pushPath: false,
                                                  path: [ { tag: 'stack' }] } },
                                         'add',
                                         { ins: { cached: true, n: 2 } },
                                         { swap: { n: 0 } }]);
    }
    return [];
  }
  async _receiveUnshielded_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(6n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                              alignment: _descriptor_13.alignment() }).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    return [];
  }
  async _unshieldedBalance_0(context, partialProofData, color_0) {
    const tmp_0 = this._left_0(color_0);
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 2 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(5n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                                                             alignment: _descriptor_13.alignment() }).encode() } },
                                                                      'member',
                                                                      { branch: { skip: 3 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { jmp: { skip: 1 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_13.toValue(tmp_0),
                                                                                                 alignment: _descriptor_13.alignment() } }] } },
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _unshieldedBalanceLt_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 2 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(5n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                                                             alignment: _descriptor_13.alignment() }).encode() } },
                                                                      'member',
                                                                      { branch: { skip: 3 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { jmp: { skip: 1 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_13.toValue(tmp_0),
                                                                                                 alignment: _descriptor_13.alignment() } }] } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _unshieldedBalanceGte_0(context, partialProofData, color_0, amount_0) {
    return !await this._unshieldedBalanceLt_0(context,
                                              partialProofData,
                                              color_0,
                                              amount_0);
  }
  async _unshieldedBalanceGt_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { dup: { n: 3 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(5n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                                                             alignment: _descriptor_13.alignment() }).encode() } },
                                                                      'member',
                                                                      { branch: { skip: 3 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { jmp: { skip: 1 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_13.toValue(tmp_0),
                                                                                                 alignment: _descriptor_13.alignment() } }] } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _unshieldedBalanceLte_0(context, partialProofData, color_0, amount_0) {
    return !await this._unshieldedBalanceGt_0(context,
                                              partialProofData,
                                              color_0,
                                              amount_0);
  }
  _transientHash_0(value_0) {
    const result_0 = __compactRuntime.transientHash(_descriptor_16, value_0);
    return result_0;
  }
  _persistentHash_0(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_18, value_0);
    return result_0;
  }
  _persistentCommit_0(value_0, rand_0) {
    const result_0 = __compactRuntime.persistentCommit(_descriptor_15,
                                                       value_0,
                                                       rand_0);
    return result_0;
  }
  _degradeToTransient_0(x_0) {
    const result_0 = __compactRuntime.degradeToTransient(x_0);
    return result_0;
  }
  _upgradeFromTransient_0(x_0) {
    const result_0 = __compactRuntime.upgradeFromTransient(x_0);
    return result_0;
  }
  _createZswapInput_0(context, partialProofData, coin_0) {
    const result_0 = __compactRuntime.createZswapInput(context, coin_0);
    partialProofData.privateTranscriptOutputs.push({
      value: [],
      alignment: []
    });
    return result_0;
  }
  _createZswapOutput_0(context, partialProofData, coin_0, recipient_0) {
    const result_0 = __compactRuntime.createZswapOutput(context,
                                                        coin_0,
                                                        recipient_0);
    partialProofData.privateTranscriptOutputs.push({
      value: [],
      alignment: []
    });
    return result_0;
  }
  async _kMintUnshielded_0(context, partialProofData, ds_0, amount_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(5n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(ds_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(amount_0),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    return [];
  }
  async _kClaimUnshieldedCoinSpend_0(context,
                                     partialProofData,
                                     color_0,
                                     addr_0,
                                     amount_0)
  {
    const tmp_0 = this._left_0(color_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(8n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell(__compactRuntime.alignedConcat(
                                                                                              { value: _descriptor_13.toValue(tmp_0),
                                                                                                alignment: _descriptor_13.alignment() },
                                                                                              { value: _descriptor_12.toValue(addr_0),
                                                                                                alignment: _descriptor_12.alignment() }
                                                                                            )).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    return [];
  }
  async _kIncUnshieldedOutputs_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(7n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                              alignment: _descriptor_13.alignment() }).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    return [];
  }
  async _kIncUnshieldedInputs_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { swap: { n: 0 } },
                                       { idx: { cached: true,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_19.toValue(6n),
                                                                  alignment: _descriptor_19.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                              alignment: _descriptor_13.alignment() }).encode() } },
                                       { dup: { n: 1 } },
                                       { dup: { n: 1 } },
                                       'member',
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       'neg',
                                       { branch: { skip: 4 } },
                                       { dup: { n: 2 } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: true,
                                                pushPath: false,
                                                path: [ { tag: 'stack' }] } },
                                       'add',
                                       { ins: { cached: true, n: 2 } },
                                       { swap: { n: 0 } }]);
    return [];
  }
  async _kBalance_0(context, partialProofData, color_0) {
    const tmp_0 = this._left_0(color_0);
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 2 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(5n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                                                             alignment: _descriptor_13.alignment() }).encode() } },
                                                                      'member',
                                                                      { branch: { skip: 3 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { jmp: { skip: 1 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_13.toValue(tmp_0),
                                                                                                 alignment: _descriptor_13.alignment() } }] } },
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _kBalanceLessThan_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 2 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(5n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                                                             alignment: _descriptor_13.alignment() }).encode() } },
                                                                      'member',
                                                                      { branch: { skip: 3 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { jmp: { skip: 1 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_13.toValue(tmp_0),
                                                                                                 alignment: _descriptor_13.alignment() } }] } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _kBalanceGreaterThan_0(context, partialProofData, color_0, amount_0) {
    const tmp_0 = this._left_0(color_0);
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(amount_0),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { dup: { n: 3 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(5n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_13.toValue(tmp_0),
                                                                                                                             alignment: _descriptor_13.alignment() }).encode() } },
                                                                      'member',
                                                                      { branch: { skip: 3 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      { jmp: { skip: 1 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_13.toValue(tmp_0),
                                                                                                 alignment: _descriptor_13.alignment() } }] } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _kBlockTimeLessThan_0(context, partialProofData, t_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 2 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(2n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(t_0),
                                                                                                                             alignment: _descriptor_2.alignment() }).encode() } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _kBlockTimeGreaterThan_0(context, partialProofData, t_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(t_0),
                                                                                                                             alignment: _descriptor_2.alignment() }).encode() } },
                                                                      { dup: { n: 3 } },
                                                                      { idx: { cached: true,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_19.toValue(2n),
                                                                                                 alignment: _descriptor_19.alignment() } }] } },
                                                                      'lt',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _sBlockTimeLt_0(context, partialProofData, t_0) {
    return await this._blockTimeLt_0(context, partialProofData, t_0);
  }
  async _sBlockTimeGte_0(context, partialProofData, t_0) {
    return await this._blockTimeGte_0(context, partialProofData, t_0);
  }
  async _sBlockTimeGt_0(context, partialProofData, t_0) {
    return await this._blockTimeGt_0(context, partialProofData, t_0);
  }
  async _sBlockTimeLte_0(context, partialProofData, t_0) {
    return await this._blockTimeLte_0(context, partialProofData, t_0);
  }
  async _sUnshieldedBalance_0(context, partialProofData, color_0) {
    return await this._unshieldedBalance_0(context, partialProofData, color_0);
  }
  async _sUnshieldedBalanceLt_0(context, partialProofData, color_0, a_0) {
    return await this._unshieldedBalanceLt_0(context,
                                             partialProofData,
                                             color_0,
                                             a_0);
  }
  async _sUnshieldedBalanceGte_0(context, partialProofData, color_0, a_0) {
    return await this._unshieldedBalanceGte_0(context,
                                              partialProofData,
                                              color_0,
                                              a_0);
  }
  async _sUnshieldedBalanceGt_0(context, partialProofData, color_0, a_0) {
    return await this._unshieldedBalanceGt_0(context,
                                             partialProofData,
                                             color_0,
                                             a_0);
  }
  async _sUnshieldedBalanceLte_0(context, partialProofData, color_0, a_0) {
    return await this._unshieldedBalanceLte_0(context,
                                              partialProofData,
                                              color_0,
                                              a_0);
  }
  async _sReceiveUnshielded_0(context, partialProofData, color_0, a_0) {
    await this._receiveUnshielded_0(context, partialProofData, color_0, a_0);
    return [];
  }
  async _sSendUnshielded_0(context, partialProofData, color_0, a_0, r_0) {
    await this._sendUnshielded_0(context, partialProofData, color_0, a_0, r_0);
    return [];
  }
  async _sMintUnshieldedToken_0(context, partialProofData, ds_0, a_0, r_0) {
    return await this._mintUnshieldedToken_0(context,
                                             partialProofData,
                                             ds_0,
                                             a_0,
                                             r_0);
  }
  async _sMergeCoin_0(context, partialProofData, a_0, b_0) {
    return await this._mergeCoin_0(context, partialProofData, a_0, b_0);
  }
  async _sMergeCoinImmediate_0(context, partialProofData, a_0, b_0) {
    return await this._mergeCoinImmediate_0(context, partialProofData, a_0, b_0);
  }
  async _sSendShielded_0(context, partialProofData, input_0, r_0, v_0) {
    return await this._sendShielded_0(context,
                                      partialProofData,
                                      input_0,
                                      r_0,
                                      v_0);
  }
  _equal_0(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_1(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_2(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_3(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
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
    get dummy() {
      return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_19.toValue(0n),
                                                                                                   alignment: _descriptor_19.alignment() } }] } },
                                                                        { popeq: { cached: true,
                                                                                   result: undefined } }]).value);
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
