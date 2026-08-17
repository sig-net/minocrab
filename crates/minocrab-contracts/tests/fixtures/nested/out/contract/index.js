import * as __compactRuntime from '@midnight-ntwrk/compact-runtime';
__compactRuntime.checkRuntimeVersion('0.18.0-rc.1');

const _descriptor_0 = new __compactRuntime.CompactTypeBytes(32);

const _descriptor_1 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

const _descriptor_2 = __compactRuntime.CompactTypeField;

class _MerkleTreeDigest_0 {
  alignment() {
    return _descriptor_2.alignment();
  }
  fromValue(value_0) {
    return {
      field: _descriptor_2.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_2.toValue(value_0.field);
  }
}

const _descriptor_3 = new _MerkleTreeDigest_0();

const _descriptor_4 = __compactRuntime.CompactTypeBoolean;

const _descriptor_5 = new __compactRuntime.CompactTypeUnsignedInteger(65535n, 2);

class _Maybe_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_0.alignment());
  }
  fromValue(value_0) {
    return {
      is_some: _descriptor_4.fromValue(value_0),
      value: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.is_some).concat(_descriptor_0.toValue(value_0.value));
  }
}

const _descriptor_6 = new _Maybe_0();

class _Either_0 {
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

const _descriptor_7 = new _Either_0();

const _descriptor_8 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

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

const _descriptor_9 = new _ContractAddress_0();

const _descriptor_10 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

const _descriptor_11 = new __compactRuntime.CompactTypeUnsignedInteger(4294967295n, 4);

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
      mapInsert: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`mapInsert: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        const v_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapInsert',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 51 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapInsert',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 51 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('mapInsert',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 51 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        if (!(typeof(v_0) === 'bigint' && v_0 >= 0n && v_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('mapInsert',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'nested.compact line 51 char 1',
                                     'Uint<0..18446744073709551616>',
                                     v_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0).concat(_descriptor_1.toValue(v_0))),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_1.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapInsert_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 k2_0,
                                                 v_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapInsertDefault: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`mapInsertDefault: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapInsertDefault',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 55 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapInsertDefault',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 55 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('mapInsertDefault',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 55 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapInsertDefault_0(context,
                                                        partialProofData,
                                                        k_0,
                                                        k2_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapLookup: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`mapLookup: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapLookup',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 59 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapLookup',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 59 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('mapLookup',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 59 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapLookup_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 k2_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapMember: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`mapMember: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapMember',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 63 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapMember',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 63 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('mapMember',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 63 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapMember_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 k2_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapRemove: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`mapRemove: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapRemove',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 67 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapRemove',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 67 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('mapRemove',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 67 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapRemove_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 k2_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapSize: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`mapSize: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapSize',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 71 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapSize',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 71 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapSize_0(context, partialProofData, k_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapIsEmpty: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`mapIsEmpty: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapIsEmpty',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 75 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapIsEmpty',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 75 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapIsEmpty_0(context, partialProofData, k_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mapReset: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`mapReset: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mapReset',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 79 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mapReset',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 79 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mapReset_0(context, partialProofData, k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      outerInsertDefault: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`outerInsertDefault: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('outerInsertDefault',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 87 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('outerInsertDefault',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 87 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._outerInsertDefault_0(context,
                                                          partialProofData,
                                                          k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listPushFront: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`listPushFront: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const v_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listPushFront',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 93 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('listPushFront',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 93 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(v_0.buffer instanceof ArrayBuffer && v_0.BYTES_PER_ELEMENT === 1 && v_0.length === 32)) {
          __compactRuntime.typeError('listPushFront',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 93 char 1',
                                     'Bytes<32>',
                                     v_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(v_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listPushFront_0(context,
                                                     partialProofData,
                                                     k_0,
                                                     v_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listPopFront: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`listPopFront: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listPopFront',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 97 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('listPopFront',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 97 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listPopFront_0(context,
                                                    partialProofData,
                                                    k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listLength: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`listLength: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listLength',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 101 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('listLength',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 101 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listLength_0(context, partialProofData, k_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listHead: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`listHead: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listHead',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 105 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('listHead',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 105 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listHead_0(context, partialProofData, k_0);
        partialProofData.output = { value: _descriptor_6.toValue(result_0), alignment: _descriptor_6.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listIsEmpty: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`listIsEmpty: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listIsEmpty',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 109 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('listIsEmpty',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 109 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listIsEmpty_0(context,
                                                   partialProofData,
                                                   k_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      listReset: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`listReset: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('listReset',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 113 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('listReset',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 113 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._listReset_0(context, partialProofData, k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      setInsert: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`setInsert: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const e_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('setInsert',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 119 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('setInsert',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 119 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(e_0.buffer instanceof ArrayBuffer && e_0.BYTES_PER_ELEMENT === 1 && e_0.length === 32)) {
          __compactRuntime.typeError('setInsert',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 119 char 1',
                                     'Bytes<32>',
                                     e_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(e_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._setInsert_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 e_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      setRemove: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`setRemove: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const e_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('setRemove',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 123 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('setRemove',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 123 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(e_0.buffer instanceof ArrayBuffer && e_0.BYTES_PER_ELEMENT === 1 && e_0.length === 32)) {
          __compactRuntime.typeError('setRemove',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 123 char 1',
                                     'Bytes<32>',
                                     e_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(e_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._setRemove_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 e_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      setMember: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`setMember: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const e_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('setMember',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 127 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('setMember',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 127 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(e_0.buffer instanceof ArrayBuffer && e_0.BYTES_PER_ELEMENT === 1 && e_0.length === 32)) {
          __compactRuntime.typeError('setMember',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 127 char 1',
                                     'Bytes<32>',
                                     e_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(e_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._setMember_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 e_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      setReset: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`setReset: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('setReset',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 135 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('setReset',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 135 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._setReset_0(context, partialProofData, k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      counterIncrement: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`counterIncrement: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('counterIncrement',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 141 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('counterIncrement',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 141 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._counterIncrement_0(context,
                                                        partialProofData,
                                                        k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      counterRead: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`counterRead: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('counterRead',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 145 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('counterRead',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 145 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._counterRead_0(context,
                                                   partialProofData,
                                                   k_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      counterReset: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`counterReset: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('counterReset',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 149 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('counterReset',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 149 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._counterReset_0(context,
                                                    partialProofData,
                                                    k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mtInsert: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`mtInsert: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const item_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mtInsert',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 158 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mtInsert',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 158 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(item_0.buffer instanceof ArrayBuffer && item_0.BYTES_PER_ELEMENT === 1 && item_0.length === 32)) {
          __compactRuntime.typeError('mtInsert',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 158 char 1',
                                     'Bytes<32>',
                                     item_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(item_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mtInsert_0(context,
                                                partialProofData,
                                                k_0,
                                                item_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mtCheckRoot: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`mtCheckRoot: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const rt_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mtCheckRoot',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 162 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mtCheckRoot',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 162 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(typeof(rt_0) === 'object' && typeof(rt_0.field) === 'bigint' && rt_0.field >= 0 && rt_0.field <= __compactRuntime.MAX_FIELD)) {
          __compactRuntime.typeError('mtCheckRoot',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 162 char 1',
                                     'struct MerkleTreeDigest<field: Field>',
                                     rt_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_3.toValue(rt_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_3.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mtCheckRoot_0(context,
                                                   partialProofData,
                                                   k_0,
                                                   rt_0);
        partialProofData.output = { value: _descriptor_4.toValue(result_0), alignment: _descriptor_4.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      mtReset: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`mtReset: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('mtReset',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 169 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('mtReset',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 169 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._mtReset_0(context, partialProofData, k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      hmtInsert: async (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`hmtInsert: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const item_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('hmtInsert',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 173 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('hmtInsert',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 173 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(item_0.buffer instanceof ArrayBuffer && item_0.BYTES_PER_ELEMENT === 1 && item_0.length === 32)) {
          __compactRuntime.typeError('hmtInsert',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 173 char 1',
                                     'Bytes<32>',
                                     item_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(item_0)),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._hmtInsert_0(context,
                                                 partialProofData,
                                                 k_0,
                                                 item_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      hmtResetHistory: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`hmtResetHistory: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('hmtResetHistory',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 177 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('hmtResetHistory',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 177 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._hmtResetHistory_0(context,
                                                       partialProofData,
                                                       k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      hmtReset: async (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`hmtReset: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('hmtReset',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 181 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('hmtReset',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 181 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0),
            alignment: _descriptor_0.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._hmtReset_0(context, partialProofData, k_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      deepInsert: async (...args_1) => {
        if (args_1.length !== 5) {
          throw new __compactRuntime.CompactError(`deepInsert: expected 5 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        const k3_0 = args_1[3];
        const v_0 = args_1[4];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('deepInsert',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 190 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('deepInsert',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 190 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('deepInsert',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 190 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        if (!(k3_0.buffer instanceof ArrayBuffer && k3_0.BYTES_PER_ELEMENT === 1 && k3_0.length === 32)) {
          __compactRuntime.typeError('deepInsert',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'nested.compact line 190 char 1',
                                     'Bytes<32>',
                                     k3_0)
        }
        if (!(typeof(v_0) === 'bigint' && v_0 >= 0n && v_0 <= 18446744073709551615n)) {
          __compactRuntime.typeError('deepInsert',
                                     'argument 4 (argument 5 as invoked from Typescript)',
                                     'nested.compact line 190 char 1',
                                     'Uint<0..18446744073709551616>',
                                     v_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0).concat(_descriptor_0.toValue(k3_0).concat(_descriptor_1.toValue(v_0)))),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_1.alignment())))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._deepInsert_0(context,
                                                  partialProofData,
                                                  k_0,
                                                  k2_0,
                                                  k3_0,
                                                  v_0);
        partialProofData.output = { value: [], alignment: [] };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      },
      deepLookup: async (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`deepLookup: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const k_0 = args_1[1];
        const k2_0 = args_1[2];
        const k3_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.callContext.currentQueryContext != undefined)) {
          __compactRuntime.typeError('deepLookup',
                                     'argument 1 (as invoked from Typescript)',
                                     'nested.compact line 194 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(k_0.buffer instanceof ArrayBuffer && k_0.BYTES_PER_ELEMENT === 1 && k_0.length === 32)) {
          __compactRuntime.typeError('deepLookup',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'nested.compact line 194 char 1',
                                     'Bytes<32>',
                                     k_0)
        }
        if (!(k2_0.buffer instanceof ArrayBuffer && k2_0.BYTES_PER_ELEMENT === 1 && k2_0.length === 32)) {
          __compactRuntime.typeError('deepLookup',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'nested.compact line 194 char 1',
                                     'Bytes<32>',
                                     k2_0)
        }
        if (!(k3_0.buffer instanceof ArrayBuffer && k3_0.BYTES_PER_ELEMENT === 1 && k3_0.length === 32)) {
          __compactRuntime.typeError('deepLookup',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'nested.compact line 194 char 1',
                                     'Bytes<32>',
                                     k3_0)
        }
        const context = __compactRuntime.copyCircuitContext(contextOrig_0);
        const partialProofData = {
          input: {
            value: _descriptor_0.toValue(k_0).concat(_descriptor_0.toValue(k2_0).concat(_descriptor_0.toValue(k3_0))),
            alignment: _descriptor_0.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = await this._deepLookup_0(context,
                                                  partialProofData,
                                                  k_0,
                                                  k2_0,
                                                  k3_0);
        partialProofData.output = { value: _descriptor_1.toValue(result_0), alignment: _descriptor_1.alignment() };
        __compactRuntime.finalizeCallProofData(context, partialProofData);
        return { result: result_0, context: context, gasCost: context.callContext.currentGasCost };
      }
    };
    this.impureCircuits = {
      mapInsert: this.circuits.mapInsert,
      mapInsertDefault: this.circuits.mapInsertDefault,
      mapLookup: this.circuits.mapLookup,
      mapMember: this.circuits.mapMember,
      mapRemove: this.circuits.mapRemove,
      mapSize: this.circuits.mapSize,
      mapIsEmpty: this.circuits.mapIsEmpty,
      mapReset: this.circuits.mapReset,
      outerInsertDefault: this.circuits.outerInsertDefault,
      listPushFront: this.circuits.listPushFront,
      listPopFront: this.circuits.listPopFront,
      listLength: this.circuits.listLength,
      listHead: this.circuits.listHead,
      listIsEmpty: this.circuits.listIsEmpty,
      listReset: this.circuits.listReset,
      setInsert: this.circuits.setInsert,
      setRemove: this.circuits.setRemove,
      setMember: this.circuits.setMember,
      setReset: this.circuits.setReset,
      counterIncrement: this.circuits.counterIncrement,
      counterRead: this.circuits.counterRead,
      counterReset: this.circuits.counterReset,
      mtInsert: this.circuits.mtInsert,
      mtCheckRoot: this.circuits.mtCheckRoot,
      mtReset: this.circuits.mtReset,
      hmtInsert: this.circuits.hmtInsert,
      hmtResetHistory: this.circuits.hmtResetHistory,
      hmtReset: this.circuits.hmtReset,
      deepInsert: this.circuits.deepInsert,
      deepLookup: this.circuits.deepLookup
    };
    this.provableCircuits = {
      mapInsert: this.circuits.mapInsert,
      mapInsertDefault: this.circuits.mapInsertDefault,
      mapLookup: this.circuits.mapLookup,
      mapMember: this.circuits.mapMember,
      mapRemove: this.circuits.mapRemove,
      mapSize: this.circuits.mapSize,
      mapIsEmpty: this.circuits.mapIsEmpty,
      mapReset: this.circuits.mapReset,
      outerInsertDefault: this.circuits.outerInsertDefault,
      listPushFront: this.circuits.listPushFront,
      listPopFront: this.circuits.listPopFront,
      listLength: this.circuits.listLength,
      listHead: this.circuits.listHead,
      listIsEmpty: this.circuits.listIsEmpty,
      listReset: this.circuits.listReset,
      setInsert: this.circuits.setInsert,
      setRemove: this.circuits.setRemove,
      setMember: this.circuits.setMember,
      setReset: this.circuits.setReset,
      counterIncrement: this.circuits.counterIncrement,
      counterRead: this.circuits.counterRead,
      counterReset: this.circuits.counterReset,
      mtInsert: this.circuits.mtInsert,
      mtCheckRoot: this.circuits.mtCheckRoot,
      mtReset: this.circuits.mtReset,
      hmtInsert: this.circuits.hmtInsert,
      hmtResetHistory: this.circuits.hmtResetHistory,
      hmtReset: this.circuits.hmtReset,
      deepInsert: this.circuits.deepInsert,
      deepLookup: this.circuits.deepLookup
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
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    state_0.setOperation('mapInsert', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapInsertDefault', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapLookup', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapMember', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapRemove', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapSize', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapIsEmpty', new __compactRuntime.ContractOperation());
    state_0.setOperation('mapReset', new __compactRuntime.ContractOperation());
    state_0.setOperation('outerInsertDefault', new __compactRuntime.ContractOperation());
    state_0.setOperation('listPushFront', new __compactRuntime.ContractOperation());
    state_0.setOperation('listPopFront', new __compactRuntime.ContractOperation());
    state_0.setOperation('listLength', new __compactRuntime.ContractOperation());
    state_0.setOperation('listHead', new __compactRuntime.ContractOperation());
    state_0.setOperation('listIsEmpty', new __compactRuntime.ContractOperation());
    state_0.setOperation('listReset', new __compactRuntime.ContractOperation());
    state_0.setOperation('setInsert', new __compactRuntime.ContractOperation());
    state_0.setOperation('setRemove', new __compactRuntime.ContractOperation());
    state_0.setOperation('setMember', new __compactRuntime.ContractOperation());
    state_0.setOperation('setReset', new __compactRuntime.ContractOperation());
    state_0.setOperation('counterIncrement', new __compactRuntime.ContractOperation());
    state_0.setOperation('counterRead', new __compactRuntime.ContractOperation());
    state_0.setOperation('counterReset', new __compactRuntime.ContractOperation());
    state_0.setOperation('mtInsert', new __compactRuntime.ContractOperation());
    state_0.setOperation('mtCheckRoot', new __compactRuntime.ContractOperation());
    state_0.setOperation('mtReset', new __compactRuntime.ContractOperation());
    state_0.setOperation('hmtInsert', new __compactRuntime.ContractOperation());
    state_0.setOperation('hmtResetHistory', new __compactRuntime.ContractOperation());
    state_0.setOperation('hmtReset', new __compactRuntime.ContractOperation());
    state_0.setOperation('deepInsert', new __compactRuntime.ContractOperation());
    state_0.setOperation('deepLookup', new __compactRuntime.ContractOperation());
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
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(0n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(2n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(3n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(4n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(5n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(6n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    state_0.data = new __compactRuntime.ChargedState(context.callContext.currentQueryContext.state.state);
    return {
      currentContractState: state_0,
      currentPrivateState: context.callContext.currentPrivateState,
      currentZswapLocalState: context.callContext.currentZswapLocalState
    }
  }
  async _mapInsert_0(context, partialProofData, k_0, k2_0, v_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k2_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(v_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _mapInsertDefault_0(context, partialProofData, k_0, k2_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k2_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _mapLookup_0(context, partialProofData, k_0, k2_0) {
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(0n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k2_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { popeq: { cached: false,
                                                                                 result: undefined } }]).value);
  }
  async _mapMember_0(context, partialProofData, k_0, k2_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(0n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k2_0),
                                                                                                                             alignment: _descriptor_0.alignment() }).encode() } },
                                                                      'member',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _mapRemove_0(context, partialProofData, k_0, k2_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k2_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _mapSize_0(context, partialProofData, k_0) {
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(0n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      'size',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _mapIsEmpty_0(context, partialProofData, k_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(0n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      'size',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                             alignment: _descriptor_1.alignment() }).encode() } },
                                                                      'eq',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _mapReset_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _outerInsertDefault_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _listPushFront_0(context, partialProofData, k_0, v_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { dup: { n: 0 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(2n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { addi: { immediate: 1 } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(v_0),
                                                                                                           alignment: _descriptor_0.alignment() })).arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newNull())
                                                          .encode() } },
                                       { swap: { n: 0 } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(2n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       { ins: { cached: true, n: 1 } },
                                       { swap: { n: 0 } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { swap: { n: 0 } },
                                       { ins: { cached: true, n: 3 } }]);
    return [];
  }
  async _listPopFront_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _listLength_0(context, partialProofData, k_0) {
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(1n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(2n),
                                                                                                 alignment: _descriptor_10.alignment() } }] } },
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _listHead_0(context, partialProofData, k_0) {
    return _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(1n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(0n),
                                                                                                 alignment: _descriptor_10.alignment() } }] } },
                                                                      { dup: { n: 0 } },
                                                                      'type',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                                                             alignment: _descriptor_10.alignment() }).encode() } },
                                                                      'eq',
                                                                      { branch: { skip: 4 } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                                                             alignment: _descriptor_10.alignment() }).encode() } },
                                                                      { swap: { n: 0 } },
                                                                      { concat: { cached: false,
                                                                                  n: (2+Number(__compactRuntime.maxAlignedSize(
                                                                                          _descriptor_0
                                                                                          .alignment()
                                                                                        ))) } },
                                                                      { jmp: { skip: 2 } },
                                                                      'pop',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell(__compactRuntime.alignedConcat(
                                                                                                                             { value: _descriptor_10.toValue(0n),
                                                                                                                               alignment: _descriptor_10.alignment() },
                                                                                                                             { value: _descriptor_0.toValue(new Uint8Array(32)),
                                                                                                                               alignment: _descriptor_0.alignment() }
                                                                                                                           )).encode() } },
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _listIsEmpty_0(context, partialProofData, k_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(1n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(1n),
                                                                                                 alignment: _descriptor_10.alignment() } }] } },
                                                                      'type',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                                                             alignment: _descriptor_10.alignment() }).encode() } },
                                                                      'eq',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _listReset_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newNull()).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                                                                                             alignment: _descriptor_1.alignment() }))
                                                          .encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _setInsert_0(context, partialProofData, k_0, e_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(2n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(e_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _setRemove_0(context, partialProofData, k_0, e_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(2n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(e_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _setMember_0(context, partialProofData, k_0, e_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(2n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(e_0),
                                                                                                                             alignment: _descriptor_0.alignment() }).encode() } },
                                                                      'member',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _setReset_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(2n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _counterIncrement_0(context, partialProofData, k_0) {
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(3n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_5.toValue(tmp_0),
                                                                alignment: _descriptor_5.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    return [];
  }
  async _counterRead_0(context, partialProofData, k_0) {
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(3n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _counterReset_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(3n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _mtInsert_0(context, partialProofData, k_0, item_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(4n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell(__compactRuntime.leafHash(
                                                                                              { value: _descriptor_0.toValue(item_0),
                                                                                                alignment: _descriptor_0.alignment() }
                                                                                            )).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { addi: { immediate: 1 } },
                                       { ins: { cached: true, n: 3 } }]);
    return [];
  }
  async _mtCheckRoot_0(context, partialProofData, k_0, rt_0) {
    return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(4n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(0n),
                                                                                                 alignment: _descriptor_10.alignment() } }] } },
                                                                      'root',
                                                                      { push: { storage: false,
                                                                                value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(rt_0),
                                                                                                                             alignment: _descriptor_3.alignment() }).encode() } },
                                                                      'eq',
                                                                      { popeq: { cached: true,
                                                                                 result: undefined } }]).value);
  }
  async _mtReset_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(4n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newBoundedMerkleTree(
                                                                       new __compactRuntime.StateBoundedMerkleTree(8)
                                                                     )).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                        alignment: _descriptor_1.alignment() }))
                                                          .encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _hmtInsert_0(context, partialProofData, k_0, item_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(5n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell(__compactRuntime.leafHash(
                                                                                              { value: _descriptor_0.toValue(item_0),
                                                                                                alignment: _descriptor_0.alignment() }
                                                                                            )).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(1n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { addi: { immediate: 1 } },
                                       { ins: { cached: true, n: 1 } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(2n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       'root',
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 3 } }]);
    return [];
  }
  async _hmtResetHistory_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(5n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(2n),
                                                                                              alignment: _descriptor_10.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       'root',
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 4 } }]);
    return [];
  }
  async _hmtReset_0(context, partialProofData, k_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(5n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newBoundedMerkleTree(
                                                                       new __compactRuntime.StateBoundedMerkleTree(8)
                                                                     )).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                        alignment: _descriptor_1.alignment() })).arrayPush(__compactRuntime.StateValue.newMap(
                                                                                                                                                                             new __compactRuntime.StateMap()
                                                                                                                                                                           ))
                                                          .encode() } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(2n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(0n),
                                                                  alignment: _descriptor_10.alignment() } }] } },
                                       'root',
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: true, n: 2 } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  async _deepInsert_0(context, partialProofData, k_0, k2_0, k3_0, v_0) {
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_10.toValue(6n),
                                                                  alignment: _descriptor_10.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k_0),
                                                                  alignment: _descriptor_0.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_0.toValue(k2_0),
                                                                  alignment: _descriptor_0.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(k3_0),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(v_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 3 } }]);
    return [];
  }
  async _deepLookup_0(context, partialProofData, k_0, k2_0, k3_0) {
    return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                     partialProofData,
                                                                     [
                                                                      { dup: { n: 0 } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_10.toValue(6n),
                                                                                                 alignment: _descriptor_10.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k_0),
                                                                                                 alignment: _descriptor_0.alignment() } },
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k2_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { idx: { cached: false,
                                                                               pushPath: false,
                                                                               path: [
                                                                                      { tag: 'value',
                                                                                        value: { value: _descriptor_0.toValue(k3_0),
                                                                                                 alignment: _descriptor_0.alignment() } }] } },
                                                                      { popeq: { cached: false,
                                                                                 result: undefined } }]).value);
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
    mm: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(0n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(0n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 41 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(0n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 41 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[0].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          isEmpty(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(0n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              'size',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                     alignment: _descriptor_1.alignment() }).encode() } },
                                                                              'eq',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          size(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(0n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              'size',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          member(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_1.length}`);
            }
            const key_1 = args_1[0];
            if (!(key_1.buffer instanceof ArrayBuffer && key_1.BYTES_PER_ELEMENT === 1 && key_1.length === 32)) {
              __compactRuntime.typeError('member',
                                         'argument 1',
                                         'nested.compact line 41 char 34',
                                         'Bytes<32>',
                                         key_1)
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(0n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(key_1),
                                                                                                                                     alignment: _descriptor_0.alignment() }).encode() } },
                                                                              'member',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          lookup(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`lookup: expected 1 argument, received ${args_1.length}`);
            }
            const key_1 = args_1[0];
            if (!(key_1.buffer instanceof ArrayBuffer && key_1.BYTES_PER_ELEMENT === 1 && key_1.length === 32)) {
              __compactRuntime.typeError('lookup',
                                         'argument 1',
                                         'nested.compact line 41 char 34',
                                         'Bytes<32>',
                                         key_1)
            }
            return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(0n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_1),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { popeq: { cached: false,
                                                                                         result: undefined } }]).value);
          },
          [Symbol.iterator](...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[0].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return self_0.asMap().keys().map(  (key) => {    const value = self_0.asMap().get(key).asCell();    return [      _descriptor_0.fromValue(key.value),      _descriptor_1.fromValue(value.value)    ];  })[Symbol.iterator]();
          }
        }
      }
    },
    ml: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(1n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(1n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 42 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(1n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 42 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[1].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          isEmpty(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(1n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(1n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              'type',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                                                                     alignment: _descriptor_10.alignment() }).encode() } },
                                                                              'eq',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          length(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`length: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(1n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(2n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          head(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`head: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_6.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(1n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(0n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              { dup: { n: 0 } },
                                                                              'type',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                                                                     alignment: _descriptor_10.alignment() }).encode() } },
                                                                              'eq',
                                                                              { branch: { skip: 4 } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_10.toValue(1n),
                                                                                                                                     alignment: _descriptor_10.alignment() }).encode() } },
                                                                              { swap: { n: 0 } },
                                                                              { concat: { cached: false,
                                                                                          n: (2+Number(__compactRuntime.maxAlignedSize(
                                                                                                  _descriptor_0
                                                                                                  .alignment()
                                                                                                ))) } },
                                                                              { jmp: { skip: 2 } },
                                                                              'pop',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell(__compactRuntime.alignedConcat(
                                                                                                                                     { value: _descriptor_10.toValue(0n),
                                                                                                                                       alignment: _descriptor_10.alignment() },
                                                                                                                                     { value: _descriptor_0.toValue(new Uint8Array(32)),
                                                                                                                                       alignment: _descriptor_0.alignment() }
                                                                                                                                   )).encode() } },
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          [Symbol.iterator](...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[1].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return (() => {  var iter = { curr: self_0 };  iter.next = () => {    const arr = iter.curr.asArray();    const head = arr[0];    if(head.type() == "null") {      return { done: true };    } else {      iter.curr = arr[1];      return { value: _descriptor_0.fromValue(head.asCell().value), done: false };    }  };  return iter;})();
          }
        }
      }
    },
    ms: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(2n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(2n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 43 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(2n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 43 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[2].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          isEmpty(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(2n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              'size',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                     alignment: _descriptor_1.alignment() }).encode() } },
                                                                              'eq',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          size(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(2n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              'size',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          member(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_1.length}`);
            }
            const elem_0 = args_1[0];
            if (!(elem_0.buffer instanceof ArrayBuffer && elem_0.BYTES_PER_ELEMENT === 1 && elem_0.length === 32)) {
              __compactRuntime.typeError('member',
                                         'argument 1',
                                         'nested.compact line 43 char 34',
                                         'Bytes<32>',
                                         elem_0)
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(2n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(elem_0),
                                                                                                                                     alignment: _descriptor_0.alignment() }).encode() } },
                                                                              'member',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          [Symbol.iterator](...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[2].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return self_0.asMap().keys().map((elem) => _descriptor_0.fromValue(elem.value))[Symbol.iterator]();
          }
        }
      }
    },
    mc: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(3n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(3n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 44 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(3n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 44 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[3].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          read(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`read: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(3n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          }
        }
      }
    },
    mt: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(4n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(4n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 45 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(4n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 45 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[4].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          isFull(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`isFull: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(4n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(1n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(256n),
                                                                                                                                     alignment: _descriptor_1.alignment() }).encode() } },
                                                                              'lt',
                                                                              'neg',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          checkRoot(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`checkRoot: expected 1 argument, received ${args_1.length}`);
            }
            const rt_0 = args_1[0];
            if (!(typeof(rt_0) === 'object' && typeof(rt_0.field) === 'bigint' && rt_0.field >= 0 && rt_0.field <= __compactRuntime.MAX_FIELD)) {
              __compactRuntime.typeError('checkRoot',
                                         'argument 1',
                                         'nested.compact line 45 char 34',
                                         'struct MerkleTreeDigest<field: Field>',
                                         rt_0)
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(4n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(0n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              'root',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(rt_0),
                                                                                                                                     alignment: _descriptor_3.alignment() }).encode() } },
                                                                              'eq',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          root(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`root: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[4].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return ((result) => result             ? __compactRuntime.CompactTypeMerkleTreeDigest.fromValue(result)             : undefined)(self_0.asArray()[0].asBoundedMerkleTree().rehash().root()?.value);
          },
          firstFree(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`first_free: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[4].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return __compactRuntime.CompactTypeField.fromValue(self_0.asArray()[1].asCell().value);
          },
          pathForLeaf(...args_1) {
            if (args_1.length !== 2) {
              throw new __compactRuntime.CompactError(`path_for_leaf: expected 2 arguments, received ${args_1.length}`);
            }
            const index_0 = args_1[0];
            const leaf_0 = args_1[1];
            if (!(typeof(index_0) === 'bigint' && index_0 >= 0 && index_0 <= __compactRuntime.MAX_FIELD)) {
              __compactRuntime.typeError('path_for_leaf',
                                         'argument 1',
                                         'nested.compact line 45 char 34',
                                         'Field',
                                         index_0)
            }
            if (!(leaf_0.buffer instanceof ArrayBuffer && leaf_0.BYTES_PER_ELEMENT === 1 && leaf_0.length === 32)) {
              __compactRuntime.typeError('path_for_leaf',
                                         'argument 2',
                                         'nested.compact line 45 char 34',
                                         'Bytes<32>',
                                         leaf_0)
            }
            const self_0 = state.asArray()[4].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return ((result) => result             ? new __compactRuntime.CompactTypeMerkleTreePath(8, _descriptor_0).fromValue(result)             : undefined)(  self_0.asArray()[0].asBoundedMerkleTree().rehash().pathForLeaf(    index_0,    {      value: _descriptor_0.toValue(leaf_0),      alignment: _descriptor_0.alignment()    }  )?.value);
          },
          findPathForLeaf(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`find_path_for_leaf: expected 1 argument, received ${args_1.length}`);
            }
            const leaf_0 = args_1[0];
            if (!(leaf_0.buffer instanceof ArrayBuffer && leaf_0.BYTES_PER_ELEMENT === 1 && leaf_0.length === 32)) {
              __compactRuntime.typeError('find_path_for_leaf',
                                         'argument 1',
                                         'nested.compact line 45 char 34',
                                         'Bytes<32>',
                                         leaf_0)
            }
            const self_0 = state.asArray()[4].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return ((result) => result             ? new __compactRuntime.CompactTypeMerkleTreePath(8, _descriptor_0).fromValue(result)             : undefined)(  self_0.asArray()[0].asBoundedMerkleTree().rehash().findPathForLeaf(    {      value: _descriptor_0.toValue(leaf_0),      alignment: _descriptor_0.alignment()    }  )?.value);
          }
        }
      }
    },
    mh: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(5n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(5n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 46 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(5n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 46 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[5].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          isFull(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`isFull: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(5n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(1n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(256n),
                                                                                                                                     alignment: _descriptor_1.alignment() }).encode() } },
                                                                              'lt',
                                                                              'neg',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          checkRoot(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`checkRoot: expected 1 argument, received ${args_1.length}`);
            }
            const rt_0 = args_1[0];
            if (!(typeof(rt_0) === 'object' && typeof(rt_0.field) === 'bigint' && rt_0.field >= 0 && rt_0.field <= __compactRuntime.MAX_FIELD)) {
              __compactRuntime.typeError('checkRoot',
                                         'argument 1',
                                         'nested.compact line 46 char 34',
                                         'struct MerkleTreeDigest<field: Field>',
                                         rt_0)
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(5n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(2n),
                                                                                                         alignment: _descriptor_10.alignment() } }] } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(rt_0),
                                                                                                                                     alignment: _descriptor_3.alignment() }).encode() } },
                                                                              'member',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          root(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`root: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[5].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return ((result) => result             ? __compactRuntime.CompactTypeMerkleTreeDigest.fromValue(result)             : undefined)(self_0.asArray()[0].asBoundedMerkleTree().rehash().root()?.value);
          },
          firstFree(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`first_free: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[5].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return __compactRuntime.CompactTypeField.fromValue(self_0.asArray()[1].asCell().value);
          },
          pathForLeaf(...args_1) {
            if (args_1.length !== 2) {
              throw new __compactRuntime.CompactError(`path_for_leaf: expected 2 arguments, received ${args_1.length}`);
            }
            const index_0 = args_1[0];
            const leaf_0 = args_1[1];
            if (!(typeof(index_0) === 'bigint' && index_0 >= 0 && index_0 <= __compactRuntime.MAX_FIELD)) {
              __compactRuntime.typeError('path_for_leaf',
                                         'argument 1',
                                         'nested.compact line 46 char 34',
                                         'Field',
                                         index_0)
            }
            if (!(leaf_0.buffer instanceof ArrayBuffer && leaf_0.BYTES_PER_ELEMENT === 1 && leaf_0.length === 32)) {
              __compactRuntime.typeError('path_for_leaf',
                                         'argument 2',
                                         'nested.compact line 46 char 34',
                                         'Bytes<32>',
                                         leaf_0)
            }
            const self_0 = state.asArray()[5].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return ((result) => result             ? new __compactRuntime.CompactTypeMerkleTreePath(8, _descriptor_0).fromValue(result)             : undefined)(  self_0.asArray()[0].asBoundedMerkleTree().rehash().pathForLeaf(    index_0,    {      value: _descriptor_0.toValue(leaf_0),      alignment: _descriptor_0.alignment()    }  )?.value);
          },
          findPathForLeaf(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`find_path_for_leaf: expected 1 argument, received ${args_1.length}`);
            }
            const leaf_0 = args_1[0];
            if (!(leaf_0.buffer instanceof ArrayBuffer && leaf_0.BYTES_PER_ELEMENT === 1 && leaf_0.length === 32)) {
              __compactRuntime.typeError('find_path_for_leaf',
                                         'argument 1',
                                         'nested.compact line 46 char 34',
                                         'Bytes<32>',
                                         leaf_0)
            }
            const self_0 = state.asArray()[5].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return ((result) => result             ? new __compactRuntime.CompactTypeMerkleTreePath(8, _descriptor_0).fromValue(result)             : undefined)(  self_0.asArray()[0].asBoundedMerkleTree().rehash().findPathForLeaf(    {      value: _descriptor_0.toValue(leaf_0),      alignment: _descriptor_0.alignment()    }  )?.value);
          },
          history(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`history: expected 0 arguments, received ${args_1.length}`);
            }
            const self_0 = state.asArray()[5].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                            alignment: _descriptor_0.alignment() });
            return self_0.asArray()[2].asMap().keys().map(  (elem) => __compactRuntime.CompactTypeMerkleTreeDigest.fromValue(elem.value))[Symbol.iterator]();
          }
        }
      }
    },
    mmm: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(6n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                 alignment: _descriptor_1.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(6n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 47 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_10.toValue(6n),
                                                                                                     alignment: _descriptor_10.alignment() } }] } },
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
                                     'nested.compact line 47 char 1',
                                     'Bytes<32>',
                                     key_0)
        }
        if (state.asArray()[6].asMap().get({ value: _descriptor_0.toValue(key_0),
                                             alignment: _descriptor_0.alignment() }) === undefined) {
          throw new __compactRuntime.CompactError(`Map value undefined for ${key_0}`);
        }
        return {
          isEmpty(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(6n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              'size',
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                     alignment: _descriptor_1.alignment() }).encode() } },
                                                                              'eq',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          size(...args_1) {
            if (args_1.length !== 0) {
              throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_1.length}`);
            }
            return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(6n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              'size',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          member(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_1.length}`);
            }
            const key_1 = args_1[0];
            if (!(key_1.buffer instanceof ArrayBuffer && key_1.BYTES_PER_ELEMENT === 1 && key_1.length === 32)) {
              __compactRuntime.typeError('member',
                                         'argument 1',
                                         'nested.compact line 47 char 35',
                                         'Bytes<32>',
                                         key_1)
            }
            return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 0 } },
                                                                              { idx: { cached: false,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_10.toValue(6n),
                                                                                                         alignment: _descriptor_10.alignment() } },
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_0.toValue(key_0),
                                                                                                         alignment: _descriptor_0.alignment() } }] } },
                                                                              { push: { storage: false,
                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(key_1),
                                                                                                                                     alignment: _descriptor_0.alignment() }).encode() } },
                                                                              'member',
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
          },
          lookup(...args_1) {
            if (args_1.length !== 1) {
              throw new __compactRuntime.CompactError(`lookup: expected 1 argument, received ${args_1.length}`);
            }
            const key_1 = args_1[0];
            if (!(key_1.buffer instanceof ArrayBuffer && key_1.BYTES_PER_ELEMENT === 1 && key_1.length === 32)) {
              __compactRuntime.typeError('lookup',
                                         'argument 1',
                                         'nested.compact line 47 char 35',
                                         'Bytes<32>',
                                         key_1)
            }
            if (state.asArray()[6].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                 alignment: _descriptor_0.alignment() }).asMap().get({ value: _descriptor_0.toValue(key_1),
                                                                                                       alignment: _descriptor_0.alignment() }) === undefined) {
              throw new __compactRuntime.CompactError(`Map value undefined for ${key_1}`);
            }
            return {
              isEmpty(...args_2) {
                if (args_2.length !== 0) {
                  throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_2.length}`);
                }
                return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                 partialProofData,
                                                                                 [
                                                                                  { dup: { n: 0 } },
                                                                                  { idx: { cached: false,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_10.toValue(6n),
                                                                                                             alignment: _descriptor_10.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_0),
                                                                                                             alignment: _descriptor_0.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_1),
                                                                                                             alignment: _descriptor_0.alignment() } }] } },
                                                                                  'size',
                                                                                  { push: { storage: false,
                                                                                            value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(0n),
                                                                                                                                         alignment: _descriptor_1.alignment() }).encode() } },
                                                                                  'eq',
                                                                                  { popeq: { cached: true,
                                                                                             result: undefined } }]).value);
              },
              size(...args_2) {
                if (args_2.length !== 0) {
                  throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_2.length}`);
                }
                return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                 partialProofData,
                                                                                 [
                                                                                  { dup: { n: 0 } },
                                                                                  { idx: { cached: false,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_10.toValue(6n),
                                                                                                             alignment: _descriptor_10.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_0),
                                                                                                             alignment: _descriptor_0.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_1),
                                                                                                             alignment: _descriptor_0.alignment() } }] } },
                                                                                  'size',
                                                                                  { popeq: { cached: true,
                                                                                             result: undefined } }]).value);
              },
              member(...args_2) {
                if (args_2.length !== 1) {
                  throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_2.length}`);
                }
                const key_2 = args_2[0];
                if (!(key_2.buffer instanceof ArrayBuffer && key_2.BYTES_PER_ELEMENT === 1 && key_2.length === 32)) {
                  __compactRuntime.typeError('member',
                                             'argument 1',
                                             'nested.compact line 47 char 50',
                                             'Bytes<32>',
                                             key_2)
                }
                return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                 partialProofData,
                                                                                 [
                                                                                  { dup: { n: 0 } },
                                                                                  { idx: { cached: false,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_10.toValue(6n),
                                                                                                             alignment: _descriptor_10.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_0),
                                                                                                             alignment: _descriptor_0.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_1),
                                                                                                             alignment: _descriptor_0.alignment() } }] } },
                                                                                  { push: { storage: false,
                                                                                            value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(key_2),
                                                                                                                                         alignment: _descriptor_0.alignment() }).encode() } },
                                                                                  'member',
                                                                                  { popeq: { cached: true,
                                                                                             result: undefined } }]).value);
              },
              lookup(...args_2) {
                if (args_2.length !== 1) {
                  throw new __compactRuntime.CompactError(`lookup: expected 1 argument, received ${args_2.length}`);
                }
                const key_2 = args_2[0];
                if (!(key_2.buffer instanceof ArrayBuffer && key_2.BYTES_PER_ELEMENT === 1 && key_2.length === 32)) {
                  __compactRuntime.typeError('lookup',
                                             'argument 1',
                                             'nested.compact line 47 char 50',
                                             'Bytes<32>',
                                             key_2)
                }
                return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                 partialProofData,
                                                                                 [
                                                                                  { dup: { n: 0 } },
                                                                                  { idx: { cached: false,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_10.toValue(6n),
                                                                                                             alignment: _descriptor_10.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_0),
                                                                                                             alignment: _descriptor_0.alignment() } },
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_1),
                                                                                                             alignment: _descriptor_0.alignment() } }] } },
                                                                                  { idx: { cached: false,
                                                                                           pushPath: false,
                                                                                           path: [
                                                                                                  { tag: 'value',
                                                                                                    value: { value: _descriptor_0.toValue(key_2),
                                                                                                             alignment: _descriptor_0.alignment() } }] } },
                                                                                  { popeq: { cached: false,
                                                                                             result: undefined } }]).value);
              },
              [Symbol.iterator](...args_2) {
                if (args_2.length !== 0) {
                  throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_2.length}`);
                }
                const self_0 = state.asArray()[6].asMap().get({ value: _descriptor_0.toValue(key_0),
                                                                alignment: _descriptor_0.alignment() }).asMap().get({ value: _descriptor_0.toValue(key_1),
                                                                                                                      alignment: _descriptor_0.alignment() });
                return self_0.asMap().keys().map(  (key) => {    const value = self_0.asMap().get(key).asCell();    return [      _descriptor_0.fromValue(key.value),      _descriptor_1.fromValue(value.value)    ];  })[Symbol.iterator]();
              }
            }
          }
        }
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
