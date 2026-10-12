import { afterEach, describe, expect, it, vi } from 'vitest';
import { assertNativeSupport, decodeBase64url, decodeNativeRequest, encodeBase64url, extensionResultsJSON, nativeError, serializeNativeAssertion } from './nativeWebAuthn';

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const options = () => ({challenge: 'AQID', rpId: 'example.com', timeout: 30000, userVerification: 'required',
  allowCredentials: [{type: 'public-key', id: '-_8', transports: ['hybrid', 'internal']}], hints: ['hybrid'],
  extensions: {remoteDesktopClientOverride: {origin: 'https://example.com', sameOriginWithAncestors: true}}});
function parser(convert?: (value: any) => any) {
  const parseRequestOptionsFromJSON = vi.fn((value: any) => convert ? convert(value) : ({...value,
    challenge: decodeBase64url(value.challenge, 'challenge'),
    ...(value.allowCredentials ? {allowCredentials: value.allowCredentials.map((item: any) => ({...item, id: decodeBase64url(item.id, 'id')}))} : {})}));
  vi.stubGlobal('PublicKeyCredential', {parseRequestOptionsFromJSON});
  return parseRequestOptionsFromJSON;
}
function credential() {
  return {id: 'AQID', type: 'public-key', rawId: new Uint8Array([1, 2, 3]).buffer, authenticatorAttachment: 'cross-platform',
    response: {clientDataJSON: new Uint8Array([123, 125]).buffer, authenticatorData: new Uint8Array([1, 2]).buffer,
      signature: new Uint8Array([255, 0]).buffer, userHandle: null}, getClientExtensionResults: () => ({})} as unknown as Credential;
}

describe('native WebAuthn JSON boundary', () => {
  it('preserves the exact browser override, challenge, transports, RP ID and policy without mutating input', () => {
    const parse = parser(); const input = options(); const saved = structuredClone(input);
    const decoded = decodeNativeRequest(input);
    expect(parse).toHaveBeenCalledWith(saved);
    expect(input).toEqual(saved);
    expect(decoded.extensions).toEqual(saved.extensions);
    expect(decoded.rpId).toBe('example.com');
    expect(decoded.userVerification).toBe('required');
    expect(decoded.challenge).toEqual(new Uint8Array([1, 2, 3]).buffer);
    expect(decoded.allowCredentials?.[0]).toEqual({type: 'public-key', id: new Uint8Array([251, 255]).buffer, transports: ['hybrid', 'internal']});
  });
  it('fails closed without a parser or when it drops or changes the remote override', () => {
    vi.stubGlobal('PublicKeyCredential', {});
    expect(() => decodeNativeRequest(options())).toThrow(/JSON 解析器/);
    for (const extensions of [{}, {remoteDesktopClientOverride: {origin: 'https://other.example', sameOriginWithAncestors: true}},
      {remoteDesktopClientOverride: {origin: 'https://example.com', sameOriginWithAncestors: false}}]) {
      parser(value => ({...value, challenge: decodeBase64url(value.challenge, 'challenge'),
        allowCredentials: [{...value.allowCredentials[0], id: decodeBase64url(value.allowCredentials[0].id, 'id')}], extensions}));
      expect(() => decodeNativeRequest(options())).toThrow(/未完整保留/);
    }
  });
  it('propagates the actual native parser exception without falling back', () => {
    const failure = new DOMException('Native parser denied this extension.', 'NotSupportedError');
    const parse = parser(() => { throw failure; });
    expect(() => decodeNativeRequest(options())).toThrow(failure);
    expect(parse).toHaveBeenCalledOnce();
  });
  it('validates and preserves binary largeBlob, PRF and legacy HMAC extension inputs', () => {
    const input = {...options(), extensions: {...options().extensions, appid: 'https://example.com/u2f', getCredBlob: true, uvm: true,
      largeBlob: {write: '-_8'}, prf: {eval: {first: 'AQI', second: 'AwQ'}, evalByCredential: {'-_8': {first: 'BQY'}}},
      hmacGetSecret: {salt1: 'AQI', salt2: 'AwQ'}}};
    parser(value => ({...value, challenge: new Uint8Array([1, 2, 3]).buffer,
      allowCredentials: [{...value.allowCredentials[0], id: new Uint8Array([251, 255]).buffer}],
      extensions: {...value.extensions, largeBlob: {write: new Uint8Array([251, 255]).buffer},
        prf: {eval: {first: new Uint8Array([1, 2]).buffer, second: new Uint8Array([3, 4]).buffer},
          evalByCredential: {'-_8': {first: new Uint8Array([5, 6]).buffer}}},
        hmacGetSecret: {salt1: new Uint8Array([1, 2]).buffer, salt2: new Uint8Array([3, 4]).buffer}}}));
    expect(extensionResultsJSON(decodeNativeRequest(input).extensions)).toEqual(input.extensions);
  });
  it('rejects a dropped binary extension instead of sending an incomplete request', () => {
    parser(value => ({...value, challenge: new Uint8Array([1, 2, 3]).buffer,
      allowCredentials: [{...value.allowCredentials[0], id: new Uint8Array([251, 255]).buffer}],
      extensions: options().extensions}));
    expect(() => decodeNativeRequest({...options(), extensions: {...options().extensions, prf: {eval: {first: 'AQI'}}}})).toThrow(/未完整保留/);
  });
  it.each([
    {unknownExtension: {bytes: 'AQI'}}, {remoteDesktopClientOverride: {origin: 'https://example.com', sameOriginWithAncestors: true, unexpected: true}},
    {largeBlob: {read: 'true'}}, {prf: {eval: {first: 'AQI', unexpected: true}}}, {prf: {eval: {first: 'bad!!'}}},
  ])('rejects unsupported or malformed extension JSON without invoking the parser: %j', extensions => {
    const parse = parser();
    expect(() => decodeNativeRequest({...options(), extensions: {...options().extensions, ...extensions}})).toThrow();
    expect(parse).not.toHaveBeenCalled();
  });
  it('rejects missing override and does not invent it from the RP or outer origin', () => {
    const parse = parser();
    expect(() => decodeNativeRequest({...options(), extensions: {}})).toThrow(/缺少原始/);
    expect(parse).not.toHaveBeenCalled();
  });
  it('preserves the empty AppID browser semantic without substituting an origin', () => {
    parser();
    expect(decodeNativeRequest({...options(), extensions: {...options().extensions, appid: ''}}).extensions).toHaveProperty('appid', '');
  });
  it('validates base64url encodings and preserves byte ranges', () => {
    expect(encodeBase64url(new Uint8Array([10, 251, 255, 20]).subarray(1, 3))).toBe('-_8');
    expect(encodeBase64url(new DataView(new Uint8Array([10, 251, 255, 20]).buffer, 1, 2))).toBe('-_8');
    expect(decodeBase64url('-_8=', 'value')).toEqual(new Uint8Array([251, 255]).buffer);
    for (const value of ['A', 'AB', 'A===', '+/8=', 'A Q', 'AQ=', 123, null]) expect(() => decodeBase64url(value, 'value')).toThrow();
  });
  it('serializes browser bytes unchanged and omits absent userHandle for Chrome proxy compatibility', () => {
    const result = serializeNativeAssertion(credential());
    expect(result).toEqual({id: 'AQID', type: 'public-key', rawId: 'AQID', authenticatorAttachment: 'cross-platform',
      response: {clientDataJSON: 'e30', authenticatorData: 'AQI', signature: '_wA'}, clientExtensionResults: {}});
    expect(result.response).not.toHaveProperty('userHandle');
  });
  it('serializes binary extension outputs deeply without losing ArrayBuffers or view offsets', () => {
    const value = credential() as PublicKeyCredential;
    Object.assign(value.response, {userHandle: new Uint8Array([0, 251, 255, 9]).subarray(1, 3)});
    Object.assign(value, {getClientExtensionResults: () => ({appid: true,
      largeBlob: {blob: new Uint8Array([10, 20]).buffer}, prf: {results: {first: new Uint8Array([0, 251, 255, 9]).subarray(1, 3)}},
      future: [true, {buffer: new DataView(new Uint8Array([5, 6]).buffer)}]})});
    expect(serializeNativeAssertion(value)).toMatchObject({response: {userHandle: '-_8'},
      clientExtensionResults: {appid: true, largeBlob: {blob: 'ChQ'}, prf: {results: {first: '-_8'}}, future: [true, {buffer: 'BQY'}]}});
  });
  it('rejects missing credentials and lossy extension result types', () => {
    expect(() => serializeNativeAssertion(null)).toThrow(/没有返回/);
    const cyclic: any = {}; cyclic.self = cyclic;
    for (const value of [undefined, NaN, Infinity, 1n, () => {}, new Map(), cyclic]) expect(() => extensionResultsJSON({value})).toThrow();
  });
  it.each([
    ['https:', 'example.com', true], ['https:', 'localhost', false],
    ['http:', 'localhost', true], ['http:', 'dev.localhost', false],
    ['http:', 'localhost.evil.test', false], ['http:', 'remote.example', false],
    ['http:', '127.0.0.1', true], ['http:', '[::1]', true],
    ['http:', '192.168.1.1', false], ['file:', '', false], ['ftp:', 'localhost', false],
  ])('leaves context decisions to the browser: %s %s secure=%s', (protocol, hostname, secure) => {
    vi.stubGlobal('isSecureContext', secure);
    vi.stubGlobal('location', {protocol, hostname});
    vi.stubGlobal('PublicKeyCredential', {});
    vi.stubGlobal('navigator', {credentials: {get: vi.fn()}});
    expect(() => assertNativeSupport()).not.toThrow();
  });
  it.each([undefined, {}, {get: undefined}, {get: 'unavailable'}])('reports a missing credentials API accurately: %j', credentials => {
    vi.stubGlobal('PublicKeyCredential', {});
    vi.stubGlobal('navigator', {credentials});
    expect(() => assertNativeSupport()).toThrow('当前页面无法使用原生 WebAuthn API。');
  });
  it('requires the credential API while preserving actual browser errors', () => {
    vi.stubGlobal('PublicKeyCredential', undefined);
    vi.stubGlobal('navigator', {credentials: {get: vi.fn()}});
    expect(() => assertNativeSupport()).toThrow('当前页面无法使用原生 WebAuthn API。');
    expect(nativeError(new DOMException('Browser policy blocked remote origins.', 'NotAllowedError')))
      .toEqual({name: 'NotAllowedError', message: 'Browser policy blocked remote origins.'});
  });
});
