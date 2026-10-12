/** WebAuthn JSON transport only. The browser, never this page, creates clientDataJSON. */
type ObjectValue = Record<string, unknown>;
export interface NativeStart { attempt_id: string; options: unknown; remaining_ms: number }
export interface NativeError { name: string; message: string }

function invalid(message: string): never { throw new DOMException(message, 'EncodingError'); }
function record(value: unknown, field: string): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid(`${field} 必须是 JSON 对象。`);
  return value as ObjectValue;
}
function fields(value: ObjectValue, allowed: string[], field: string) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new DOMException(`不支持 ${field}.${key}，本次验证已停止。`, 'NotSupportedError');
  }
}
function text(value: unknown, field: string, empty = false): string {
  if (typeof value !== 'string' || (!empty && !value)) invalid(`${field} 必须是字符串。`);
  return value as string;
}
function boolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') invalid(`${field} 必须是布尔值。`);
  return value as boolean;
}
export function encodeBase64url(value: unknown, field = '二进制字段'): string {
  let bytes: Uint8Array;
  if (value instanceof ArrayBuffer) bytes = new Uint8Array(value);
  else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  else return invalid(`${field} 必须是浏览器返回的二进制数据。`);
  let raw = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) raw += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function decodeBase64url(value: unknown, field: string): ArrayBuffer {
  const encoded = text(value, field, true);
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(encoded) || encoded.replace(/=+$/, '').length % 4 === 1
      || (encoded.includes('=') && encoded.length % 4 !== 0)) invalid(`${field} 不是有效的 Base64URL。`);
  let raw: string;
  try { raw = atob(encoded.replace(/-/g, '+').replace(/_/g, '/')); }
  catch { return invalid(`${field} 不是有效的 Base64URL。`); }
  const bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
  if (encodeBase64url(bytes) !== encoded.replace(/=+$/, '')) invalid(`${field} 不是规范的 Base64URL。`);
  return bytes.buffer;
}
function prfValues(value: unknown, field: string): ObjectValue {
  const input = record(value, field);
  fields(input, ['first', 'second'], field);
  return {first: decodeBase64url(input.first, `${field}.first`),
    ...('second' in input ? {second: decodeBase64url(input.second, `${field}.second`)} : {})};
}
function decodeExtensions(value: unknown): ObjectValue {
  const input = record(value, 'extensions');
  const output: ObjectValue = {};
  // Unknown extension types must not be silently stripped by an older JSON parser.
  fields(input, ['remoteDesktopClientOverride', 'appid', 'credProps', 'getCredBlob', 'uvm', 'largeBlob', 'prf', 'hmacGetSecret'], 'extensions');
  for (const [key, item] of Object.entries(input)) {
    if (key === 'remoteDesktopClientOverride') {
      const override = record(item, key);
      fields(override, ['origin', 'sameOriginWithAncestors'], key);
      output[key] = {origin: text(override.origin, `${key}.origin`),
        sameOriginWithAncestors: boolean(override.sameOriginWithAncestors, `${key}.sameOriginWithAncestors`)};
    } else if (key === 'appid') output[key] = text(item, key, true);
    else if (['credProps', 'getCredBlob', 'uvm'].includes(key)) output[key] = boolean(item, key);
    else if (key === 'largeBlob') {
      const blob = record(item, key); fields(blob, ['read', 'write'], key);
      output[key] = {...('read' in blob ? {read: boolean(blob.read, `${key}.read`)} : {}),
        ...('write' in blob ? {write: decodeBase64url(blob.write, `${key}.write`)} : {})};
    } else if (key === 'prf') {
      const prf = record(item, key); fields(prf, ['eval', 'evalByCredential'], key);
      output[key] = {...('eval' in prf ? {eval: prfValues(prf.eval, 'prf.eval')} : {}),
        ...('evalByCredential' in prf ? {evalByCredential: Object.fromEntries(Object.entries(record(prf.evalByCredential, 'prf.evalByCredential'))
          .map(([id, values]) => { decodeBase64url(id, 'prf credential ID'); return [id, prfValues(values, 'prf.evalByCredential')]; }))} : {})};
    } else if (key === 'hmacGetSecret') {
      const salts = record(item, key); fields(salts, ['salt1', 'salt2'], key);
      output[key] = {salt1: decodeBase64url(salts.salt1, `${key}.salt1`),
        ...('salt2' in salts ? {salt2: decodeBase64url(salts.salt2, `${key}.salt2`)} : {})};
    }
  }
  if (!output.remoteDesktopClientOverride) invalid('缺少原始 remoteDesktopClientOverride，不能进行远程验证。');
  return output;
}

export function decodeNativeRequest(value: unknown): PublicKeyCredentialRequestOptions {
  const input = record(value, 'publicKey');
  fields(input, ['challenge', 'timeout', 'rpId', 'allowCredentials', 'userVerification', 'hints', 'extensions'], 'publicKey');
  const challenge = decodeBase64url(input.challenge, 'challenge');
  if (!challenge.byteLength) invalid('challenge 不得为空。');
  text(input.rpId, 'rpId');
  if ('timeout' in input && (typeof input.timeout !== 'number' || !Number.isFinite(input.timeout) || input.timeout < 0)) invalid('timeout 无效。');
  if ('userVerification' in input && !['required', 'preferred', 'discouraged'].includes(String(input.userVerification))) invalid('userVerification 无效。');
  if ('hints' in input && (!Array.isArray(input.hints) || input.hints.some(item => typeof item !== 'string'))) invalid('hints 无效。');
  let allowCredentials: PublicKeyCredentialDescriptor[] | undefined;
  if ('allowCredentials' in input) {
    if (!Array.isArray(input.allowCredentials)) invalid('allowCredentials 必须是数组。');
    allowCredentials = (input.allowCredentials as unknown[]).map((item, index) => {
      const descriptor = record(item, `allowCredentials[${index}]`);
      fields(descriptor, ['type', 'id', 'transports'], 'allowCredentials');
      if (descriptor.type !== 'public-key') invalid('凭据类型必须是 public-key。');
      if ('transports' in descriptor && (!Array.isArray(descriptor.transports) || descriptor.transports.some(item => typeof item !== 'string'))) invalid('transports 无效。');
      return {...descriptor, id: decodeBase64url(descriptor.id, 'credential ID')} as PublicKeyCredentialDescriptor;
    });
  }
  const extensions = decodeExtensions(input.extensions);
  const constructor = globalThis.PublicKeyCredential as (typeof PublicKeyCredential & {
    parseRequestOptionsFromJSON?: (options: unknown) => PublicKeyCredentialRequestOptions;
  }) | undefined;
  // Requiring the native parser to recognize the override prevents an unsupported
  // browser from silently starting a local-origin ceremony (and its side effects).
  // Do not restore a dropped extension, or retry without the override.
  if (typeof constructor?.parseRequestOptionsFromJSON !== 'function') {
    throw new DOMException('浏览器缺少可验证远程来源支持的原生 WebAuthn JSON 解析器。请使用支持 remoteDesktopClientOverride 的浏览器。', 'NotSupportedError');
  }
  const parsed = constructor.parseRequestOptionsFromJSON(structuredClone(input));
  const expected = {...input, challenge, ...('allowCredentials' in input ? {allowCredentials} : {}), extensions};
  const preserves = (original: unknown, decoded: unknown): boolean => {
    if (original instanceof ArrayBuffer) return (decoded instanceof ArrayBuffer || ArrayBuffer.isView(decoded))
      && encodeBase64url(original) === encodeBase64url(decoded);
    if (Array.isArray(original)) return Array.isArray(decoded) && original.length === decoded.length
      && original.every((item, index) => preserves(item, decoded[index]));
    if (original && typeof original === 'object') return Boolean(decoded && typeof decoded === 'object'
      && Object.entries(original).every(([key, item]) => Object.prototype.hasOwnProperty.call(decoded, key)
        && preserves(item, (decoded as ObjectValue)[key])));
    return original === decoded;
  };
  if (!preserves(expected, parsed)) {
    throw new DOMException('浏览器未完整保留 remoteDesktopClientOverride 或其他请求选项；已停止，未调用设备验证。', 'NotSupportedError');
  }
  return parsed;
}

/** Recursively preserve extension buffers (including offset views); reject lossy JSON. */
export function extensionResultsJSON(value: unknown, ancestors = new Set<object>(), depth = 0): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return encodeBase64url(value);
  if (depth > 32 || typeof value !== 'object' || !value || ancestors.has(value)) invalid('浏览器扩展结果无法无损序列化。');
  const nested = new Set(ancestors).add(value);
  if (Array.isArray(value)) return value.map(item => extensionResultsJSON(item, nested, depth + 1));
  return Object.fromEntries(Object.entries(record(value, '扩展结果')).map(([key, item]) => [key, extensionResultsJSON(item, nested, depth + 1)]));
}
export function serializeNativeAssertion(value: Credential | null): ObjectValue {
  if (!value || value.type !== 'public-key') throw new DOMException('浏览器没有返回公钥凭据。', 'NotAllowedError');
  const credential = value as PublicKeyCredential;
  const response = credential.response as AuthenticatorAssertionResponse;
  if (!response || typeof credential.getClientExtensionResults !== 'function') invalid('浏览器返回的断言无效。');
  // Explicitly read browser fields. Do not parse, construct, or rewrite clientDataJSON.
  return {id: text(credential.id, 'credential.id'), type: 'public-key', rawId: encodeBase64url(credential.rawId, 'rawId'),
    ...(credential.authenticatorAttachment == null ? {} : {authenticatorAttachment: text(credential.authenticatorAttachment, 'authenticatorAttachment')}),
    response: {clientDataJSON: encodeBase64url(response.clientDataJSON, 'clientDataJSON'),
      authenticatorData: encodeBase64url(response.authenticatorData, 'authenticatorData'),
      signature: encodeBase64url(response.signature, 'signature'),
      ...(response.userHandle == null ? {} : {userHandle: encodeBase64url(response.userHandle, 'userHandle')})},
    clientExtensionResults: extensionResultsJSON(credential.getClientExtensionResults())};
}
export function assertNativeSupport() {
  // Browser policy decides whether this page may invoke WebAuthn.
  if (!globalThis.PublicKeyCredential || typeof navigator.credentials?.get !== 'function') {
    throw new DOMException('当前页面无法使用原生 WebAuthn API。', 'NotSupportedError');
  }
}
export function assertNativeRequestBinding(options: PublicKeyCredentialRequestOptions, request: {rp_id?: string; origin?: string; uv?: string}) {
  const override = (options.extensions as ObjectValue | undefined)?.remoteDesktopClientOverride as ObjectValue | undefined;
  if (options.rpId !== request.rp_id || override?.origin !== request.origin || override?.sameOriginWithAncestors !== true
      || (options.userVerification ?? 'preferred') !== (request.uv ?? 'preferred')) {
    throw new DOMException('设备验证选项与当前网站请求不一致，已停止。', 'SecurityError');
  }
}
export function nativeError(error: unknown): NativeError {
  // DOMException can originate from a different realm; retain its actual name/message.
  if (error && typeof error === 'object' && 'name' in error && 'message' in error
      && typeof error.name === 'string' && typeof error.message === 'string') return {name: error.name, message: error.message};
  return {name: 'UnknownError', message: '浏览器验证失败。'};
}
