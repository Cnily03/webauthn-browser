/** Ephemeral outer-browser hints. These values must never enter persistent state or logs. */
export interface LocalNavigationEvent {
  id: string;
  url: string;
  remaining_ms: number;
  mode_generation: number;
}

export function navigationGeneration(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function localNavigationIdentity(id: unknown): {instance: string; sequence: bigint} | null {
  if (typeof id !== 'string') return null;
  const match = /^([a-zA-Z0-9_-]{1,80}):([1-9][0-9]{0,19})$/.exec(id);
  if (!match) return null;
  const sequence = BigInt(match[2]);
  return sequence <= 18_446_744_073_709_551_615n ? {instance: match[1], sequence} : null;
}

export function validateLocalNavigationEvent(value: unknown): LocalNavigationEvent | null {
  if (!value || typeof value !== 'object') return null;
  const event = value as LocalNavigationEvent;
  if (!localNavigationIdentity(event.id)
      || typeof event.url !== 'string' || new TextEncoder().encode(event.url).length > 8192
      || /[\u0000-\u0020\u007f\\]/.test(event.url)
      || !/^https?:\/\/(?:localhost|127\.0\.0\.1)(?::[0-9]+)?(?:[/?#]|$)/i.test(event.url)
      || typeof event.remaining_ms !== 'number' || !Number.isFinite(event.remaining_ms) || event.remaining_ms <= 0
      || !navigationGeneration(event.mode_generation)) return null;
  try {
    const url = new URL(event.url);
    if (!['http:', 'https:'].includes(url.protocol) || !['localhost', '127.0.0.1'].includes(url.hostname)
        || url.username || url.password) return null;
  } catch { return null; }
  // Validation is deliberately separate from serialization: the exact target,
  // including its query and fragment, is only passed to the user's click action.
  return event;
}
