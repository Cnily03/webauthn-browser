// Clipboard bytes exist only in the current browser API call / transport frame.
// Never retain a last value, retry payload, history, or background-read timer.
export const MAX_CLIPBOARD_BYTES = 1024 * 1024;
export type ClipboardState = { kind: 'ready' | 'read' | 'copy' | 'unavailable' | 'error'; message: string };
type ClipboardPort = Pick<Clipboard, 'readText' | 'writeText' | 'write'>;
type Frame = { type: string; id: string; text?: string; error?: string };
const ready: ClipboardState = { kind: 'ready', message: '' };

export class LiveClipboard {
  private live = true;
  private generation = 0;
  private pendingRead: string | null = null;
  private retryableRead: string | null = null;
  private armedCopy: { id: string | null; generation: number; resolve: (blob: Blob) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> } | null = null;
  constructor(private send: (frame: Frame) => void, private update: (state: ClipboardState) => void,
    private port: ClipboardPort | undefined = navigator.clipboard, private secure = window.isSecureContext) {}

  private abandonRead() {
    if (this.pendingRead) this.send({ type: 'read_result', id: this.pendingRead, error: 'denied' });
    this.pendingRead = null;
    this.retryableRead = null;
  }
  private cancelCopy() {
    if (!this.armedCopy) return;
    clearTimeout(this.armedCopy.timer);
    this.armedCopy.generation = -1;
    this.armedCopy.reject(new Error('Clipboard operation cancelled'));
    this.armedCopy = null;
  }
  dispose() { this.live = false; this.generation++; this.pendingRead = null; this.retryableRead = null; this.cancelCopy(); }
  receive(frame: Frame) {
    if (!this.live) return;
    if (frame.type === 'copy_failed') {
      this.abandonRead(); this.generation++; this.cancelCopy();
      this.update({ kind: 'copy', message: frame.error === 'too_large' ? '复制超过 1 MiB，未同步' : '复制未同步' });
      return;
    }
    if (frame.type === 'cancel') {
      if (this.pendingRead === frame.id) { this.generation++; this.pendingRead = null; this.retryableRead = null; this.update({ kind: 'ready', message: '粘贴已结束' }); }
      return;
    }
    if (frame.type === 'read') {
      this.abandonRead();
      this.cancelCopy();
      const generation = ++this.generation;
      this.pendingRead = frame.id;
      void this.read(frame.id, generation);
    } else if (frame.type === 'copy' && typeof frame.text === 'string') {
      this.abandonRead();
      const generation = ++this.generation;
      if (new TextEncoder().encode(frame.text).length > MAX_CLIPBOARD_BYTES) {
        this.cancelCopy(); this.send({ type: 'copy_result', id: frame.id, error: 'too_large' });
        this.update({ kind: 'copy', message: '复制超过 1 MiB，未同步' }); return;
      }
      if (this.armedCopy) {
        clearTimeout(this.armedCopy.timer);
        this.armedCopy.id = frame.id;
        this.armedCopy.generation = generation;
        this.armedCopy.resolve(new Blob([frame.text], { type: 'text/plain' }));
        this.armedCopy = null;
        // The gesture-started write promise owns completion reporting.
      } else void this.write(frame.id, frame.text, generation);
    }
  }
  retryRead() {
    if (!this.live || !this.pendingRead || this.retryableRead !== this.pendingRead) return;
    // Invoke readText directly in the icon's click handler, before activation
    // expires. The browser owns its permission prompt; never pre-read/cache.
    void this.read(this.pendingRead, ++this.generation);
  }
  private async read(id: string, generation: number) {
    this.retryableRead = null;
    this.update(ready);
    try {
      if (!this.secure || !this.port?.readText) throw new Error('unavailable');
      const text = await this.port.readText();
      if (!this.live || generation !== this.generation || this.pendingRead !== id) return;
      this.pendingRead = null;
      if (new TextEncoder().encode(text).length > MAX_CLIPBOARD_BYTES) {
        this.send({ type: 'read_result', id, error: 'too_large' });
        this.update({ kind: 'error', message: '剪贴板文本超过 1 MiB' }); return;
      }
      this.send({ type: 'read_result', id, text });
      this.update(ready);
    } catch {
      if (!this.live || generation !== this.generation || this.pendingRead !== id) return;
      if (!this.secure || !this.port?.readText) {
        this.pendingRead = null;
        this.send({ type: 'read_result', id, error: 'unavailable' });
        this.update({ kind: 'unavailable', message: '剪贴板不可用' });
      } else {
        this.retryableRead = id;
        this.update({ kind: 'read', message: '' });
      }
    }
  }
  private async write(id: string, text: string, generation: number) {
    try {
      if (!this.secure || !this.port?.writeText) throw new Error('unavailable');
      await this.port.writeText(text);
      if (!this.live || generation !== this.generation) return;
      this.send({ type: 'copy_result', id }); this.update(ready);
    } catch {
      if (!this.live || generation !== this.generation) return;
      this.send({ type: 'copy_result', id, error: 'denied' });
      this.update({ kind: this.secure ? 'copy' : 'unavailable', message: this.secure ? '复制未获允许' : '剪贴板不可用' });
    }
  }
  copyAgain(triggerRemoteCopy: () => void) {
    if (!this.live) return;
    this.abandonRead(); this.generation++; this.cancelCopy();
    if (!this.secure || !this.port?.write || typeof ClipboardItem === 'undefined') {
      this.update({ kind: 'copy', message: '复制不可用' }); return;
    }
    // Ask the browser to write while this click still has transient activation.
    // Resolve only from a NEW remote Copy, never from previously received text.
    let resolve!: (blob: Blob) => void, reject!: (error: Error) => void;
    const nextCopy = new Promise<Blob>((yes, no) => { resolve = yes; reject = no; });
    // Browsers may reject write() without consuming the ClipboardItem promise.
    void nextCopy.catch(() => {});
    const armed: NonNullable<LiveClipboard['armedCopy']> = { id: null, generation: this.generation, resolve, reject, timer: setTimeout(() => { if (this.armedCopy === armed) { this.cancelCopy(); this.update({ kind: 'copy', message: '未收到复制内容' }); } }, 10000) };
    this.armedCopy = armed;
    let result: Promise<void>;
    try { result = this.port.write([new ClipboardItem({ 'text/plain': nextCopy })]); }
    catch { this.cancelCopy(); this.update({ kind: 'copy', message: '复制未获允许' }); return; }
    void result.then(() => { if (this.live && this.generation === armed.generation) { if (armed.id) this.send({ type: 'copy_result', id: armed.id }); this.update(ready); } }).catch(() => {
      if (!this.live || this.generation !== armed.generation) return;
      if (this.armedCopy === armed) this.cancelCopy();
      if (armed.id) this.send({ type: 'copy_result', id: armed.id, error: 'denied' });
      this.update({ kind: 'copy', message: '复制未获允许' });
    });
    try { triggerRemoteCopy(); } catch { this.cancelCopy(); }
  }
}
