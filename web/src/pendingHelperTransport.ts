export interface PendingHelperSocket {socket?: WebSocket; opened: boolean; startedAt: number; retryAt?: number}
type Candidate = PendingHelperSocket & {socket: WebSocket};

// Establish the actual transport before a backend capability exists. This
// controller never sends a pair frame or forwards data. take() transfers the
// same socket to the owner-bound protocol once a real session is available.
export class PendingHelperTransport {
  private candidate: Candidate | null = null;
  private generation = 0;
  private running = false;
  private url = '';
  private retryAt: number | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;

  start(url: string): void {
    this.stop(); this.running = true; this.url = url; this.connect();
  }
  take(url: string): PendingHelperSocket | null {
    if (url !== this.url || !this.running || (this.candidate && this.candidate.socket.readyState > 1)) { this.stop(); return null; }
    // Transfer the remaining retry delay even between physical socket attempts.
    // A live candidate retains its original establishment deadline on handoff.
    const candidate: PendingHelperSocket | null = this.candidate ?? (this.retryAt === null ? null : {opened: false, startedAt: Date.now(), retryAt: this.retryAt});
    this.candidate = null; this.running = false; this.generation++;
    this.clearTimer(); this.retryAt = null; if (candidate?.socket) this.detach(candidate.socket);
    return candidate;
  }
  stop(): void {
    this.running = false; this.generation++; this.clearTimer(); this.retryAt = null; this.closeCandidate();
  }
  private clearTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private detach(socket: WebSocket): void { socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null; }
  private closeCandidate(): void {
    const candidate = this.candidate; this.candidate = null;
    if (candidate) { this.detach(candidate.socket); try { candidate.socket.close(); } catch { /* Already closed. */ } }
  }
  private connect(): void {
    if (!this.running) return;
    this.timer = null; this.retryAt = null;
    const generation = ++this.generation;
    try {
      const startedAt = Date.now();
      const candidate = {socket: new WebSocket(this.url), opened: false, startedAt};
      this.candidate = candidate;
      const current = () => this.running && generation === this.generation && this.candidate === candidate;
      const retry = (delay: number) => {
        if (!current()) return;
        this.generation++; this.clearTimer(); this.closeCandidate();
        if (delay === 0) this.connect();
        else { this.retryAt = Date.now() + delay; this.timer = setTimeout(() => this.connect(), delay); }
      };
      candidate.socket.onopen = () => { if (current()) { candidate.opened = true; this.clearTimer(); } };
      const failed = () => retry(candidate.opened ? 1000 : Math.max(0, 1000 - (Date.now() - candidate.startedAt)));
      candidate.socket.onerror = failed;
      candidate.socket.onclose = failed;
      this.timer = setTimeout(() => { if (current() && !candidate.opened) retry(0); }, 1000);
    } catch {
      if (this.running && generation === this.generation) { this.retryAt = Date.now() + 1000; this.timer = setTimeout(() => this.connect(), 1000); }
    }
  }
}
