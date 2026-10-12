interface EngineConnectionSnapshot {
  connected: boolean;
  control_connected?: boolean;
  native_qr_mode?: boolean;
  mode_switching?: boolean;
  mode_error?: string | null;
}

interface EngineConnection {
  kind: 'disconnected' | 'switching' | 'native' | 'ready' | 'unready';
  state: 'offline' | 'connecting' | 'connected';
  message: string;
}

/** Presentation only: native mode does not authorize software-proxy requests. */
export function describeEngineConnection(snapshot: EngineConnectionSnapshot): EngineConnection {
  if (snapshot.mode_error === 'extension_upgrade_required') return {kind: 'unready', state: 'offline', message: '浏览器验证扩展版本过旧或不兼容，请等待扩展重新加载；若仍未恢复，请更新并重新创建容器，保留现有数据卷'};
  if (snapshot.control_connected === false) return {kind: 'disconnected', state: 'offline', message: '验证引擎连接已断开'};
  if (snapshot.mode_error) {
    const failure = snapshot.mode_error.startsWith('native_') ? '原生验证模式切换失败' : '验证器拦截恢复失败';
    const reason = snapshot.mode_error.endsWith('_timeout') ? '：浏览器未确认切换' : '：浏览器报告错误';
    return {kind: 'unready', state: 'offline', message: failure + reason + (snapshot.mode_switching ? '，正在恢复…' : '，请重新启动容器浏览器后重试')};
  }
  if (snapshot.mode_switching) return {kind: 'switching', state: 'connecting', message: '验证模式切换中…'};
  if (snapshot.native_qr_mode && snapshot.control_connected === true) return {kind: 'native', state: 'connected', message: '原生验证模式'};
  if (snapshot.connected) return {kind: 'ready', state: 'connected', message: '验证事件已连接'};
  return {kind: 'unready', state: 'offline', message: '虚拟验证器未就绪'};
}
