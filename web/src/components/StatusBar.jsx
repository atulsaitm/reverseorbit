import { Activity, AlertTriangle, Wifi, WifiOff } from 'lucide-react';
import { useStore } from '../store';

export default function StatusBar() {
  const progress = useStore((state) => state.runProgress);
  const message = useStore((state) => state.runMessage);
  const event = useStore((state) => state.runEvent);
  const status = useStore((state) => state.runStatus);
  const wsConnectionState = useStore((state) => state.wsConnectionState);
  const systemNotice = useStore((state) => state.systemNotice);
  const clearSystemNotice = useStore((state) => state.clearSystemNotice);
  const requestDataRefresh = useStore((state) => state.requestDataRefresh);

  const showRunState = status !== 'idle' || !!message || !!event;
  const progressPercent = Math.round((progress || 0) * 100);
  const progressWidth = showRunState ? Math.max((progress || 0) * 100, 2) : 0;
  const connectionMeta = getConnectionMeta(wsConnectionState);
  const noticeTone = getNoticeTone(systemNotice?.level);
  const noticeKindLabel = getNoticeKindLabel(systemNotice?.kind);
  const canRetryNotice = isRetryableNotice(systemNotice);

  const handleRetry = () => {
    if (!systemNotice) {
      return;
    }
    requestDataRefresh();
    clearSystemNotice(systemNotice.source);
  };

  if (!showRunState && !systemNotice && wsConnectionState === 'open') {
    return null;
  }

  return (
    <div className="glass-sm border-b border-white/[0.04] px-5 py-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2.5">
          <span className="text-[11px] font-medium text-accent-warm uppercase tracking-wider flex items-center gap-2">
            <Activity className={`w-3 h-3 ${showRunState ? 'animate-pulse' : ''}`} />
            {event || 'idle'}
          </span>
          <span className={`text-[10px] uppercase tracking-wide flex items-center gap-1.5 ${connectionMeta.className}`}>
            {connectionMeta.icon}
            {connectionMeta.label}
          </span>
        </div>
        {showRunState && <span className="text-[11px] text-white/30 mono">{progressPercent}%</span>}
      </div>
      {showRunState && (
        <>
          <div className="w-full h-1 bg-white/[0.04] rounded-full overflow-hidden">
            <div className="h-full progress-bar rounded-full transition-all duration-700 ease-out" style={{ width: `${progressWidth}%` }} />
          </div>
          {message && <p className="text-[11px] text-white/20 mt-1.5 truncate">{message}</p>}
        </>
      )}
      {systemNotice?.message && (
        <div className={`mt-2 rounded-lg border px-3 py-2 flex items-start justify-between gap-3 ${noticeTone.boxClass}`}>
          <p className="text-[11px] flex items-start gap-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span className="space-y-1">
              {noticeKindLabel && (
                <span className="inline-block text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-current/40">
                  {noticeKindLabel}
                </span>
              )}
              <span className="block">{systemNotice.message}</span>
            </span>
          </p>
          <div className="flex items-center gap-2">
            {canRetryNotice && (
              <button
                type="button"
                onClick={handleRetry}
                className={`text-[10px] uppercase tracking-wide ${noticeTone.buttonClass}`}
              >
                Retry
              </button>
            )}
            <button
              type="button"
              onClick={() => clearSystemNotice(systemNotice.source)}
              className={`text-[10px] uppercase tracking-wide ${noticeTone.buttonClass}`}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function getConnectionMeta(state) {
  if (state === 'open') {
    return {
      label: 'realtime online',
      className: 'text-emerald-300/80',
      icon: <Wifi className="w-3 h-3" />,
    };
  }
  if (state === 'connecting' || state === 'reconnecting') {
    return {
      label: state === 'connecting' ? 'connecting' : 'reconnecting',
      className: 'text-amber-300/80',
      icon: <Activity className="w-3 h-3 animate-pulse" />,
    };
  }
  if (state === 'failed' || state === 'closed') {
    return {
      label: state === 'failed' ? 'realtime offline' : 'socket closed',
      className: 'text-red-300/90',
      icon: <WifiOff className="w-3 h-3" />,
    };
  }
  return {
    label: 'unknown',
    className: 'text-white/40',
    icon: <WifiOff className="w-3 h-3" />,
  };
}

function getNoticeTone(level) {
  if (level === 'warn') {
    return {
      boxClass: 'border-amber-300/30 bg-amber-500/10 text-amber-100',
      buttonClass: 'text-amber-200/90 hover:text-amber-100',
    };
  }
  return {
    boxClass: 'border-red-400/30 bg-red-500/10 text-red-100',
    buttonClass: 'text-red-200/90 hover:text-red-100',
  };
}

function getNoticeKindLabel(kind) {
  if (kind === 'bad_request') {
    return 'input';
  }
  if (kind === 'not_found') {
    return 'missing';
  }
  if (kind === 'timeout') {
    return 'timeout';
  }
  if (kind === 'internal') {
    return 'internal';
  }
  if (kind === 'network') {
    return 'network';
  }
  return null;
}

function isRetryableNotice(notice) {
  if (!notice || notice.source !== 'api') {
    return false;
  }
  return notice.kind === 'timeout' || notice.kind === 'network' || notice.kind === 'internal';
}

