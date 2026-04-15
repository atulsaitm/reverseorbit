import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  timeout: 300000,
});

const READ_RETRY_ATTEMPTS = 3;
const READ_RETRY_BASE_DELAY_MS = 400;
const READ_RETRY_MAX_DELAY_MS = 4000;

const sleep = (delayMs) =>
  new Promise((resolve) => {
    window.setTimeout(resolve, delayMs);
  });

const shouldRetryReadRequest = (error) => {
  if (!axios.isAxiosError(error)) {
    return false;
  }

  if (!error.response) {
    return true;
  }

  const status = error.response.status;
  return status === 429 || status >= 500;
};

const readWithRetry = async (operation) => {
  let attempt = 0;

  for (;;) {
    try {
      return await operation();
    } catch (error) {
      const canRetry = shouldRetryReadRequest(error);
      if (!canRetry || attempt >= READ_RETRY_ATTEMPTS) {
        throw error;
      }

      attempt += 1;
      const retryDelayMs = Math.min(
        READ_RETRY_BASE_DELAY_MS * 2 ** (attempt - 1),
        READ_RETRY_MAX_DELAY_MS,
      );
      await sleep(retryDelayMs);
    }
  }
};

export const listCases = () => readWithRetry(() => api.get("/api/cases"));
export const createCase = (data) => api.post("/api/cases", data);
export const getCase = (caseId) =>
  readWithRetry(() => api.get(`/api/cases/${caseId}`));
export const analyzeCase = (caseId, data = {}) =>
  api.post(`/api/cases/${caseId}/analyze`, data);
export const getTimeline = (caseId) =>
  readWithRetry(() => api.get(`/api/cases/${caseId}/timeline`));
export const getFindings = (caseId) =>
  readWithRetry(() => api.get(`/api/cases/${caseId}/findings`));
export const explainFinding = (caseId, findingId) =>
  readWithRetry(() =>
    api.get(`/api/cases/${caseId}/findings/${findingId}/explain`),
  );
export const getGraph = (caseId, view) =>
  readWithRetry(() => api.get(`/api/cases/${caseId}/graphs/${view}`));
export const getArtifact = (caseId, artifactId) =>
  readWithRetry(() => api.get(`/api/cases/${caseId}/artifacts/${artifactId}`));
export const runAction = (caseId, actionId) =>
  api.post(`/api/cases/${caseId}/actions/${actionId}/run`);
export const exportCase = (caseId) =>
  readWithRetry(() => api.get(`/api/cases/${caseId}/export`));

export const deleteCase = (caseId) => api.delete(`/api/cases/${caseId}`);

export const exportCaseBundle = (caseId) =>
  api.get(`/api/cases/${caseId}/bundle`, { responseType: "blob" });

export const importCaseBundle = (bundle) =>
  api.post("/api/cases/import", bundle);

const API_ERROR_KINDS = new Set([
  "bad_request",
  "not_found",
  "timeout",
  "internal",
]);

const API_KIND_DEFAULT_DETAIL = {
  bad_request: "request is invalid",
  not_found: "requested resource was not found",
  timeout: "request timed out",
  internal: "server error",
  network: "network unavailable",
};

const noticeLevelForKind = (kind) => {
  if (kind === "bad_request" || kind === "not_found") {
    return "warn";
  }
  return "error";
};

const normalizeApiErrorKind = (kind) => {
  if (typeof kind !== "string") {
    return null;
  }
  const normalized = kind.trim().toLowerCase();
  return API_ERROR_KINDS.has(normalized) ? normalized : null;
};

const inferApiErrorKind = (error) => {
  if (!axios.isAxiosError(error)) {
    return "internal";
  }

  const explicitKind = normalizeApiErrorKind(error.response?.data?.kind);
  if (explicitKind) {
    return explicitKind;
  }

  if (!error.response) {
    return error.code === "ECONNABORTED" ? "timeout" : "network";
  }

  const status = error.response.status;
  if (status === 400 || status === 422) {
    return "bad_request";
  }
  if (status === 404) {
    return "not_found";
  }
  if (status === 408 || status === 504) {
    return "timeout";
  }
  return status >= 500 ? "internal" : "internal";
};

export const buildApiNotice = (error, fallbackMessage = "Request failed") => {
  const kind = inferApiErrorKind(error);

  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.error || error.response?.data?.message;
    if (typeof detail === "string" && detail.trim().length > 0) {
      return {
        kind,
        level: noticeLevelForKind(kind),
        message: `${fallbackMessage}: ${detail}`,
      };
    }
    if (error.message) {
      return {
        kind,
        level: noticeLevelForKind(kind),
        message: `${fallbackMessage}: ${error.message}`,
      };
    }
  }

  if (error instanceof Error && error.message) {
    return {
      kind,
      level: noticeLevelForKind(kind),
      message: `${fallbackMessage}: ${error.message}`,
    };
  }

  return {
    kind,
    level: noticeLevelForKind(kind),
    message: `${fallbackMessage}: ${API_KIND_DEFAULT_DETAIL[kind] || "request failed"}`,
  };
};

const WS_INITIAL_RETRY_MS = 1000;
const WS_MAX_RETRY_MS = 30000;
const WS_MAX_RETRIES = 10;

function nextRetryDelayMs(retryAttempt) {
  return Math.min(
    WS_INITIAL_RETRY_MS * 2 ** (retryAttempt - 1),
    WS_MAX_RETRY_MS,
  );
}

export const connectWebSocket = (onEvent, options = {}) => {
  const wsUrl = `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws`;
  let ws = null;
  let retryAttempt = 0;
  let closedManually = false;
  let retryTimer = null;

  const { onStatus, onError } = options;

  const notifyStatus = (status, details = {}) => {
    if (typeof onStatus === "function") {
      onStatus(status, details);
    }
  };

  const notifyError = (message) => {
    const error = new Error(message);
    if (typeof onError === "function") {
      onError(error);
    }
    return error;
  };

  const clearRetryTimer = () => {
    if (retryTimer !== null) {
      window.clearTimeout(retryTimer);
      retryTimer = null;
    }
  };

  const connect = () => {
    if (closedManually) {
      return;
    }

    notifyStatus("connecting", { retryAttempt });

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      retryAttempt = 0;
      clearRetryTimer();
      notifyStatus("open");
    };

    ws.onmessage = (event) => {
      try {
        onEvent(JSON.parse(event.data));
      } catch (error) {
        console.error("[ReverseOrbit WS] Parse error", error);
      }
    };

    ws.onerror = (error) => {
      console.error("[ReverseOrbit WS] Connection error", error);
      notifyError("Realtime connection encountered an error");
    };

    ws.onclose = () => {
      if (closedManually) {
        notifyStatus("closed");
        return;
      }

      if (retryAttempt >= WS_MAX_RETRIES) {
        console.error("[ReverseOrbit WS] Reconnect limit reached");
        notifyStatus("failed", { retryAttempt, maxRetries: WS_MAX_RETRIES });
        notifyError(
          "Realtime updates are unavailable after repeated reconnect attempts",
        );
        return;
      }

      retryAttempt += 1;
      const delayMs = nextRetryDelayMs(retryAttempt);
      notifyStatus("reconnecting", {
        retryAttempt,
        maxRetries: WS_MAX_RETRIES,
        delayMs,
      });
      retryTimer = window.setTimeout(() => {
        retryTimer = null;
        connect();
      }, delayMs);
    };
  };

  connect();

  return {
    close: () => {
      closedManually = true;
      clearRetryTimer();
      if (ws && ws.readyState < WebSocket.CLOSING) {
        ws.close();
      } else {
        notifyStatus("closed");
      }
    },
  };
};

export default api;
