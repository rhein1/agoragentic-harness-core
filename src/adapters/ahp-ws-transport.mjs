import { TextDecoder } from 'node:util';
import WebSocket from 'ws';

const utf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Node 18-compatible AHP WebSocket transport.
 *
 * Endpoint policy is validated by the public observer before this function is
 * called. This transport deliberately has no reconnect, redirect, headers,
 * cookies, authentication, proxy, or global-WebSocket behavior.
 */
export async function createAhpLoopbackWebSocketTransport(endpoint, {
  maxFrameBytes,
  maxBufferedFrames = 16,
  maxBufferedBytes = maxFrameBytes * 4,
  connectTimeoutMs,
  signal,
} = {}) {
  const frames = [];
  const waiters = [];
  let terminal = null;
  let closeCount = 0;
  let bufferedBytes = 0;

  const socket = new WebSocket(endpoint, {
    followRedirects: false,
    handshakeTimeout: connectTimeoutMs,
    maxPayload: maxFrameBytes,
    perMessageDeflate: false,
  });

  const settleWaiters = () => {
    while (waiters.length && (frames.length || terminal)) {
      const waiter = waiters.shift();
      if (frames.length) {
        const queued = frames.shift();
        bufferedBytes -= queued.bytes;
        waiter.resolve(queued.frame);
      } else if (terminal?.error) {
        waiter.reject(terminal.error);
      } else {
        waiter.resolve(null);
      }
    }
  };

  const end = (error = null) => {
    if (terminal) return;
    if (error) {
      frames.length = 0;
      bufferedBytes = 0;
    }
    terminal = { error };
    settleWaiters();
  };

  socket.on('message', (data, isBinary) => {
    if (terminal) return;
    try {
      const bytes = toBytes(data);
      if (bytes.byteLength > maxFrameBytes) {
        end(observerTransportError('frame_limit'));
        socket.terminate();
        return;
      }
      if (frames.length >= maxBufferedFrames || bufferedBytes + bytes.byteLength > maxBufferedBytes) {
        end(observerTransportError('inbound_buffer_limit'));
        socket.terminate();
        return;
      }
      const frame = isBinary
        ? { kind: 'binary', data: bytes }
        : { kind: 'text', text: utf8.decode(bytes) };
      frames.push({ frame, bytes: bytes.byteLength });
      bufferedBytes += bytes.byteLength;
      settleWaiters();
    } catch {
      end(observerTransportError('invalid_utf8'));
      socket.terminate();
    }
  });
  socket.on('close', (code) => {
    if ([1000, 1001, 1005].includes(code)) end();
    else end(observerTransportError('websocket_transport_error'));
  });
  socket.on('error', () => end(observerTransportError('websocket_transport_error')));

  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      fn(value);
    };
    const onOpen = () => finish(resolve);
    const onError = () => finish(reject, observerTransportError('websocket_connect_failed'));
    const onAbort = () => {
      socket.terminate();
      finish(reject, observerTransportError('cancelled'));
    };
    socket.once('open', onOpen);
    socket.once('error', onError);
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
  });

  return Object.freeze({
    async send(message) {
      if (terminal || socket.readyState !== WebSocket.OPEN) {
        throw observerTransportError('websocket_closed');
      }
      const text = typeof message === 'string' ? message : JSON.stringify(message);
      if (Buffer.byteLength(text, 'utf8') > maxFrameBytes) {
        throw observerTransportError('outbound_frame_limit');
      }
      await new Promise((resolve, reject) => {
        socket.send(text, (error) => {
          if (error) reject(observerTransportError('websocket_send_failed'));
          else resolve();
        });
      });
    },

    recv() {
      if (frames.length) {
        const queued = frames.shift();
        bufferedBytes -= queued.bytes;
        return Promise.resolve(queued.frame);
      }
      if (terminal?.error) return Promise.reject(terminal.error);
      if (terminal) return Promise.resolve(null);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },

    close() {
      closeCount += 1;
      if (closeCount > 1) return;
      end();
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.terminate();
      }
    },
  });
}

function toBytes(data) {
  if (data instanceof Uint8Array) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) {
    const joined = Buffer.concat(data.map((entry) => Buffer.from(entry)));
    return new Uint8Array(joined.buffer, joined.byteOffset, joined.byteLength);
  }
  return new Uint8Array(Buffer.from(data));
}

function observerTransportError(code) {
  const error = new Error(code);
  error.name = 'AhpObserverTransportError';
  error.code = code;
  return error;
}
