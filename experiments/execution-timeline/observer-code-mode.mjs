#!/usr/bin/env node
/** Cooperative timing at an actual Node/V8 dispatcher, with bounded metadata.
 *
 * awaitTool measures a child's outstanding interval. runJS measures synchronous
 * JS dispatch explicitly. Unwrapped async continuations remain unmeasured;
 * subtracting tool waits from invocation wall time never becomes JS CPU time.
 */
import fs from 'node:fs';
import path from 'node:path';
import v8 from 'node:v8';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

const SCHEMA = 'CODE_MODE_DISPATCH_TIMING_V1';
const bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
const runtimeId = crypto.randomUUID();
const ledgers = new Map();
const calls = new Set();
const validId = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && !value.includes('\0');
const now = () => process.hrtime.bigint().toString();

function memory() {
  const sample = process.memoryUsage();
  const heap = v8.getHeapStatistics();
  return { rss_bytes: sample.rss, heap_used_bytes: sample.heapUsed, heap_total_bytes: sample.heapTotal,
    external_bytes: sample.external, array_buffers_bytes: sample.arrayBuffers,
    v8_used_heap_bytes: heap.used_heap_size, v8_total_heap_bytes: heap.total_heap_size,
    v8_heap_limit_bytes: heap.heap_size_limit };
}

function emitter(meta) {
  for (const key of ['run_id', 'agent_id', 'task_id', 'call_id']) {
    if (!validId(meta[key])) throw new Error(`Code Mode requires bounded ${key}`);
  }
  if (typeof meta.ledgerPath !== 'string' || !path.isAbsolute(meta.ledgerPath)) {
    throw new Error('Code Mode requires an absolute ledgerPath');
  }
  let ledger = ledgers.get(meta.ledgerPath);
  if (!ledger) {
    ledger = { fd: fs.openSync(meta.ledgerPath, 'wx', 0o600), sequence: 0 };
    ledgers.set(meta.ledgerPath, ledger);
  }
  const identity = { run_id: meta.run_id, agent_id: meta.agent_id, task_id: meta.task_id, call_id: meta.call_id,
    runtime_id: runtimeId, pid: process.pid, boot_id: bootId };
  return (event, fields = {}) => {
    const row = { schema: SCHEMA, sequence: ++ledger.sequence, ...identity,
      clock: 'NODE_HRTIME_MONOTONIC', occurred_ns: now(), event, ...fields };
    fs.writeSync(ledger.fd, JSON.stringify(row) + '\n');
    if (event === 'CODE_MODE_COMPLETED') fs.fsyncSync(ledger.fd);
    return row;
  };
}

/**
 * Wrap the real gateway's execution entry:
 * await runObservedCodeMode(meta, async ({runJS, awaitTool}) => {
 *   const args = runJS('prepare query', () => prepare());
 *   const result = await awaitTool('search', () => gateway.search(args));
 *   return runJS('format result', () => format(result));
 * });
 *
 * runJS rejects promises: callers explicitly mark each synchronous dispatch
 * slice. awaitTool automatically times fn()'s synchronous JS dispatch, then
 * measures waiting only after fn() returns a Promise/thenable. Plain returned
 * values have no tool wait. Parallel asynchronous tools retain child IDs.
 * Memory samples describe the hosting process and may include other isolates.
 */
export async function runObservedCodeMode(meta, callback) {
  if (typeof callback !== 'function') throw new Error('Code Mode callback required');
  const key = JSON.stringify([meta.run_id, meta.call_id]);
  if (calls.has(key)) throw new Error('duplicate Code Mode run/call identity');
  const emit = emitter(meta);
  calls.add(key);
  let nextSpan = 0;
  let jsActive = false;
  let finished = false;
  const pending = new Set();
  emit('CODE_MODE_STARTED', { runtime: { engine: 'V8', v8_version: process.versions.v8,
    node_version: process.version }, memory: memory() });
  const measureSynchronous = (name, fn, { allowPromise = false, purpose = 'USER_JS', childCallId = null } = {}) => {
    if (finished || !validId(name) || typeof fn !== 'function' || jsActive ||
        (!allowPromise && fn.constructor.name === 'AsyncFunction')) {
      throw new Error('invalid, asynchronous, or nested JS slice');
    }
    const span_id = `js-${++nextSpan}`;
    jsActive = true;
    emit('JS_STARTED', { name, span_id, purpose, child_call_id: childCallId });
    const cpu = typeof process.threadCpuUsage === 'function' ? process.threadCpuUsage() : null;
    const dispatchBegin = now();
    let status = 'SUCCEEDED';
    try {
      const result = fn();
      const isThenable = result != null && typeof result.then === 'function';
      if (isThenable && !allowPromise) {
        throw new Error('runJS requires synchronous work; use awaitTool for child waits');
      }
      return { result, isThenable };
    } catch (error) {
      status = 'FAILED';
      throw error;
    } finally {
      const dispatchEnd = now();
      const used = cpu ? process.threadCpuUsage(cpu) : null;
      emit('JS_COMPLETED', { name, span_id, status, purpose, child_call_id: childCallId, memory: memory(),
        dispatch_begin_ns: dispatchBegin, dispatch_end_ns: dispatchEnd,
        thread_cpu_usec: used ? used.user + used.system : null });
      jsActive = false;
    }
  };
  const runJS = (name, fn) => measureSynchronous(name, fn).result;
  const awaitTool = async (name, fn, { call_id: childCallId } = {}) => {
    if (finished || !validId(name) || typeof fn !== 'function' || (childCallId != null && !validId(childCallId))) {
      throw new Error('invalid tool wait');
    }
    const span_id = `tool-${++nextSpan}`;
    pending.add(span_id);
    let waiting = false;
    let status = 'SUCCEEDED';
    try {
      const dispatch = measureSynchronous(name, fn, {
        allowPromise: true, purpose: 'TOOL_DISPATCH', childCallId: childCallId ?? null });
      if (!dispatch.isThenable) return dispatch.result;
      emit('TOOL_WAIT_STARTED', { name, span_id, child_call_id: childCallId ?? null });
      waiting = true;
      return await dispatch.result;
    }
    catch (error) { status = 'FAILED'; throw error; }
    finally {
      if (waiting) {
        emit('TOOL_WAIT_COMPLETED', { name, span_id, status, child_call_id: childCallId ?? null, memory: memory() });
      }
      pending.delete(span_id);
    }
  };
  let status = 'SUCCEEDED';
  try { return await callback({ runJS, awaitTool }); }
  catch (error) { status = 'FAILED'; throw error; }
  finally {
    finished = true;
    if (pending.size) {
      // An incomplete ledger preserves an unawaited operation rather than
      // claiming that its effects ended with the parent callback.
      fs.fsyncSync(ledgers.get(meta.ledgerPath).fd);
      throw new Error('Code Mode callback returned with unawaited tool operations');
    }
    emit('CODE_MODE_COMPLETED', { status, memory: memory() });
  }
}

export function closeCodeModeLedgers() {
  for (const ledger of ledgers.values()) { fs.fsyncSync(ledger.fd); fs.closeSync(ledger.fd); }
  ledgers.clear();
}

// Local real-V8 smoke; it makes no model/API request.
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--ledger') {
    console.error('usage: node observer-code-mode.mjs --ledger /absolute/new-events.jsonl');
    process.exitCode = 2;
  } else {
    try {
      const result = await runObservedCodeMode({ run_id: 'local-v8-smoke', agent_id: 'local-agent',
        task_id: 'prepare-await-format', call_id: 'code-mode-1', ledgerPath: args[1] }, async ({runJS, awaitTool}) => {
        const values = runJS('prepare input', () => Array.from({length: 200000}, (_, i) => i % 97));
        await Promise.all([
          awaitTool('local tool A', () => new Promise(resolve => setTimeout(resolve, 30)), {call_id: 'tool-a'}),
          awaitTool('local tool B', () => new Promise(resolve => setTimeout(resolve, 15)), {call_id: 'tool-b'}),
        ]);
        return runJS('format output', () => values.reduce((a, b) => a + b, 0));
      });
      console.log(JSON.stringify({ status: 'SUCCEEDED', result, ledger: args[1], runtime: 'Node/V8' }));
    } finally { closeCodeModeLedgers(); }
  }
}
