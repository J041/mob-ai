'use strict';

// Read-only diagnostic instrumentation. The worker replaces the placeholder
// with an allowlisted action array and owns all artifact writes and limits.
const ACTIONS = new Set({{ACTIONS}});
const MAX_DUMPS = 5;
const MAX_DUMP_BYTES = 1024 * 1024;
let dumpCount = 0;

function enabled(name) { return ACTIONS.has(name); }
function safeString(value) {
  try { return String(value); } catch (_) { return '<unavailable>'; }
}
function moduleLocation(address) {
  try {
    const module = Process.findModuleByAddress(address);
    return module ? { module: module.name, offset: address.sub(module.base).toString() } : {};
  } catch (_) { return {}; }
}
function emit(kind, detail) {
  send({ source: 'mob-ai-diagnostics', kind: kind, detail: detail || {} });
}
function backtrace(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 16).map(DebugSymbol.fromAddress).map(String);
  } catch (_) { return []; }
}
function dumpRange(base, size, reason, kind) {
  kind = kind || 'runtime-payload';
  if (kind === 'runtime-payload' && !enabled('dump_runtime_payloads')) return;
  if (kind === 'runtime-dex' && !enabled('capture_runtime_dex')) return;
  if (dumpCount >= MAX_DUMPS) return;
  const length = Math.min(Number(size), MAX_DUMP_BYTES);
  if (!Number.isFinite(length) || length <= 0) return;
  try {
    const bytes = base.readByteArray(length);
    const location = moduleLocation(base);
    dumpCount += 1;
    send({
      source: 'mob-ai-diagnostics', kind: kind,
      detail: Object.assign({ address: base.toString(), size: length, reason: reason }, location)
    }, bytes);
  } catch (error) {
    emit('diagnostic-error', { action: 'dump_runtime_payloads', error: safeString(error) });
  }
}

if (enabled('trace_dynamic_loading')) {
  ['dlopen', 'android_dlopen_ext'].forEach(function (name) {
    const target = Module.findGlobalExportByName(name);
    if (!target) return;
    Interceptor.attach(target, {
      onEnter(args) {
        this.path = args[0].isNull() ? '' : safeString(args[0].readCString());
        this.caller = moduleLocation(this.returnAddress);
      },
      onLeave(retval) {
        emit('dynamic-load', { name: name, path: this.path, result: retval.toString(), caller: this.caller });
      }
    });
  });
  const dlsym = Module.findGlobalExportByName('dlsym');
  if (dlsym) Interceptor.attach(dlsym, {
    onEnter(args) {
      this.symbol = args[1].isNull() ? '' : safeString(args[1].readCString());
      this.caller = moduleLocation(this.returnAddress);
    },
    onLeave(retval) {
      emit('dynamic-symbol', { symbol: this.symbol, result: retval.toString(), caller: this.caller });
    }
  });
}

if (enabled('trace_signal_handlers')) {
  ['signal', 'sigaction'].forEach(function (name) {
    const target = Module.findGlobalExportByName(name);
    if (!target) return;
    Interceptor.attach(target, {
      onEnter(args) {
        emit('signal-handler', {
          name: name, signal: args[0].toInt32(), handler: safeString(args[1]),
          caller: moduleLocation(this.returnAddress), backtrace: backtrace(this.context)
        });
      }
    });
  });
}

if (enabled('capture_native_exceptions')) {
  Process.setExceptionHandler(function (details) {
    emit('native-exception', {
      type: details.type,
      address: safeString(details.address),
      memory: details.memory || null,
      location: moduleLocation(details.address),
      backtrace: backtrace(details.context)
    });
    return false;
  });
}

if (enabled('trace_termination_calls')) {
  ['abort', 'exit', '_exit', 'raise', 'kill', 'tgkill'].forEach(function (name) {
    const target = Module.findGlobalExportByName(name);
    if (!target) return;
    Interceptor.attach(target, {
      onEnter(args) {
        emit('termination-call', {
          name: name,
          caller: moduleLocation(this.returnAddress),
          arguments: [safeString(args[0]), safeString(args[1]), safeString(args[2])],
          backtrace: backtrace(this.context)
        });
      }
    });
  });
}

if (enabled('trace_jni_registration')) {
  try {
    const art = Process.getModuleByName('libart.so');
    const candidates = art.enumerateSymbols().filter(function (symbol) {
      return symbol.name.indexOf('RegisterNatives') !== -1 && symbol.name.indexOf('CheckJNI') === -1;
    });
    const seen = new Set();
    candidates.forEach(function (symbol) {
      const key = symbol.address.toString();
      if (seen.has(key)) return;
      seen.add(key);
      Interceptor.attach(symbol.address, {
        onEnter(args) {
          const methods = args[2];
          const count = Math.min(Number(args[3].toInt32()), 512);
          const entries = [];
          for (let index = 0; index < count; index += 1) {
            try {
              const row = methods.add(index * Process.pointerSize * 3);
              const name = row.readPointer().readCString();
              const signature = row.add(Process.pointerSize).readPointer().readCString();
              const fn = row.add(Process.pointerSize * 2).readPointer();
              entries.push({ name: name, signature: signature, address: fn.toString(), location: moduleLocation(fn) });
            } catch (_) { break; }
          }
          if (entries.length) emit('jni-registration', { symbol: symbol.name, methods: entries });
        }
      });
    });
    emit('jni-tracer-ready', { hooks: seen.size });
  } catch (error) {
    emit('diagnostic-error', { action: 'trace_jni_registration', error: safeString(error) });
  }
}

if (enabled('inventory_executable_mappings') || enabled('dump_runtime_payloads')) {
  const known = new Set();
  function inspectRange(base, size, reason) {
    const key = base.toString() + ':' + String(size);
    if (known.has(key)) return;
    known.add(key);
    let range = null;
    try { range = Process.findRangeByAddress(base); } catch (_) {}
    const detail = {
      base: base.toString(), size: Number(size), reason: reason,
      protection: range ? range.protection : '', file: range && range.file ? range.file.path : ''
    };
    if (enabled('inventory_executable_mappings')) emit('executable-mapping', detail);
    if (!detail.file || /memfd:|deleted|anon_inode/i.test(detail.file)) dumpRange(base, size, reason);
  }
  Process.enumerateRanges('r-x').forEach(function (range) {
    known.add(range.base.toString() + ':' + String(range.size));
  });
  const mprotect = Module.findGlobalExportByName('mprotect');
  if (mprotect) Interceptor.attach(mprotect, {
    onEnter(args) {
      this.base = args[0]; this.size = Number(args[1]); this.executable = (args[2].toInt32() & 4) !== 0;
    },
    onLeave(retval) {
      if (this.executable && retval.toInt32() === 0) inspectRange(this.base, this.size, 'mprotect');
    }
  });
  const mmap = Module.findGlobalExportByName('mmap');
  if (mmap) Interceptor.attach(mmap, {
    onEnter(args) { this.size = Number(args[1]); this.executable = (args[2].toInt32() & 4) !== 0; },
    onLeave(retval) { if (this.executable && !retval.equals(ptr(-1))) inspectRange(retval, this.size, 'mmap'); }
  });
  setInterval(function () {
    try {
      Process.enumerateRanges('r-x').forEach(function (range) {
        inspectRange(range.base, range.size, 'periodic-snapshot');
      });
    } catch (error) {
      emit('diagnostic-error', { action: 'inventory_executable_mappings', error: safeString(error) });
    }
  }, 100);
}

if (enabled('capture_runtime_dex')) {
  const dexSeen = new Set();
  setInterval(function () {
    try {
      const candidates = Process.enumerateRanges('rw-').concat(Process.enumerateRanges('r--')).slice(0, 1024);
      candidates.forEach(function (range) {
        const key = range.base.toString() + ':' + String(range.size);
        if (dexSeen.has(key) || range.size < 40) return;
        const magic = new Uint8Array(range.base.readByteArray(4));
        const isDex = magic[0] === 0x64 && magic[1] === 0x65 && magic[2] === 0x78 && magic[3] === 0x0a;
        const isCdex = magic[0] === 0x63 && magic[1] === 0x64 && magic[2] === 0x65 && magic[3] === 0x78;
        if (!isDex && !isCdex) return;
        dexSeen.add(key);
        let length = range.size;
        try { if (isDex) length = Math.min(length, range.base.add(32).readU32()); } catch (_) {}
        emit('runtime-dex-found', { base: range.base.toString(), size: length, compact: isCdex });
        dumpRange(range.base, length, 'periodic-dex-scan', 'runtime-dex');
      });
    } catch (error) {
      emit('diagnostic-error', { action: 'capture_runtime_dex', error: safeString(error) });
    }
  }, 250);
}

emit('diagnostics-ready', { actions: Array.from(ACTIONS) });
