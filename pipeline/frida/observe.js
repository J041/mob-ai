'use strict';

// Observation-only instrumentation. Every hook calls the original API and
// emits a stable, machine-readable line for pipeline.py to consume.
const ROOT_PATHS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
  '/system/app/Superuser.apk', '/system/app/SuperSU.apk',
  '/data/adb/magisk', '/sbin/.magisk', '/cache/magisk.log'
];
const ROOT_PACKAGES = [
  'com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.noshufou.android.su',
  'com.koushikdutta.superuser', 'com.thirdparty.superuser'
];
const SUSPICIOUS = ['frida', 'gum-js-loop', 'gmain', 'linjector', 're.frida.server'];

function includesAny(value, needles) {
  const text = String(value || '').toLowerCase();
  return needles.some(needle => text.indexOf(needle.toLowerCase()) !== -1);
}

function emit(kind, detail, stack) {
  const event = { source: 'mob-ai-observe', kind, detail: String(detail || '') };
  if (stack) event.stack = String(stack).split('\n').slice(0, 10).join('\n');
  console.log('MOB_AI_EVENT ' + JSON.stringify(event));
}

Java.perform(function () {
  const Exception = Java.use('java.lang.Exception');
  const Log = Java.use('android.util.Log');
  const stack = () => Log.getStackTraceString(Exception.$new());

  try {
    const File = Java.use('java.io.File');
    const exists = File.exists.overload();
    exists.implementation = function () {
      const path = String(this.getAbsolutePath());
      if (includesAny(path, ROOT_PATHS) || includesAny(path, SUSPICIOUS) || path.indexOf('/proc/') !== -1)
        emit('java-file', path, stack());
      return exists.call(this);
    };
  } catch (error) { emit('observer-error', 'File.exists: ' + error); }

  try {
    const Debug = Java.use('android.os.Debug');
    const connected = Debug.isDebuggerConnected.overload();
    connected.implementation = function () {
      emit('debugger', 'Debug.isDebuggerConnected', stack());
      return connected.call(this);
    };
    const waiting = Debug.waitingForDebugger.overload();
    waiting.implementation = function () {
      emit('debugger', 'Debug.waitingForDebugger', stack());
      return waiting.call(this);
    };
  } catch (error) { emit('observer-error', 'Debug: ' + error); }

  try {
    const Props = Java.use('android.os.SystemProperties');
    Props.get.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const key = String(arguments[0]);
        if (/^(ro\.(debuggable|secure|build\.tags)|service\.adb\.root)$/.test(key))
          emit('system-property', key, stack());
        return overload.apply(this, arguments);
      };
    });
  } catch (error) { emit('observer-error', 'SystemProperties: ' + error); }

  try {
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const command = String(arguments[0]);
        if (/\b(su|which|getprop|mount|id)\b|magisk/i.test(command))
          emit('process-command', command, stack());
        return overload.apply(this, arguments);
      };
    });
  } catch (error) { emit('observer-error', 'Runtime.exec: ' + error); }

  try {
    const APM = Java.use('android.app.ApplicationPackageManager');
    APM.getPackageInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const pkg = String(arguments[0]);
        if (ROOT_PACKAGES.indexOf(pkg) !== -1 || includesAny(pkg, SUSPICIOUS))
          emit('package-query', pkg, stack());
        return overload.apply(this, arguments);
      };
    });
  } catch (error) { emit('observer-error', 'PackageManager: ' + error); }
});

['access', 'stat', 'lstat', 'open', 'readlink'].forEach(function (name) {
  const target = Module.findGlobalExportByName(name);
  if (!target) return;
  Interceptor.attach(target, {
    onEnter(args) {
      if (args[0].isNull()) return;
      const path = args[0].readUtf8String();
      if (includesAny(path, ROOT_PATHS) || includesAny(path, SUSPICIOUS) || path.indexOf('/proc/') !== -1)
        emit('native-file', name + ':' + path, Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 10));
    }
  });
});

['ptrace', 'prctl'].forEach(function (name) {
  const target = Module.findGlobalExportByName(name);
  if (!target) return;
  Interceptor.attach(target, { onEnter() { emit('native-antidebug', name); } });
});

const strstr = Module.findGlobalExportByName('strstr');
if (strstr) Interceptor.attach(strstr, {
  onEnter(args) {
    if (args[1].isNull()) return;
    const needle = args[1].readUtf8String();
    if (includesAny(needle, SUSPICIOUS)) emit('anti-frida', needle);
  }
});

emit('ready', 'observation hooks installed');
