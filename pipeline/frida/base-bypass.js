'use strict';

// Generated/loaded by pipeline.py. Raise BYPASS_LEVEL only after reviewing the
// previous iteration's report: 1=Java, 2=filesystem/libc, 3=anti-Frida strings.
const BYPASS_LEVEL = parseInt('{{LEVEL}}', 10);
const ENABLED = new Set({{MODULES}});
const enabled = name => ENABLED.has(name);
const emit = (kind, detail) => send({ source: 'mob-ai', kind, detail });

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
  const s = String(value || '').toLowerCase();
  return needles.some(n => s.indexOf(n.toLowerCase()) !== -1);
}

Java.perform(function () {
  if (enabled('java-files')) {
    const File = Java.use('java.io.File');
    const exists = File.exists.overload();
    exists.implementation = function () {
      const path = String(this.getAbsolutePath());
      if (includesAny(path, ROOT_PATHS) || (enabled('anti-frida') && includesAny(path, SUSPICIOUS))) {
        emit('hide-file', path);
        return false;
      }
      return exists.call(this);
    };
  }

  if (enabled('debugger')) {
    const Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
      emit('debugger-check', 'isDebuggerConnected=false');
      return false;
    };
    Debug.waitingForDebugger.implementation = function () { return false; };
  }

  if (enabled('properties')) try {
    const Props = Java.use('android.os.SystemProperties');
    const get = Props.get.overload('java.lang.String');
    get.implementation = function (key) {
      const k = String(key);
      const safe = { 'ro.debuggable': '0', 'ro.secure': '1', 'service.adb.root': '0', 'ro.build.tags': 'release-keys' };
      if (Object.prototype.hasOwnProperty.call(safe, k)) {
        emit('property', k + '=' + safe[k]);
        return safe[k];
      }
      return get.call(this, key);
    };
  } catch (_) {}

  if (enabled('rootbeer')) try {
    const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.class.getDeclaredMethods().forEach(function (method) {
      const name = String(method.getName());
      try {
        RootBeer[name].overloads.forEach(function (overload) {
          if (overload.returnType.className === 'boolean') {
            overload.implementation = function () {
              emit('rootbeer', name + '=false');
              return false;
            };
          }
        });
      } catch (_) {}
    });
  } catch (_) {}

  if (enabled('packages')) try {
    const APM = Java.use('android.app.ApplicationPackageManager');
    APM.getPackageInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const pkg = String(arguments[0]);
        if (ROOT_PACKAGES.indexOf(pkg) !== -1) {
          emit('hide-package', pkg);
          const NameNotFound = Java.use('android.content.pm.PackageManager$NameNotFoundException');
          throw NameNotFound.$new(pkg);
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (_) {}

  if (enabled('commands')) try {
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const command = String(arguments[0]);
        if (/\b(su|which)\b|magisk/i.test(command)) {
          emit('hide-command', command);
          throw Java.use('java.io.IOException').$new('Command not found');
        }
        return overload.apply(this, arguments);
      };
    });
  } catch (_) {}
});

if (enabled('native-files') && BYPASS_LEVEL >= 2) {
  ['access', 'stat', 'lstat', 'open'].forEach(function (name) {
    const target = Module.findGlobalExportByName(name);
    if (!target) return;
    Interceptor.attach(target, {
      onEnter(args) {
        this.path = args[0].isNull() ? '' : args[0].readUtf8String();
        this.hide = includesAny(this.path, ROOT_PATHS) || (enabled('anti-frida') && includesAny(this.path, SUSPICIOUS));
      },
      onLeave(retval) {
        if (this.hide) {
          emit('hide-native-file', this.path);
          retval.replace(-1);
        }
      }
    });
  });
}

if (enabled('native-antidebug') && BYPASS_LEVEL >= 3) {
  const ptrace = Module.findGlobalExportByName('ptrace');
  if (ptrace) Interceptor.attach(ptrace, {
    onLeave(retval) {
      emit('hide-native-antidebug', 'ptrace=-1');
      retval.replace(-1);
    }
  });
}

if (enabled('anti-frida') && BYPASS_LEVEL >= 3) {
  const strstr = Module.findGlobalExportByName('strstr');
  if (strstr) Interceptor.attach(strstr, {
    onEnter(args) {
      this.needle = args[1].isNull() ? '' : args[1].readUtf8String();
      this.hide = includesAny(this.needle, SUSPICIOUS);
    },
    onLeave(retval) {
      if (this.hide && !retval.isNull()) {
        emit('hide-string', this.needle);
        retval.replace(ptr(0));
      }
    }
  });
}

emit('ready', 'bypass level ' + BYPASS_LEVEL);
