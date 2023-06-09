/*
LICENSE

    Copyright (c) 2023 by J.W https://github.com/jakwings/frida.y

      TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

     0. You just DO WHAT THE FUCK YOU WANT TO.

DESCRIPTION

    Hook into the Unity Mono runtime of a PC game and alter the frame rate.

    $ frida -l unity.mono.js -P '{"FrameRate":30}' -p PID  # JS debug console
    $ frida ... -P '{"FrameRate":30,"keep":true}' -q --eternalize  # persist

    Note: Limiting FPS cannot solve all overheating issues.
          https://gamedev.stackexchange.com/a/185916
          https://unity.com/how-to/gpu-optimization

    TODO: throttle gpu batch-rendering (no way to enable software rendering)
    TODO: frida-(core/gum/gumjs)-devkit + https://neutralino.js.org/

REFERENCE

    + https://frida.re/docs/javascript-api/
    + https://docs.unity3d.com/ScriptReference/Application-targetFrameRate.html
    + https://docs.unity3d.com/ScriptReference/QualitySettings-vSyncCount.html
    + https://docs.unity3d.com/ScriptReference/Rendering.OnDemandRendering.html

    - https://tomorrowisnew.com/posts/Hacking-Mono-Games-With-Frida/
    - https://www.mono-project.com/docs/advanced/runtime/
    - https://www.mono-project.com/docs/advanced/embedding/
    - http://docs.go-mono.com/?link=root:/embed
    - https://github.com/mono/mono/tree/main/docs
    - https://github.com/mono/mono/tree/main/mono/metadata
*/

// Frida REPL auto-completion cannot detect "let" and "const" declarations.
var $MODULE_NAMES = [
  'UnityEngine',
  //'Assembly-CSharp',
];

const MAX_NUMBER = 32767;

// Both Application.targetFrameRate and QualitySettings.vSyncCount let you control your game's frame rate for smoother performance. targetFrameRate controls the frame rate by specifying the number of frames your game tries to render per second, whereas vSyncCount specifies the number of screen refreshes to allow between frames. [...] On all other platforms, Unity ignores the value of targetFrameRate if you set vSyncCount. When you use vSyncCount, Unity calculates the target frame rate by dividing the platform's default target frame rate by the value of vSyncCount. For example, if the platform's default render rate is 60 fps and vSyncCount is 2, Unity tries to render the game at 30 frames per second.
var cfg_VSyncCount = 0;
var cfg_FrameRate = 15;
var cfg_keep = false;

const $ = Object.create(null);
const _ = Object.create(null);  // a messy vault for $$$

function Or$(a, b) {
  return a == null || Number.isNaN(a) ? b : a;
}

function Clamp$(n, a, b) {
  return Math.max(a, Math.min(n, b));
}

function DeepCopy$(json) {
  return JSON.parse(JSON.stringify(json));
}

function Assert$(ok, msg) {
  if (!ok) throw new Error(msg || 'unknown error');
}

function LogInfo$(msg) {
  console.log(`[INFO] ${msg}`);
}

function LogWarning$(msg) {
  console.error(`[WARNING] ${msg}`);
}

function LogError$(err, msg) {
  if (err.stack) console.error(err.stack);
  const errmsg = String(msg != null ? msg : (err.message || err));
  console.error(`[ERROR] ${errmsg}`);
}

function Begin$(stage, parameters) {
  try {
    console.log(`[BEGIN] stage: ${stage}`);
    console.log(`[PARAM] ${JSON.stringify(parameters)}`);

    cfg_VSyncCount = Clamp$(Or$(Number(parameters.VSyncCount), cfg_VSyncCount) | 0, 0, MAX_NUMBER);
    cfg_FrameRate = Clamp$(Or$(Number(parameters.FrameRate), cfg_FrameRate) | 0, 0, MAX_NUMBER);
    cfg_keep = Boolean(parameters.keep);

    console.log(`[PARAM] VSyncCount = ${cfg_VSyncCount}`);
    console.log(`[PARAM] FrameRate  = ${cfg_FrameRate}`);
    console.log(`[PARAM] keep       = ${cfg_keep}`);

    Setup$();
    Hack$();
  } catch (err) {
    LogError$(err);  // for REPL
    throw err;
  } finally {
    if ($.LibMono && $.LibMono.Detach$) {
      $.LibMono.Detach$();  // avoid deadlock when closing the game
    }
  }
}

function FindModuleByName$(...names) {
  let lib = null;
  if (!names.some(name => (lib = Process.findModuleByName(name)) != null)) {
    LogWarning$(`failed to find module: ${names.join(' / ')}`);
    lib = {base: new NativePointer(NULL)};
  }
  Module.ensureInitialized(lib.name);
  lib.GetExportByName$ = GetExportByName$;
  lib.FindExportByName$ = FindExportByName$;
  return lib;
}

function GetExportByName$(name, ...rest) {
  const lib = this;
  const fun = lib.FindExportByName$(name, ...rest);
  Assert$(fun != null, `failed to import ${name} from ${lib.name}`);
  return fun;
}

function FindExportByName$(name, sig_ret, sig_args, ...rest) {
  const lib = this;
  const $address = !lib.base.isNull() ? lib.findExportByName(name)
                                      : Module.findExportByName(null, name);
  if ($address == null) return null;
  const sig = DeepCopy$([sig_ret, sig_args]);
  const fun = new NativeFunction($address, sig_ret, sig_args, ...rest);
  fun.GetLibrary$ = () => lib;  // GC retain
  fun.GetSignature$ = () => sig;
  return fun;
}

function Setup$() {
  $.TRUE = 1;
  $.FALSE = 0;
  $.BOOL = (x => x ? $.TRUE : $.FALSE);

  $.Modules = Object.create(null);

  //\ basic utils
  {
    $.LibMono = FindModuleByName$('mono-2.0-bdwgc.dll', 'libmonobdwgc-2.0.so', 'libmonobdwgc-2.0.dylib');

    function Import$(name, sig_ret, sig_args, ...rest) {
      // delay loading to avoid errors from importing non-existent functions
      let fun = null;
      $[name] = (...args) => {
        if (!fun) {
          fun = $[name] = $.LibMono.GetExportByName$(name, sig_ret, sig_args, ...rest);
        }
        return fun(...args);
      };
      const sig = DeepCopy$([sig_ret, sig_args]);
      $[name].GetSignature$ = () => sig;
    }
    globalThis.Import$ = Import$;
  }

  //\ attach to the main thread
  {
    // MonoDomain * (void)
    Import$('mono_get_root_domain', 'pointer', []);

    // MonoDomain * (void)
    Import$('mono_domain_get', 'pointer', []);

    // MonoThread * (void)
    Import$('mono_thread_current', 'pointer', []);

    // MonoThread * (MonoDomain *domain)
    Import$('mono_thread_attach', 'pointer', ['pointer']);

    // void (MonoThread *thread)
    Import$('mono_thread_detach', 'void', ['pointer']);

    $.LibMono.Detach$ = () => {
      $.LibMono.$prev_domain = null;
      $.LibMono.$root_domain = null;
    };

    // Attach the current thread (that was created outside the runtime or managed code) to the runtime. The thread was created on behalf of the runtime and the runtime is responsible for it.
    // Effect: enter GC Unsafe Mode (non-preemptive / cooperatively-suspended / non-blocking)
    $.LibMono.Attach$ = () => {
      $.LibMono.Detach$();

      const $root_domain = $.mono_get_root_domain();
      Assert$(!$root_domain.isNull());
      const $curr_domain = $.mono_domain_get();
      //Assert$(!$curr_domain.isNull());

      if (!$curr_domain.equals($root_domain)) {
        const $that_thread = $.mono_thread_attach($root_domain);
        const $this_thread = $.mono_thread_current();
        Assert$(!$this_thread.isNull());
        Assert$($this_thread.equals($that_thread));

        $.LibMono.Detach$ = () => {
          $.mono_thread_detach($this_thread);
          $.LibMono.$prev_domain = null;
          $.LibMono.$root_domain = null;
          $.LibMono.Detach$ = () => {};
        };
      }

      $.LibMono.$prev_domain = $curr_domain;
      $.LibMono.$root_domain = $root_domain;
    };

    $.LibMono.Attach$();
  }

  //\ assemble Mono modules
  try {
    // typedef void (*GFunc)(gpointer data, gpointer user_data);
    // void (GFunc func, gpointer user_data)
    Import$('mono_assembly_foreach', 'void', ['pointer', 'pointer']);

    // MonoImage * (MonoAssembly *assembly)
    Import$('mono_assembly_get_image', 'pointer', ['pointer']);

    // const char * (MonoImage *image)
    Import$('mono_image_get_name', 'pointer', ['pointer']);

    // MonoClass * (MonoImage *image, const char *name_space, const char *name)
    Import$('mono_class_from_name', 'pointer', ['pointer', 'pointer', 'pointer']);

    // MonoClassField * (MonoClass *klass, const char *name)
    Import$('mono_class_get_field_from_name', 'pointer', ['pointer', 'pointer']);

    // MONO_API uint32_t (MonoClassField *field)
    Import$('mono_field_get_offset', 'uint32', ['pointer']);

    // MonoMethod * (MonoClass *klass, const char *name, int param_count)
    Import$('mono_class_get_method_from_name', 'pointer', ['pointer', 'pointer', 'int']);

    // MonoMethodDesc * (const char *name, mono_bool include_namespace)
    Import$('mono_method_desc_new', 'pointer', ['pointer', 'bool']);

    // void (MonoMethodDesc *desc)
    Import$('mono_method_desc_free', 'void', ['pointer']);

    // MonoMethod * (MonoMethodDesc *desc, MonoImage *image)
    Import$('mono_method_desc_search_in_image', 'pointer', ['pointer', 'pointer']);

    // void * (MonoMethod *method)
    Import$('mono_compile_method', 'pointer', ['pointer']);

    // MonoClass * (void)
    Import$('mono_get_boolean_class', 'pointer', []);

    // MonoString * (MonoDomain *domain, const char *text)
    Import$('mono_string_new', 'pointer', ['pointer', 'pointer']);

    function Class$($class) {
      $class.GetFieldByName$ = GetFieldByName$;
      $class.GetMethodByName$ = GetMethodByName$;
      $class.GetNativeMethodByName$ = GetNativeMethodByName$;
      return $class;
    }
    globalThis.Class$ = Class$;

    function Field$($field) {
      $field.GetFieldOffset$ = GetFieldOffset$;
      return $field;
    }
    globalThis.Field$ = Field$;

    function Method$($method) {
      $method.ToCompiledMethod$ = ToCompiledMethod$;
      return $method;
    }
    globalThis.Method$ = Method$;

    function Jitted$($jitted) {
      $jitted.ToNativeMethod$ = ToNativeMethod$;
      return $jitted;
    }
    globalThis.Jitted$ = Jitted$;

    function GetClassByName$(name) {
      const $image = this;
      const $namespace = Memory.allocUtf8String($image.GetName$());
      const $name = Memory.allocUtf8String(name);
      const $class = $.mono_class_from_name($image, $namespace, $name);
      Assert$(!$class.isNull());
      $class.GetImage$ = () => $image;  // GC retain
      return Class$($class);
    }

    function GetFieldByName$(name) {
      const $class = this;
      const $name = Memory.allocUtf8String(name);
      const $field = $.mono_class_get_field_from_name($class, $name);
      Assert$(!$field.isNull());
      $field.GetClass$ = () => $class;  // GC retain
      return Field$($field);
    }

    function GetFieldOffset$(base = 0) {
      const $field = this;
      const offset = $.mono_field_get_offset($field);
      return base + offset;
    }

    function GetMethodByName$(name, arity = 0) {
      const $class = this;
      const $name = Memory.allocUtf8String(name);
      const $method = $.mono_class_get_method_from_name($class, $name, arity);
      Assert$(!$method.isNull());
      $method.GetClass$ = () => $class;  // GC retain
      return Method$($method);
    }

    function GetNativeMethodByName$(name, sig_ret, sig_args, ...rest) {
      const $class = this;
      const $method = $class.GetMethodByName$(name, sig_args.length);
      Assert$($method != null);
      const $jitted = $method.ToCompiledMethod$();
      Assert$(!$jitted.isNull());
      return $jitted.ToNativeMethod$(sig_ret, sig_args, ...rest);
    }

    // e.g. 'UnityEngine.QualitySettings::get_vSyncCount'
    // e.g. 'UnityEngine.Application::set_targetFrameRate(int)'
    function GetMethodByDesc$(pattern) {
      const $image = this;
      const $pattern = Memory.allocUtf8String(pattern);
      const $desc = $.mono_method_desc_new($pattern, $.FALSE);
      Assert$(!$desc.isNull());
      const $method = $.mono_method_desc_search_in_image($desc, $image);
      $.mono_method_desc_free($desc);
      Assert$(!$method.isNull());
      $method.GetImage$ = () => $image;  // GC retain
      return Method$($method);
    }

    function ToCompiledMethod$() {
      const $method = this;
      const $jitted = $.mono_compile_method($method);
      Assert$(!$jitted.isNull());
      $jitted.GetMethod$ = () => $method;  // GC retain
      return Jitted$($jitted);
    }

    function ToNativeMethod$(sig_ret, sig_args, ...rest) {
      const $jitted = this;
      const sig = DeepCopy$([sig_ret, sig_args]);
      const fun = new NativeFunction($jitted, sig_ret, sig_args, ...rest);
      fun.GetJitted$ = () => $jitted;  // GC retain
      fun.GetSignature$ = () => sig;
      return fun;
    }

    $.mono_assembly_foreach(
      new NativeCallback(($assembly, user_data) => {
        const $image = $.mono_assembly_get_image($assembly);
        const $name = !$image.isNull() ? $.mono_image_get_name($image) : null;
        const name = $name != null ? $name.readUtf8String() : null;
        //LogInfo$(`Image at ${$image}: ${name}`);
        if (name != null && $MODULE_NAMES.includes(name)) {
          $image.GetName$ = () => name;
          $image.GetClassByName$ = GetClassByName$;
          $image.GetMethodByDesc$ = GetMethodByDesc$;
          $.Modules[name] = $image;
        }
      }, ... $.mono_assembly_foreach.GetSignature$()),
      NULL  // user_data
    );

    $MODULE_NAMES.forEach(name => Assert$($.Modules[name] != null));
  } catch (err) {
    $.LibMono.Detach$();
    throw err;
  }
}

function Hack$() {
  _.call$ = (desc, sig_ret, sig_args, ...rest) => {
    const $method = $.Modules.UnityEngine.GetMethodByDesc$(desc);
    const method = $method.ToCompiledMethod$().ToNativeMethod$(sig_ret, sig_args);
    return method(...rest);
  };

  try {
    _.screen_width = _.call$('UnityEngine.Screen::get_width', 'int32', []);
    LogInfo$(`_.screen_width = ${_.screen_width}`);
    _.screen_height = _.call$('UnityEngine.Screen::get_height', 'int32', []);
    LogInfo$(`_.screen_height = ${_.screen_height}`);
    _.screen_fullscreen = _.call$('UnityEngine.Screen::get_fullScreen', 'bool', []);
    LogInfo$(`_.screen_fullscreen = ${Boolean(_.screen_fullscreen)}`);
  } catch (err) {
    LogError$(err);
  }

  _.$Application = $.Modules['UnityEngine'].GetClassByName$('Application');
  _.$QualitySettings = $.Modules['UnityEngine'].GetClassByName$('QualitySettings');

  try {
    _.get_vSyncCount = _.$QualitySettings.GetNativeMethodByName$('get_vSyncCount', 'int32', []);
  } catch (err) {
    LogError$(err);
    _.get_vSyncCount = () => {};
  }
  _.set_vSyncCount = _.$QualitySettings.GetNativeMethodByName$('set_vSyncCount', 'void', ['int32']);

  try {
    _.get_targetFrameRate = _.$Application.GetNativeMethodByName$('get_targetFrameRate', 'int32', []);
  } catch (err) {
    LogError$(err);
    _.get_targetFrameRate = () => {};
  }
  _.set_targetFrameRate = _.$Application.GetNativeMethodByName$('set_targetFrameRate', 'void', ['int32']);

  LogInfo$(`_.get_vSyncCount() old = ${_.get_vSyncCount()}`);
  try {
    // FIXME: Error: access violation accessing 0x0 (safely ignored?)
    //        mono_compile_method interferes with previously compiled methods
    _.set_vSyncCount(cfg_VSyncCount);
  } catch (err) {
    LogError$(err);
  }
  LogInfo$(`_.get_vSyncCount() new = ${_.get_vSyncCount()}`);

  LogInfo$(`_.get_targetFrameRate() old = ${_.get_targetFrameRate()}`);
  try {
    _.set_targetFrameRate(cfg_FrameRate);
  } catch (err) {
    LogError$(err);
  }
  LogInfo$(`_.get_targetFrameRate() new = ${_.get_targetFrameRate()}`);

  Interceptor.replace(_.set_vSyncCount,
    new NativeCallback(count => {
      LogInfo$(`_.set_vSyncCount(old = ${count})`);
      if (cfg_keep) count = cfg_VSyncCount;
      count = count >= 0 ? count : 0;
      try {
        _.set_vSyncCount(count);
      } catch (err) {
        LogError$(err);
      }
      count = _.get_vSyncCount();
      LogInfo$(`_.set_vSyncCount(new = ${count})`);
    }, ... _.set_vSyncCount.GetSignature$())
  );

  Interceptor.replace(_.set_targetFrameRate,
    new NativeCallback(frame_rate => {
      LogInfo$(`_.set_targetFrameRate(old = ${frame_rate})`);
      if (cfg_keep) frame_rate = cfg_FrameRate;
      // -1 ==> from Screen.currentResolution.refreshRate to Infinity
      frame_rate = frame_rate > 0 ? frame_rate : -1;
      try {
        _.set_targetFrameRate(frame_rate);
      } catch (err) {
        LogError$(err);
      }
      frame_rate = _.get_targetFrameRate();
      LogInfo$(`_.set_targetFrameRate(new = ${frame_rate})`);
    }, ... _.set_targetFrameRate.GetSignature$())
  );

  Interceptor.flush();
}

function End$(stage) {
  console.log(`[END] stage: ${stage}`);
}

rpc.exports = {
  init: Begin$,
  dispose: End$,
};
