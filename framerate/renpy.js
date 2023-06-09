/*
LICENSE

    Copyright (c) 2023 by J.W https://github.com/jakwings/frida.y

      TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

     0. You just DO WHAT THE FUCK YOU WANT TO.

DESCRIPTION

    Hook into the runtime of a Ren'Py game and fake the _screen_ refresh rate.

    # Example: screen fps = 5; movie fps = 5
    $ frida -l renpy.js -P '{"Screen":5,"Movie":30}' -f /path/to/game  # play

    # ditto; play without entering the debug console
    $ nohup /path/to/game >/dev/null & p="$!"
    $ frida -l renpy.js -P '{"Screen":5,"Movie":30}' -p "${p}" -q --eternalize

    Note: When in powersave mode frame rate of game window is 5 by default.
    Note: When not in powersave mode, _screen_ refresh rate is the default.
    Note: Movie frame rate is not controlled by preferences.gl_framerate.
    Note: preferences.gl_powersave and preferences.gl_framerate are meh.

    Pure renpy script solution:

        # 1. Fake screen refresh rate (not movie frame rate)
        # 2. Do not skip movies despite environment variable RENPY_LESS_UPDATES
        init python hide:

            _constant = True

            # also emulates python3 "nonlocal" and works around game reload
            def wrap(src):
                while hasattr(src, 'hack'): src = src.hack
                src = [src]
                def wrap(fun):
                    fun = [fun]
                    def hack(*args, **opts):
                        fun[0].hack = src[0]
                        return fun[0](*args, **opts)
                    hack.hack = src[0]
                    return hack
                return wrap

            # Ren'Py 6.99.14.3063 or later (8.1.1.23060707 / 7.6.1.23060707)
            if renpy.version_tuple >= (6, 99, 14, 3063):

                @wrap(renpy.display.get_info)
                def hacked_get_info(*args, **opts):
                    info = hacked_get_info.hack(*args, **opts)
                    print('[INFO] refresh rate (old) = ' + str(info.refresh_rate))
                    if preferences.gl_powersave:
                        info.refresh_rate = 5
                    else:
                        info.refresh_rate = preferences.gl_framerate or 30
                    print('[INFO] refresh rate (new) = ' + str(info.refresh_rate))
                    return info

                renpy.display.get_info = hacked_get_info

            # Ren'Py 6.9.1a or later (8.1.1.23060707 / 7.6.1.23060707)
            if not hasattr(renpy, 'version_tuple') or renpy.version_tuple >= (6, 9, 1):

                if not (renpy.display.video.movie_start == renpy.display.video.movie_start_fullscreen == renpy.display.video.movie_start_displayable):
                    raise '[ERROR] movie_start'

                @wrap(renpy.display.video.movie_start)
                def hacked_movie_start(filename, *args, **opts):
                    movie_start = hacked_movie_start.hack
                    if renpy.game.less_updates:
                        print('[INFO] movie_start (new): ' + filename)
                        renpy.game.less_updates = False
                        ret = movie_start(filename, *args, **opts)
                        renpy.game.less_updates = True
                        return ret
                    else:
                        print('[INFO] movie_start (old): ' + filename)
                        return movie_start(filename, *args, **opts)

                renpy.display.video.movie_start = hacked_movie_start
                renpy.display.video.movie_start_fullscreen = hacked_movie_start
                renpy.display.video.movie_start_displayable = hacked_movie_start

REFERENCE

    + https://frida.re/docs/javascript-api/
    - https://github.com/renpy/renpy/blob/master/renpy/display/__init__.py
    - https://github.com/renpy/renpy/blob/master/renpy/gl/gldraw.pyx
    - https://github.com/renpy/renpy/blob/master/renpy/gl2/gl2draw.pyx
    - https://github.com/renpy/pygame_sdl2/blob/master/src/pygame_sdl2/display.pyx
*/

const MAX_NUMBER = 32767;

// fake screen refresh rate
var cfg_Screen = 5;
// custom fps for movie
var cfg_Movie = 15;
// special hacks
var cfg_Platform = null;

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

function Throw$(msg) {
  throw new Error(msg);
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

function Global$() {
  $.TRUE = 1;
  $.FALSE = 0;
  $.BOOL = (x => x ? $.TRUE : $.FALSE);
}

function Begin$(stage, parameters) {
  try {
    Global$();

    console.log(`[BEGIN] stage: ${stage}`);
    console.log(`[PARAM] ${JSON.stringify(parameters)}`);

    cfg_Screen = Clamp$(Or$(Number(parameters.Screen), cfg_Screen) | 0, 0, MAX_NUMBER);
    cfg_Movie = Clamp$(Or$(Number(parameters.Movie), cfg_Movie) | 0, 0, MAX_NUMBER);
    cfg_Platform = parameters.Platform;

    console.log(`[PARAM] Screen = ${cfg_Screen}`);
    console.log(`[PARAM] Movie  = ${cfg_Movie}`);
    if (cfg_Platform != null) console.log(`[PARAM] Platform = ${cfg_Platform}`);

    Hack$();
  } catch (err) {
    LogError$(err);  // for REPL
    throw err;
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

function HackScreen$() {
  $.LibRenpy = $.LibRenpy || FindModuleByName$('librenpython.dll', 'librenpython.so', 'librenpython.dylib');

  // int (int displayIndex, SDL_DisplayMode * mode)
  _.SDL_GetCurrentDisplayMode = $.LibRenpy.FindExportByName$(
    'SDL_GetCurrentDisplayMode',
    'int', ['int', 'pointer']
  );

  if (cfg_Platform !== 'macos' && _.SDL_GetCurrentDisplayMode != null) {

    const c_mod = new CModule(`
        #include <stddef.h>
        #include <stdint.h>

        typedef struct {
            uint32_t format;
            int width;
            int height;
            int refresh_rate;
            void *driver_data;
        } SDL_DisplayMode;

        int SIZE_OF_SDL_DisplayMode = sizeof(SDL_DisplayMode);
        int OFFSET_OF_refresh_rate = offsetof(SDL_DisplayMode, refresh_rate);
    `);
    _.SIZE_OF_SDL_DisplayMode = c_mod.SIZE_OF_SDL_DisplayMode.readInt();
    _.OFFSET_OF_refresh_rate = c_mod.OFFSET_OF_refresh_rate.readInt();

    Interceptor.replace(_.SDL_GetCurrentDisplayMode,
      new NativeCallback((index, $mode) => {
        try {
          const ret = _.SDL_GetCurrentDisplayMode(index, $mode);
          LogInfo$(`_.SDL_GetCurrentDisplayMode(?, ${$mode}) = ${ret}`);
          if (ret !== 0) return ret;
          Assert$(Memory.protect($mode, _.SIZE_OF_SDL_DisplayMode, 'rw-'));
          const $rate = $mode.add(_.OFFSET_OF_refresh_rate);
          let rate = $rate.readInt();
          LogInfo$(`SDL_DisplayMode(${$mode})->refresh_rate (old) = ${rate}`);
          rate = rate === 0 || rate > cfg_Screen ? cfg_Screen : rate;
          $rate.writeInt(rate);
          LogInfo$(`SDL_DisplayMode(${$mode})->refresh_rate (new) = ${rate}`);
          return ret;
        } catch (err) {
          LogError$(err);
          Interceptor.revert(_.SDL_GetCurrentDisplayMode);
          return -1;
        }
      }, ... _.SDL_GetCurrentDisplayMode.GetSignature$())
    );

  } else if (cfg_Platform === 'macos' && Process.platform === 'darwin') {

    $.CoreGraphics = FindModuleByName$('CoreGraphics');

    _.CGDisplayModeGetRefreshRate = $.CoreGraphics.GetExportByName$(
      'CGDisplayModeGetRefreshRate',
      'double', ['pointer']
    );

    Interceptor.replace(_.CGDisplayModeGetRefreshRate,
      new NativeCallback($mode => {
        try {
          let rate = _.CGDisplayModeGetRefreshRate($mode);
          LogInfo$(`_.CGDisplayModeGetRefreshRate(${$mode}) old = ${rate}`);
          rate = rate === 0 || rate > cfg_Screen ? cfg_Screen : rate;
          LogInfo$(`_.CGDisplayModeGetRefreshRate(${$mode}) new = ${rate}`);
          return rate;
        } catch (err) {
          LogError$(err);
          Interceptor.revert(_.CGDisplayModeGetRefreshRate);
          return cfg_Screen;
        }
      }, ... _.CGDisplayModeGetRefreshRate.GetSignature$())
    );

  } else {
    const supported = ['window', 'linux', 'darwin'].indexOf(Process.platform) >= 0;
    Assert$(supported, `unsupported platform: ${Process.platform}`);
    Throw$(`Ren'Py 6.99.14.3063 or later (8.1.1.23060707 / 7.6.1.23060707) required`);
  }
}

function HackMovie$() {
  // https://github.com/renpy/renpy/blob/master/module/ffmedia.c
  // Ren'Py 6.99.9.1154 or later (8.1.1.23060707 / 7.6.1.23060707)
  // ffmpeg version 0.11 to 4.3.1 ?
  // decoding is expensive: avcodec_send_packet, avcodec_decode_video2
  // libavfilter "fps" won't help because it needs decoded frames
  // AVCodecContext->skip_frame doesn't work for some videos (there's hope?)
  // too troublesome to stalk-stab av_read_frame and fake along the way
  LogWarning$(`TODO: undo this function?`);
}

function Hack$() {
  let hacked_Screen = false;
  let hacked_Movie = false;

  try {
    // verify it by renpy.get_refresh_rate()
    HackScreen$();
    hacked_Screen = true;
  } catch (err) {
    LogError$(err, `[FPS.Screen] ${err.message}`);
  }

  try {
    HackMovie$();
    //hacked_Movie = true;
  } catch (err) {
    LogError$(err, `[FPS.Movie] ${err.message}`);
  }

  Interceptor.flush();

  Assert$(hacked_Screen || hacked_Movie, 'This frida script did not work at all!');
}

function End$(stage) {
  console.log(`[END] stage: ${stage}`);
}

rpc.exports = {
  init: Begin$,
  dispose: End$,
};
