Here are my assembly of Frida scripts.

To use them, install Frida first.  For instructions, go to https://frida.re/

------------------------------------------------

# framerate/unity.mono.js

*Hook into the Unity Mono runtime of a PC game and alter the frame rate.*

Hopefully your overheating problem is solved by lowering the FPS.

```sh
# the executable of your game developed with Unity Mono
name='Hot Summer'

# use "keep":false to make this a one-time adjustment
# btw enters live debug console: read the js source code for reference
frida -l unity.mono.js -P '{"FrameRate":30, "keep":true}' -n "$name"

# ditto but quit this program immediately without opening debug console
# needs to restart the game if you want to use a different frame rate
frida -q --eternalize -l unity.mono.js -P '{"FrameRate":30, "keep":true}' -n "$name"

# ditto but this frame rate won't persist and may be modified in-game
frida -q -l unity.mono.js -P '{"FrameRate":30}' -n "$name"
```

# framerate/renpy.js

Hook into the runtime of a Ren'Py game and fake the _screen_ refresh rate.

```sh
# Example: launch the game; screen fps = 5; movie fps = 5
frida -l renpy.js -P '{"Screen":5,"Movie":30}' -f /path/to/game

# ditto; play without entering the debug console
nohup /path/to/game >/dev/null & p="$!"
frida -l renpy.js -P '{"Screen":5,"Movie":30}' -p "${p}" -q --eternalize
```

Note: When in powersave mode frame rate of game window is 5 by default.
Note: When not in powersave mode, _screen_ refresh rate is the default.
Note: Movie frame rate is not controlled by `preferences.gl_framerate`.
Note: `preferences.gl_powersave` and `preferences.gl_framerate` are meh.

# To Be Continued...
