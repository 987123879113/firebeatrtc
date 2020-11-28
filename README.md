# firebeatrtc
Code to unlock Firebeat (pop'n music) RTC recovery.

## Usage
```
usage: keygen.py [-h] (--verify VERIFY | --serial SERIAL) [--keycode KEYCODE] [--retries RETRIES]

optional arguments:
  -h, --help         show this help message and exit
  --verify VERIFY    Verify password
  --serial SERIAL    Serial/license number
  --keycode KEYCODE  Key code
  --retries RETRIES  Retry count
```

## Building Javascript
Note: pscript is required to build the rtcpass.js file required for the webpage.

```
python3 -c "import pscript; pscript.script2js('rtcpass.py')"
```
