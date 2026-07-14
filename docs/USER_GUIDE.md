# Participant guide

## Before you start

- Install USBPcap 1.5.4.0.
- Connect the USB mouse or USB receiver you want to record.
- Close software that may change the mouse profile during the run.
- If your keyboard shares the receiver, avoid typing private text until the
  session is finished.

The collector saves locally and never uploads on its own.

## Collecting a session

1. Open `ABCurves Capture Trainer.exe`. If an earlier run was interrupted, let
   the startup file check finish.
2. Read the privacy summary and choose your mouse by its friendly name.
3. Move the mouse in a few directions and click once. Windows may ask for
   permission while the app matches it to the USB capture stream.
4. Choose your sensitivity and visual/sound preferences, then select Full
   Research or Quick Test.
5. Play normally. `Esc` pauses and `F11` toggles fullscreen. Alt-Tab or focus
   loss pauses the game and resumes with a short countdown when you return.
6. Let saving finish. Keep the file ending in `_SEND_THIS.zip`.

Quick Test runs one 10-second block for each challenge. The full routine runs the
complete study plan.

## What is in the session

The archive contains raw USB records from the selected mouse or receiver,
decoded mouse reports when available, targets, clicks, outcomes, timing, device
information, and integrity checks.

It does not contain screenshots, microphone audio, or personal files. A shared
mouse-and-keyboard receiver may include keyboard reports in the raw PCAP; see
[Privacy](PRIVACY.md) for details.

## If something goes wrong

- **Permission denied:** retry only if you want another Windows permission
  prompt.
- **Mouse check unclear:** move clearly in several directions, complete one
  click, or reconnect the mouse/receiver and rescan.
- **Focus lost:** return to the app and wait for the resume countdown.
- **No sound:** keep playing; sound feedback is optional.
- **Capture, device, or storage error:** let the app finish preserving whatever
  it captured.

If the app closes unexpectedly, reopen it and let the startup check finish. It
will recover complete records where possible and create the missing ZIP when the
session is safe to package.
