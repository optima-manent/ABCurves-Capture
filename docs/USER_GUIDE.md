# Participant guide

## Before you start

Install USBPcap 1.5.4.0, connect the USB mouse or USB receiver you intend to use,
and close applications that may switch mouse profiles during the run. Native
Bluetooth-only mice, PS/2 mice, and touchpads are not supported capture sources.
The collector does not upload anything automatically.

Prefer a mouse-only receiver. If your keyboard shares the receiver, do not type
passwords, messages, or other private text while collection is active, including
while the trainer is paused or in the background.

## Collecting a session

1. Open ABCurves Capture Trainer. If an earlier run was interrupted, the app
   first finishes its local file safely. Continue unlocks when that check is
   done.
2. Read the privacy summary and choose your physical mouse by its friendly name.
3. Move that mouse in several directions and click once. The bounded check
   confirms that the selected Windows mouse and its exact physical USB device
   are both active. Windows may ask permission for this check.
4. Choose sensitivity and presentation preferences, then select Full Research
   or Quick Test. Quick Test runs one 10-second block for each challenge.
   Windows may ask permission once more when collection begins. Neither prompt
   retries on its own.
5. Play normally. `Esc` pauses and `F11` toggles fullscreen. Alt-Tab and focus
   loss pause automatically; returning starts a short resume countdown. A
   manual `Esc` pause waits for you to choose Resume. Timed targets fade and
   remain clickable for 60 ms beyond their original fade duration.
6. Let saving finish. The final screen shows a file ending in
   `_SEND_THIS.zip`. That is the only file a study organizer needs.

## What is collected

The session contains exact-device USB records, optional decoded mouse reports,
target geometry, gameplay outcomes, timing anchors, and quality annotations.
Detailed Windows movement from other mice is not retained. The app does not
intentionally copy usernames, native device paths, container IDs, or device
serials into session metadata, and it does not capture screenshots, microphone
audio, or personal files.

The raw PCAP preserves every USB record from the selected mouse or receiver so
unusual formats remain recoverable. It can therefore contain control, vendor,
descriptor, or serial bytes exchanged with that device. On a shared
mouse-and-keyboard receiver it can also contain the actual key reports from the
keyboard. Those bytes are not interpreted by the trainer, but they remain in
the raw capture and may be decoded later. The privacy screen calls this out
before collection.

## If something goes wrong

- Permission denied: choose Try again only if you want another UAC prompt.
- Mouse certification unclear: retry once with a clear movement and one full
  click, or reconnect the selected mouse/receiver and Rescan.
- Focus lost: return to the app and let the resume countdown finish; the prior
  session remains valid.
- Display/interface problem: the affected target is skipped and play pauses
  while graphics recover; the selected-mouse capture remains active.
- No sound or a sound-device problem: continue playing; optional feedback may
  be silent and collection is unaffected.
- Capture/device/storage failure: let the app preserve the available evidence.
  The archive records whether an authoritative USB prefix was verified, so an
  interrupted archive can still be valuable without claiming all data is usable.

If a crash leaves an unfinished session, reopen the trainer and let the startup
file check finish. It recovers complete source records, keeps questionable
bytes for researcher review, and creates a missing `_SEND_THIS.zip` when safe.
If another process still owns the session or the files cannot be certified,
the original directory is left unchanged; keep it for the organizer.
