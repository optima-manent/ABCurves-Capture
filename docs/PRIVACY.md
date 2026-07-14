# Privacy and participant control

The public collector stores mouse/target research evidence locally and never
uploads automatically. Submission is a separate, explicit participant action.

The stable `user_id` used for leakage-safe research splits is a random 128-bit
local pseudonym. It is not derived from a Windows account, SID, hostname,
device path, serial number, IP address, or hardware fingerprint. The participant
can reset it by deleting the local `participant_id.txt`; future sessions will
then no longer group with earlier ones.

The session includes sanitized VID/PID/product and optional descriptor evidence
used to decode the selected mouse. The app does not intentionally copy native
device paths, container IDs, device serials, or usernames into session metadata,
and it does not capture screenshots, audio recordings, personal files, or
detailed Windows movement from other mice.

The short mouse check transiently observes interrupt traffic on the selected
USB root so it can correct Windows/USBPcap address disagreements. Those
broad-root payloads are neither written to disk nor returned to the participant
process; the helper keeps only bounded counters and payload-change state in
memory until it exits.

After that check, USBPcap filters by the observed mouse device address in the
kernel. The raw artifact deliberately retains every record from that one
address so unusual mouse formats remain recoverable offline. That raw stream can
contain control, vendor, descriptor, or serial bytes exchanged with the selected
device even though those values are not copied into app metadata.

A shared mouse-and-keyboard receiver can also contribute the keyboard's actual
key and media-button reports from that physical receiver. The collector does not
interpret them as keyboard input, but they remain in the raw PCAP and may be
decoded later. Participants should prefer a mouse-only receiver and must not
type passwords, messages, or other private text during collection, including
while the trainer is paused or in the background. The in-app consent screen
discloses this before collection.
