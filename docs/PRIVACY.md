# Privacy

## The short version

Sessions stay on the participant's computer until they choose to share the final
ZIP. The app has no automatic upload step.

It records the selected mouse or USB receiver, the aim-trainer events, timing,
settings, and a random participant ID. It does not take screenshots, record a
microphone, read personal files, or use a Windows account name as the participant
ID.

## Raw USB capture

The PCAP keeps the selected device's raw USB traffic so unusual mice can still be
decoded later. That can include control, vendor, descriptor, or serial bytes
exchanged with the device even though the app does not copy those values into its
own session metadata.

Some wireless receivers combine a mouse and keyboard. In that case, keyboard
reports from the shared receiver may also be present in the PCAP and could be
decoded later. Use a mouse-only receiver when possible and avoid typing private
text during collection, including while the trainer is paused or in the
background.

The short mouse check briefly watches activity on the relevant USB root to match
the Windows mouse with its USBPcap address. That broader traffic is kept in
memory only for the check and is not written to the session.

## Participant ID

The local `user_id` is a random 128-bit value used to group sessions from the
same participant. It is not based on a username, SID, hostname, IP address, or
hardware fingerprint. Deleting `participant_id.txt` creates a new identity for
future sessions.
