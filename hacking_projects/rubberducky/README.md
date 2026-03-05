# Rubber Ducky (HID Trust) Demo (Group 24)

This folder contains an **educational** USB HID keystroke-injection demo used to illustrate a core security lesson:

This material is intended for **authorized, controlled lab environments only** (e.g., your own machine/VM for a class exercise). Do not use on systems you don’t own or don’t have explicit permission to test.

## What’s Here

- `payload.txt` — A Duckyscript payload used for a classroom demonstration.
- `note.txt` — Scratch notes.
- `inject.bin` -- The compiled binary of the duckyscript

## About `payload.txt`

At a high level, the current payload is structured like this:

- Opens a text editor (notepad) and types a short Python program.
- Saves the program as a `.py` file.
- Opens powershell and runs the `.py` script.
- Open WhatsApp and send a message to someone.


### Timing / focus issues

HID scripts are sensitive to device speed and window focus.

- Increase `DELAY` values when a window isn’t ready.
- Add an extra delay after launching an app (especially before the first `STRING`).


## Ethical Use

This project is for learning defensive security concepts. Not to be used for malicious purposes.