# RTSP Decoder

The decoder will try to extract all the RTP streams it finds, and will try to
use the information it has to the fullest (best effort). If an SDP file is not
found in the stream, you can provide one that might be close enough and work
for these streams.

>Disclaimer: To detect a packet as an RTP packet, there MUST be an RTSP SETUP response
in the capture file.

```
usage: python -m rtsp_decoder [-h] [-p PREFIX] [-o OUTPUT_DIR] [--sdp SDP] [--fast] [-v]
                              input

RTSP decoder from capture file

positional arguments:
  input                 Path to capture file with RTSP and RTP data

options:
  -h, --help            show this help message and exit
  -p PREFIX, --prefix PREFIX
                        Prefix for the name of the files generated. The stream number `n`
                        and the file extenstion `.mp4` will be appended like so:
                        `<PREFIX>n.mp4`. For example, if the prefix is `stream` you might
                        get `stream0.mp4`
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output directory path. Default is the name of the capture file
  --sdp SDP             Path to a backup SDP file to fallback on if none was found in the
                        capture
  --fast                Use threading to boost the decoding speed
  -v, --verbose         Add debug prints
```

## How it works (and how I made it)

First we should understand RTSP streaming on a high level.
First, the client uses RTSP to find a stream on the server, and negotiate
the streaming protocol/s and codecs and such.

RTSP is basically HTTP with different methods and headers.
The negotiation usually works something like this:

```
Client                        Server
   |         DESCRIBE           |
   |----------------------->    |
   |                            |
   |           SDP              |
   |  <-------------------------|
   |                            |
   |           SETUP            |
   |----------------------->    |
   |                            |
   |            OK              |
   |  <-------------------------|
   |                            |
   |           PLAY             |
   |----------------------->    |
   |                            |
   |            OK              |
   |  <-------------------------|
   |                            |
```

The SDP (Session Description Protocol) is a format for describing the stream that
is hosted on that URL. It has several elements, the most important ones are the
tracks. A stream can have more that one track, for example one for video and one for audio.

Each track element describes what protocol it uses (almost always RTP, which is what we support),
and which codec the stream is using, plus some extra data which might be important for decoding
the stream later.

The SETUP method is used to negotiate the protocol details per track. The client will send its
preferred configuration via the Transport header, and the server will either accept it or not.
If it does it will send the Transport header again, sometimes with important values like the
server port.

The PLAY method tells the server to start streaming to the client.

The server will start sending RTP packets to the client. Each packet contains a seqence number
for ordering, a timestamp for telling the client when the content of this packet should be shown,
and the payload.

Depending on the codec, each packet might contain either a fragment of a frame, a full frame or
multiple full frames of audio/video/other. Each codec defines how it should be transmitted over RTP
in an RFC. Some of them have special headers that are unique to the transmission over RTP, that need
to be parsed.

Then the decoder combines the different tracks (if there are multiple) into one stream, and displays
it to the user (or maybe saves to a file).

In RTSP Decoder, we decode each stream seperately, encode to a known format (h264 for video, aac for audio)
and save to a file.

For parsing the codecs, I used two sources: FFmpeg and the relevant RFC. Since I am using PyAV which is
just a wrapper around FFmpeg, looking at the FFmpeg source really helped at times. However, sometimes
their code is really hard to understand, and in those cases I used the relevant RFC to understand the
structure of the RTP payload.

