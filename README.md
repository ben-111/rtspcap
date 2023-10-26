# RTSP Decoder
Make sure that `tshark` is installed for `pyshark` to work.
You might encounter problems if the `tshark` version is not recent enough.

The decoder will only extract the first RTSP stream it finds.

Usage:
```
python -m rtsp_decoder [-h] [-o OUTPUT] [-v] <input.pcap>
```

By default the output file will use the name of the stream.
