import sys
import argparse

from rtspcap import RTSPcapApp


PREFIX_OPT_HELP = """\
Prefix for the name of the files generated.
The stream number `n` and the file extenstion `.<output_format>` will 
be appended like so: `<PREFIX>n.<output_format>`.
For example, if the prefix is `stream` and the output format is `mp4` you might get `stream0.mp4`
"""
OUTPUT_DIR_HELP = "Output directory path. Default is the name of the capture file"
FAST_HELP = "Use threading to boost the decoding speed (use with caution)"
FORMAT_HELP = "Output format (to get a list of output formats run `ffmpeg -formats`)"
DEFAULT_CODEC_HELP_TEMPLATE = (
    "Default {} codec to fallback on if copying original codec fails "
    "(to get a list of codecs run `ffmpeg -codecs`)"
)
DEFAULT_VCODEC_HELP = DEFAULT_CODEC_HELP_TEMPLATE.format("video")
DEFAULT_ACODEC_HELP = DEFAULT_CODEC_HELP_TEMPLATE.format("audio")
FORCE_CODEC_HELP_TEMPLATE = "Force using default {} codec"
FORCE_VCODEC_HELP = FORCE_CODEC_HELP_TEMPLATE.format("video")
FORCE_ACODEC_HELP = FORCE_CODEC_HELP_TEMPLATE.format("audio")
GUESS_TCP_LEN_HELP = (
    "When using RTP/TCP, some badly coded devices will send the wrong RTP"
    "packet length, so we must try to guess the length of the packet ourselves"
    "by trying to find the start of the next packet"
)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Recover your RTSP streams from a capture file",
        prog=f"python -m {__package__}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", help="Path to capture file with RTSP and RTP data")
    parser.add_argument("-p", "--prefix", help=PREFIX_OPT_HELP, default="stream")
    parser.add_argument("-o", "--output-dir", help=OUTPUT_DIR_HELP)
    parser.add_argument("--fast", action="store_true", help=FAST_HELP)
    parser.add_argument("-v", "--verbose", action="store_true", help="Add debug prints")
    parser.add_argument("-f", "--format", help=FORMAT_HELP, default="mp4")
    parser.add_argument("--default-vcodec", help=DEFAULT_VCODEC_HELP, default="h264")
    parser.add_argument("--default-acodec", help=DEFAULT_ACODEC_HELP, default="aac")
    parser.add_argument("--force-vcodec", action="store_true", help=FORCE_VCODEC_HELP)
    parser.add_argument("--force-acodec", action="store_true", help=FORCE_ACODEC_HELP)
    parser.add_argument("--guess-tcp-len", action="store_true", help=GUESS_TCP_LEN_HELP)
    args = parser.parse_args()

    try:
        app = RTSPcapApp(
            args.input,
            args.prefix,
            args.output_dir,
            args.fast,
            args.verbose,
            args.format,
            args.default_vcodec,
            args.default_acodec,
            args.force_vcodec,
            args.force_acodec,
            args.guess_tcp_len,
        )
        app.run()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    sys.exit()
