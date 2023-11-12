import sys
import argparse

from rtsp_decoder import RTSPDecoder


PREFIX_OPT_HELP = """\
Prefix for the name of the files generated.
The stream number `n` and the file extenstion `.mp4` will be appended like so: `<PREFIX>n.mp4`.
For example, if the prefix is `stream` you might get `stream0.mp4`
"""
OUTPUT_DIR_OPT_HELP = "Output directory path. Default is the name of the capture file"
FAST_OPT_HELP = "Use threading to boost the decoding speed"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RTSP decoder from capture file", prog=f"python -m {__package__}"
    )
    parser.add_argument("input", help="Path to capture file with RTSP and RTP data")
    parser.add_argument("-p", "--prefix", help=PREFIX_OPT_HELP, default="stream")
    parser.add_argument("-o", "--output-dir", help=OUTPUT_DIR_OPT_HELP)
    parser.add_argument("--fast", action="store_true", help=FAST_OPT_HELP)
    parser.add_argument("-v", "--verbose", action="store_true", help="Add debug prints")
    args = parser.parse_args()

    rtsp_decoder = RTSPDecoder(
        args.input, args.prefix, args.output_dir, args.fast, args.verbose
    )
    rtsp_decoder.run()
    sys.exit()
