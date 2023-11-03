import os
import sys
import argparse
import logging
from contextlib import contextmanager

import av
from av.container import Container
from pyshark import FileCapture

from rtsp_decoder.rtsp import RTSPDataExtractor
from rtsp_decoder.rtp import RTPDecoder

from typing import Dict, Optional

PREFIX_OPT_HELP = """\
Prefix for the name of the files generated.
The stream number `n` and the file extenstion `.mp4` will be appended like so: `<PREFIX>n.mp4`.
For example, if the prefix is `stream` you might get `stream0.mp4`
"""
OUTPUT_DIR_OPT_HELP = "Output directory path. Default is the name of the capture file"
SDP_OPT_HELP = (
    "Path to a backup SDP file to fallback on if none was found in the capture"
)
FAST_OPT_HELP = "Use threading to boost the decoding speed"


@contextmanager
def GetContainer(output_path: str) -> Container:
    c = av.open(output_path, format="mp4", mode="w")
    try:
        yield c
    finally:
        c.close()


def main(
    input_path: str,
    output_prefix: str,
    output_dir: Optional[str],
    sdp_path: Optional[str],
    fast: bool,
    verbose: bool,
) -> int:
    logging_level = logging.INFO
    if verbose:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level, format="[%(levelname)s] %(message)s")
    logger = logging.getLogger("RTSP Decoder")
    logger.debug(
        f"Running with arguments: {input_path=}, {output_prefix=}, {output_dir=}, {sdp_path=}"
    )

    if output_dir is None:
        output_dir = os.path.basename(input_path)
        output_dir, _ = os.path.splitext(output_dir)

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    if not os.path.isdir(output_dir):
        logger.error("Invalid output dir path; Not a directory")
        return 1

    rtsp_data = RTSPDataExtractor(input_path, sdp_path)
    if not rtsp_data.streams:
        logger.error("Could not extract data from capture; exiting")
        return 1

    logger.info(f"Found {len(rtsp_data.streams)} RTP streams")

    stream_num = 0
    for ssrc, stream_info in rtsp_data.streams.items():
        output_filename = f"{output_prefix}{stream_num}.mp4"
        output_path = os.path.join(output_dir, output_filename)
        logger.info(f"Processing stream {stream_num}, saving to `{output_path}`")
        try:
            with GetContainer(output_path) as container:
                rtp_decoder = RTPDecoder(ssrc, stream_info, fast)
                rtp_decoder.decode_stream(input_path, container)
        except Exception as e:
            logger.error(f"{e}, skipping")

        stream_num += 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RTSP decoder from capture file", prog=f"python -m {__package__}"
    )
    parser.add_argument("input", help="Path to capture file with RTSP and RTP data")
    parser.add_argument("-p", "--prefix", help=PREFIX_OPT_HELP, default="stream")
    parser.add_argument("-o", "--output-dir", help=OUTPUT_DIR_OPT_HELP)
    parser.add_argument("--sdp", help=SDP_OPT_HELP)
    parser.add_argument("--fast", action="store_true", help=FAST_OPT_HELP)
    parser.add_argument("-v", "--verbose", action="store_true", help="Add debug prints")
    args = parser.parse_args()

    sys.exit(
        main(
            args.input, args.prefix, args.output_dir, args.sdp, args.fast, args.verbose
        )
    )
