import os
import sys
import argparse
import logging
from pyshark import FileCapture

from rtsp_decoder.rtsp import RTSPDataExtractor
from rtsp_decoder.transport.transport_decoder import RTSPTransportDecoder

from typing import Dict, Optional

PREFIX_OPT_HELP = """\
Prefix for the name of the files generated.
The stream number `n` and the file extenstion `.mp4` will be appended like so: `<PREFIX>n.mp4`
For example, if the prefix is `stream` you might get `stream0.mp4`
"""
OUTPUT_DIR_OPT_HELP = "Output directory path. Default is the name of the capture file"
SDP_OPT_HELP = (
    "Path to a backup SDP file to fallback on if none was found in the capture"
)


def main(
    input_path: str,
    output_prefix: str,
    output_dir: Optional[str],
    sdp_path: Optional[str],
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

    rtsp_data = RTSPDataExtractor(input_path, sdp_path)
    if not rtsp_data.streams:
        logger.error("Could not extract data from capture; exiting")
        return 1

    logger.info(f"Found {len(rtsp_data.streams)} RTP streams")
    breakpoint()

    for track_id, transport_info in rtsp_data.tracks.items():
        try:
            with RTSPTransportDecoder(transport_info, output_path) as transport_decoder:
                transport_decoder.decode_stream(input_path, rtsp_data.sdp, track_id)
        except Exception as e:
            logger.error(f"{e}, skipping")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RTSP decoder from capture file")
    parser.add_argument("input", help="Path to capture file with RTSP and RTP data")
    parser.add_argument("-p", "--prefix", help=PREFIX_OPT_HELP, default="stream")
    parser.add_argument("-o", "--output-dir", help=OUTPUT_DIR_OPT_HELP)
    parser.add_argument("--sdp", help=SDP_OPT_HELP)
    parser.add_argument("-v", "--verbose", action="store_true", help="Add debug prints")
    args = parser.parse_args()

    sys.exit(main(args.input, args.prefix, args.output_dir, args.sdp, args.verbose))
