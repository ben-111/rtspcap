import argparse
import logging
from pyshark import FileCapture

from rtsp_decoder.parse_rtsp import RTSPDataExtractor
from rtsp_decoder.rtp_decoder import RTPDecoder

from typing import Dict, Optional


def main(input_path: str, output_path: Optional[str]) -> None:
    logging.basicConfig(level=logging_level, format="[%(levelname)s] %(message)s")
    logger = logging.getLogger("RTSP Decoder")
    logger.debug(f"Running with arguments: {input_path=}, {output_path=}")

    rtsp_data = RTSPDataExtractor(input_path)
    if output_path is None:
        output_path = rtsp_data.stream_name + ".mp4"

    logger.info(
        f"Found RTSP stream `{rtsp_data.stream_name}`, saving to `{output_path}`"
    )

    with RTPDecoder(output_path) as rtp_decoder:
        for track_id, track in rtsp_data.tracks.items():
            with FileCapture(
                input_path, display_filter=f"rtp and {track.get_display_filter()}"
            ) as rtp_capture:
                rtp_decoder.decode_stream(rtp_capture, rtsp_data.sdp, track_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RTSP decoder from capture file")
    parser.add_argument("input", help="Path to capture_file with RTSP and RTP data")
    parser.add_argument("-o", "--output", help="Path to output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Add debug prints")
    args = parser.parse_args()

    logging_level = logging.INFO
    if args.verbose:
        logging_level = logging.DEBUG

    main(args.input, args.output)
