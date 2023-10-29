import argparse
import logging
from pyshark import FileCapture

from rtsp_decoder.rtsp import RTSPDataExtractor
from rtsp_decoder.transport.transport_decoder import RTSPTransportDecoder

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

    for track_id, transport_info in rtsp_data.tracks.items():
        try:
            with RTSPTransportDecoder(transport_info, output_path) as transport_decoder:
                transport_decoder.decode_stream(input_path, rtsp_data.sdp, track_id)
        except KeyError as e:
            logger.error(f"{e}, skipping")


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
