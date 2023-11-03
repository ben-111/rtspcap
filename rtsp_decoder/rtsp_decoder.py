import os
from contextlib import contextmanager
import logging

import av
from av.container import Container

from rtsp_decoder.rtsp import RTSPDataExtractor
from rtsp_decoder.rtp import RTPDecoder

from typing import Optional


@contextmanager
def GetContainer(output_path: str) -> Container:
    c = av.open(output_path, format="mp4", mode="w")
    try:
        yield c
    finally:
        c.close()


class RTSPDecoder:
    """
    This class is the main application which takes a capture file that
    contains one or more RTSP streams and extracts them as video/audio
    output files.

    Parameters:
    input_path: Path to the input capture file.
    output_prefix: Optional string that will be prepended to each output file; Default is `stream`.
    output_dir: Optional oath to the directory which all the output files will be saved. Default
        is using the name of the capture file without the extension.
    sdp_path: Optional path to a backup SDP file that will be used if no SDP is found in the capture.
    fast: Tells PyAV to use threading when decoding. Default is False.
    verbose: Print debug logs. Default is False.
    """

    def __init__(
        self,
        input_path: str,
        output_prefix: str = "stream",
        output_dir: Optional[str] = None,
        sdp_path: Optional[str] = None,
        fast: bool = False,
        verbose: bool = False,
    ):
        logging_level = logging.INFO
        if verbose:
            logging_level = logging.DEBUG

        logging.basicConfig(
            level=logging_level, format="[%(levelname)s][%(name)s] %(message)s"
        )
        self.logger = logging.getLogger(__name__)
        self.logger.debug(
            f"Running with arguments: {input_path=}, {output_prefix=}, {output_dir=}, {sdp_path=}, {fast=}"
        )

        self.input_path = input_path
        self.output_prefix = output_prefix

        if output_dir is None:
            output_dir = os.path.basename(input_path)
            output_dir, _ = os.path.splitext(output_dir)

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)

        if not os.path.isdir(output_dir):
            raise NotADirectoryError("Invalid output dir path; Not a directory")

        self.output_dir = output_dir

        self.sdp = None
        if sdp_path is not None:
            with open(sdp_path, "r") as f:
                self.sdp = f.read()

        self.fast = fast

    def run(self) -> int:
        """Run the decoder. Returns an error code."""
        rtsp_data = RTSPDataExtractor(self.input_path, self.sdp)
        if not rtsp_data.streams:
            self.logger.error("Could not extract data from capture; exiting")
            return 1

        self.logger.info(f"Found {len(rtsp_data.streams)} RTP streams")

        stream_num = 0
        for ssrc, stream_info in rtsp_data.streams.items():
            output_filename = f"{self.output_prefix}{stream_num}.mp4"
            output_path = os.path.join(self.output_dir, output_filename)
            self.logger.info(
                f"Processing stream {stream_num}, saving to `{output_path}`"
            )

            try:
                with GetContainer(output_path) as container:
                    rtp_decoder = RTPDecoder(ssrc, stream_info, self.fast)
                    rtp_decoder.decode_stream(self.input_path, container)
            except Exception as e:
                self.logger.error(f"{e}, skipping")

            stream_num += 1
        return 0
