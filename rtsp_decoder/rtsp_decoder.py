import os
from contextlib import contextmanager
import logging

import av
from av.container import Container

from rtsp_decoder.rtsp import RTSPDataExtractor
from rtsp_decoder.rtp import RTPDecoder
from rtsp_decoder.task import TaskType

from typing import Optional, Dict, Iterable


@contextmanager
def CloseAllDictValues(closables: Dict):
    try:
        yield
    finally:
        for closable in closables.values():
            closable.close()


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
            self.logger.info(f"Directory {output_dir} does not exist, creating it")
            os.mkdir(output_dir)

        if not os.path.isdir(output_dir):
            raise NotADirectoryError("Invalid output dir path; Not a directory")

        self.output_dir = output_dir

        self.sdp = None
        if sdp_path is not None:
            with open(sdp_path, "r") as f:
                self.sdp = f.read()

        self.fast = fast

    def run(self) -> None:
        """Run the decoder. Returns an error code."""
        rtp_decoders: Dict[int, RTPDecoder] = {}
        rtsp_extractor = RTSPDataExtractor(self.input_path, self.sdp)

        with CloseAllDictValues(rtp_decoders):
            for task in rtsp_extractor.process_next():
                if task.ttype == TaskType.CREATE_DECODER:
                    output_filename = f"{self.output_prefix}{task.body.ident}.mp4"
                    output_path = os.path.join(self.output_dir, output_filename)
                    self.logger.info(f"Found RTP stream, saving to `{output_path}`")
                    try:
                        rtp_decoder = RTPDecoder(
                            output_path, task.body.sdp_media, self.fast
                        )
                    except Exception as e:
                        self.logger.error(e)
                        continue

                    rtp_decoders[task.body.ident] = rtp_decoder
                elif task.ttype == TaskType.PROCESS_RTP_PACKET:
                    if task.body.ident not in rtp_decoders:
                        continue

                    rtp_decoder = rtp_decoders[task.body.ident]
                    rtp_decoder.process_rtp_packet(task.body.rtp_packet)

            if not rtp_decoders:
                self.logger.warning("No RTSP streams found")
