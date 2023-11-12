from io import BytesIO
import os
from contextlib import contextmanager
import logging

import av
from av.codec import codecs_available, Codec
from av.format import formats_available
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


@contextmanager
def TempContainer(output_format: str) -> Container:
    container = av.open(BytesIO(), mode="w", format=output_format)
    try:
        yield container
    finally:
        container.close()


def format_kwargs(kwargs: dict) -> str:
    return ", ".join(f"{key}={repr(value)}" for key, value in kwargs.items())


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
    fast: Tells PyAV to use threading when decoding. Default is False.
    verbose: Print debug logs. Default is False.
    output_format: Output format of each output file. Default is `mp4`.
    default_vcodec: Default video codec to fallback on if if copying original codec fails.
        Default is `h264`.
    default_acodec: Default audio codec to fallback on if if copying original codec fails.
        Default is `aac`.
    force_vcodec: Force using default video codec.
    force_acodec: Force using default audio codec.
    """

    def __init__(
        self,
        input_path: str,
        output_prefix: str = "stream",
        output_dir: Optional[str] = None,
        fast: bool = False,
        verbose: bool = False,
        output_format: str = "mp4",
        default_vcodec: str = "h264",
        default_acodec: str = "aac",
        force_vcodec: bool = False,
        force_acodec: bool = False,
    ):
        kwargs = locals()
        logging_level = logging.INFO
        if verbose:
            logging_level = logging.DEBUG

        logging.basicConfig(
            level=logging_level, format="[%(levelname)s][%(name)s] %(message)s"
        )
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Running with arguments: {format_kwargs(kwargs)}")

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

        if output_format not in formats_available:
            raise ValueError(f"Unspported format: {output_format}")

        self.output_format = output_format
        with TempContainer(self.output_format) as temp_container:
            if default_vcodec not in codecs_available:
                raise ValueError(f"Unsupported codec: {default_vcodec}")

            if Codec(default_vcodec, mode="w").type != "video":
                raise ValueError(f"Codec {default_vcodec} is not a video codec")

            self.default_vcodec = default_vcodec
            temp_container.add_stream(self.default_vcodec)  # Will throw if incompatible

            if default_acodec not in codecs_available:
                raise ValueError(f"Unsupported codec: {default_acodec}")

            if Codec(default_acodec, mode="w").type != "audio":
                raise ValueError(f"Codec {default_acodec} is not a audio codec")

            self.default_acodec = default_acodec
            temp_container.add_stream(self.default_acodec)  # Will throw if incompatible

        self.force_vcodec = force_vcodec
        self.force_acodec = force_acodec

        self.fast = fast
        if self.fast:
            self.logger.info("Using FAST setting")

    def run(self) -> None:
        """Run the decoder. Returns an error code."""
        rtp_decoders: Dict[int, RTPDecoder] = {}
        rtsp_extractor = RTSPDataExtractor(self.input_path)

        with CloseAllDictValues(rtp_decoders):
            for task in rtsp_extractor.process_next():
                if task.ttype == TaskType.CREATE_DECODER:
                    output_filename = (
                        f"{self.output_prefix}{task.body.ident}.{self.output_format}"
                    )
                    output_path = os.path.join(self.output_dir, output_filename)
                    self.logger.info(f"Found RTP stream, saving to `{output_path}`")
                    try:
                        rtp_decoder = RTPDecoder(
                            output_path,
                            task.body.sdp_media,
                            self.output_format,
                            self.default_vcodec,
                            self.default_acodec,
                            self.force_vcodec,
                            self.force_acodec,
                            self.fast,
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
