import logging

import av
from av.container import Container
from av.stream import Stream
from av.frame import Frame

from rtspcap.sdp import get_codec_name_from_sdp_media
from rtspcap.rtp_packet import RTPPacket
from rtspcap.reassembler import Reassembler
from rtspcap.codecs.rtp_codec import RTPCodec

from typing import Optional, List


class RTPDecoder:
    RTP_SEQ_BIT_SIZE = 16
    MAX_OUT_OF_ORDER_PACKETS = 50
    FRAME_BUFFER_SIZE = 100

    def __init__(
        self,
        output_path: str,
        sdp_media: dict,
        output_format: str,
        default_vcodec: str,
        default_acodec: str,
        force_vcodec: bool = False,
        force_acodec: bool = False,
        fast: bool = False,
    ):
        self.logger = logging.getLogger(__name__)
        self._default_vcodec = default_vcodec
        self._default_acodec = default_acodec
        self._force_vcodec = force_vcodec
        self._force_acodec = force_acodec
        self._fast = fast
        self._error: bool = False
        self._frame_buffer: List[Frame] = []
        self._out_stream: Optional[Stream] = None

        codec_name = get_codec_name_from_sdp_media(sdp_media)
        self._stream_codec = RTPCodec(codec_name, sdp_media, self._fast)
        if self._stream_codec.codec_type not in ("video", "audio"):
            raise ValueError(f"Unexpected codec type: {self._stream_codec.codec_type}")

        self.logger.info(f"Decoding stream with codec: {self._stream_codec.codec_name}")
        self._reassembler = Reassembler[RTPPacket](
            self.RTP_SEQ_BIT_SIZE, self.MAX_OUT_OF_ORDER_PACKETS, "packet"
        )
        self._container: Container = av.open(
            output_path, format=output_format, mode="w"
        )

    def close(self) -> None:
        if self._out_stream is None and self._frame_buffer:
            self.logger.debug("Could not get input codec settings, using defaults")
            self._init_out_stream()
            for frame in self._frame_buffer:
                encoded_packets = self._out_stream.encode(frame)
                self._container.mux(encoded_packets)

            self._frame_buffer.clear()

        self._reassembler.process(None)
        for out_packet, skipped in self._reassembler.get_output_packets():
            self._handle_packet(out_packet)
            if out_packet is None:
                break

        self._flush_encoder()
        self._container.close()

    def process_rtp_packet(self, rtp_packet: RTPPacket) -> None:
        self._reassembler.process(rtp_packet, rtp_packet.seq)
        for out_packet, skipped in self._reassembler.get_output_packets():
            self._handle_packet(out_packet)

    def _handle_packet(
        self,
        packet: Optional[RTPPacket],
    ) -> None:
        out_packets = self._stream_codec.handle_packet(packet)
        self.logger.debug(f"Parsed {len(out_packets)} packets")

        for out_packet in out_packets:
            frames = self._stream_codec.decode(out_packet)
            self.logger.debug(f"Decoded {len(frames)} frames")

            if self._out_stream is None:
                if not self._stream_codec.ready:
                    self._frame_buffer += frames
                    if len(self._frame_buffer) >= self.FRAME_BUFFER_SIZE:
                        self.logger.info("Frame buffer is full, using default settings")
                    else:
                        continue

                self._init_out_stream()
                frames = self._frame_buffer + frames
                self._frame_buffer.clear()

            for frame in frames:
                try:
                    encoded_packets = self._out_stream.encode(frame)
                    self._container.mux(encoded_packets)
                except Exception as e:
                    self.logger.error(e)

    def _init_out_stream(self) -> None:
        assert self._stream_codec.codec_type in ("video", "audio")
        if self._stream_codec.codec_type == "video":
            if not self._force_vcodec:
                try:
                    self._out_stream = self._container.add_stream(
                        self._stream_codec.av_codec_name
                    )
                except Exception as e:
                    self.logger.error(f"Error creating out stream: {e}")

            if self._out_stream is None:
                self._out_stream = self._container.add_stream(self._default_vcodec)

            self.logger.info(
                f"Added output video stream with codec: {self._out_stream.codec_context.name}"
            )

            if (
                self._stream_codec.width is not None
                and self._stream_codec.height is not None
            ):
                self._out_stream.codec_context.width = self._stream_codec.width
                self._out_stream.codec_context.height = self._stream_codec.height
            else:
                self.logger.warning(
                    "Could not get original frame size, using codec default"
                )

            if self._stream_codec.rate and 1 < self._stream_codec.rate < 120:
                self._out_stream.codec_context.rate = self._stream_codec.rate
            else:
                self.logger.warning(
                    "Could not get original frame rate, using codec default"
                )

        elif self._stream_codec.codec_type == "audio":
            if not self._force_acodec:
                try:
                    self._out_stream = self._container.add_stream(
                        self._stream_codec.av_codec_name
                    )
                except Exception as e:
                    self.logger.error(f"Error creating out stream: {e}")

            if self._out_stream is None:
                self._out_stream = self._container.add_stream(self._default_acodec)

            self.logger.info(
                f"Added output stream with codec: {self._out_stream.codec_context.name}"
            )

            if self._stream_codec.rate is not None:
                self._out_stream.codec_context.rate = self._stream_codec.rate
            else:
                self.logger.warning(
                    "Could not get original sample rate, using codec default"
                )

        if self._fast:
            self._out_stream.thread_type = "AUTO"

    def _flush_encoder(self) -> None:
        if self._out_stream is None:
            return

        out_packets = self._out_stream.encode(None)
        self._container.mux(out_packets)
