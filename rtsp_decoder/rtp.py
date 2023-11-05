import logging

import av
from av.container import Container
from av.stream import Stream
from av.frame import Frame

from rtsp_decoder.sdp import get_codec_name_from_sdp_media
from rtsp_decoder.rtp_packet import RTPPacket
from rtsp_decoder.reassembler import Reassembler
from rtsp_decoder.codecs.rtp_codec import RTPCodec

from typing import Optional, List


class RTPDecoder:
    RTP_SEQ_BIT_SIZE = 16
    MAX_OUT_OF_ORDER_PACKETS = 50
    FRAME_BUFFER_SIZE = 100

    def __init__(self, output_path: str, sdp_media: dict, fast: bool = False):
        self.logger = logging.getLogger(__name__)
        self._error: bool = False
        self._fast = fast
        self._frame_buffer: List[Frame] = []
        self._out_stream: Optional[Stream] = None

        codec_name = get_codec_name_from_sdp_media(sdp_media)
        self._stream_codec = RTPCodec(codec_name, sdp_media, self._fast)
        if self._stream_codec.codec_type not in ("video", "audio"):
            self.logger.error(f"Unexpected codec type: {self._stream_codec.codec_type}")
            self._error = True
            return

        self.logger.info(f"Decoding stream with codec: {self._stream_codec.codec_name}")
        self._reassembler = Reassembler[RTPPacket](
            self.RTP_SEQ_BIT_SIZE, self.MAX_OUT_OF_ORDER_PACKETS
        )
        self._container: Container = av.open(output_path, format="mp4", mode="w")

    def close(self) -> None:
        if self._error:
            return

        self._reassembler.process(None)
        for out_packet in self._reassembler.get_output_packets():
            self._handle_packet(out_packet)
            if out_packet is None:
                break

        self._flush_encoder()
        self._container.close()

    def process_rtp_packet(self, rtp_packet: RTPPacket) -> None:
        if self._error:
            return

        self._reassembler.process(rtp_packet, rtp_packet.seq)
        for out_packet in self._reassembler.get_output_packets():
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
                    if len(self._frame_buffer) >= self.FRAME_BUFFER_SIZE:
                        raise ValueError("Frame buffer is full, soemthing went wrong")

                    self._frame_buffer += frames
                    continue

                self._out_stream = self._container.add_stream(
                    self._stream_codec.av_codec_name
                )
                if self._stream_codec.codec_type == "video":
                    self._out_stream.codec_context.width = self._stream_codec.width
                    self._out_stream.codec_context.height = self._stream_codec.height
                    if 1 < self._stream_codec.rate < 120:
                        self._out_stream.codec_context.rate = self._stream_codec.rate
                    else:
                        self.logger.warning("Setting frame rate to 30 FPS")
                        self._out_stream.codec_context.rate = 30

                elif self._stream_codec.codec_type == "audio":
                    self._out_stream.codec_context.rate = self._stream_codec.rate

                if self._fast:
                    self._out_stream.thread_type = "AUTO"

                frames = self._frame_buffer + frames
                self._frame_buffer.clear()

            for frame in frames:
                encoded_packets = self._out_stream.encode(frame)
                self._container.mux(encoded_packets)

    def _flush_encoder(self) -> None:
        out_packets = self._out_stream.encode(None)
        self._container.mux(out_packets)
