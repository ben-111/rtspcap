from contextlib import contextmanager
import logging

import av
from av.container import Container
from av.stream import Stream
from av.frame import Frame
from pyshark import FileCapture
from pyshark.packet.packet import Packet

from rtsp_decoder.sdp import get_codec_name_from_sdp_media
from rtsp_decoder.task import RTPPacket

from rtsp_decoder.codecs.rtp_codec import RTPCodec

from typing import Dict, Generator, Optional, List


@contextmanager
def GetContainer(output_path: str) -> Container:
    c = av.open(output_path, format="mp4", mode="w")
    try:
        yield c
    finally:
        c.close()


class RTPDecoder:
    MAX_OUT_OF_ORDER_PACKETS = 50
    FRAME_BUFFER_SIZE = 100

    def __init__(self, output_path: str, sdp_media: dict, fast: bool = False):
        self.logger = logging.getLogger(__name__)
        self._frame_buffer: List[Frame] = []
        self._out_stream: Optional[Stream] = None
        self._output_queue = []

        self._decode_stream_coroutine = self._decode_stream(
            output_path, sdp_media, fast
        )
        self._decode_stream_coroutine.send(None)
        self._iterate_packets_coroutine = self._iterate_packets()
        self._iterate_packets_coroutine.send(None)

    def process_rtp_packet(self, rtp_packet: RTPPacket) -> None:
        self._decode_stream_coroutine.send(rtp_packet)

    def _decode_stream(
        self,
        output_path: str,
        sdp_media: dict,
        fast: bool = False,
    ) -> Generator[None, RTPPacket, None]:
        with GetContainer(output_path) as container:
            codec_name = get_codec_name_from_sdp_media(sdp_media)
            stream_codec = RTPCodec(codec_name, sdp_media, fast)

            self.logger.info(f"Decoding stream with codec: {stream_codec.codec_name}")
            if stream_codec.codec_type not in ("video", "audio"):
                raise ValueError(f"Unexpected codec type: {stream_codec.codec_type}")

            while True:
                rtp_packet = yield
                self._iterate_packets_coroutine.send(rtp_packet)
                if self._output_queue:
                    out_packet = self._output_queue.pop(0)
                    self._handle_packet(container, stream_codec, out_packet, fast)
                    if out_packet is None:
                        break

            self._flush_encoder(container)

    def _handle_packet(
        self,
        container: Container,
        stream_codec: RTPCodec,
        packet: Optional[RTPPacket],
        fast: bool = False,
    ) -> None:
        out_packets = stream_codec.handle_packet(packet)
        self.logger.debug(f"Parsed {len(out_packets)} packets")

        for out_packet in out_packets:
            frames = stream_codec.decode(out_packet)
            self.logger.debug(f"Decoded {len(frames)} frames")

            if self._out_stream is None:
                if stream_codec.ready:
                    self._out_stream = container.add_stream(stream_codec.av_codec_name)
                    if stream_codec.codec_type == "video":
                        self._out_stream.codec_context.width = stream_codec.width
                        self._out_stream.codec_context.height = stream_codec.height
                        if 1 < stream_codec.rate < 120:
                            self._out_stream.codec_context.rate = stream_codec.rate
                        else:
                            self.logger.warning("Setting frame rate to 30 FPS")
                            self._out_stream.codec_context.rate = 30

                    elif stream_codec.codec_type == "audio":
                        self._out_stream.codec_context.rate = stream_codec.rate

                    if fast:
                        self._out_stream.thread_type = "AUTO"

                    frames = self._frame_buffer + frames
                    self._frame_buffer.clear()
                elif len(self._frame_buffer) >= self.FRAME_BUFFER_SIZE:
                    raise ValueError("Packet buffer is full, soemthing went wrong")
                else:
                    self._frame_buffer += frames
                    continue

            for frame in frames:
                encoded_packet = self._out_stream.encode(frame)
                container.mux(encoded_packet)

    def _flush_encoder(self, container: Container) -> None:
        out_packet = self._out_stream.encode(None)
        container.mux(out_packet)

    def _iterate_packets(self) -> Generator[RTPPacket, RTPPacket, None]:
        out_of_order_packets: Dict[int, RTPPacket] = {}
        expected_seq = None
        try:
            rtp_packet: RTPPacket = yield
            expected_seq = rtp_packet.seq
            self.logger.debug(f"First seq is {expected_seq}")
        except StopIteration:
            raise ValueError("RTP stream not found")

        while True:
            try:
                if expected_seq in out_of_order_packets:
                    packet = out_of_order_packets.pop(expected_seq)
                else:
                    packet = yield
            except StopIteration:
                if out_of_order_packets:
                    earliest_packet = min(out_of_order_packets.keys())
                    packet = out_of_order_packets.pop(earliest_packet)
                    expected_seq = packet.seq
                    self.logger.debug(
                        f"Out of order packet with seq {expected_seq} found after the end of the pcap file; Appending to the end"
                    )
                else:
                    break

            seq = packet.seq
            if seq != expected_seq:
                out_of_order_packets[seq] = packet
                if len(out_of_order_packets) > self.MAX_OUT_OF_ORDER_PACKETS:
                    self.logger.debug(
                        f"Could not find packet with sequence number {expected_seq}; Likely packet loss"
                    )
                    if out_of_order_packets:
                        expected_seq = min(out_of_order_packets.keys())
                    else:
                        expected_seq += 1
                        expected_seq %= 1 << 16

                continue
            else:
                expected_seq += 1
                expected_seq %= 1 << 16

            self.logger.debug(f"Processing RTP packet with seq {seq}")
            self._output_queue.append(packet)

        # Flush the decoder
        self._output_queue.append(None)
