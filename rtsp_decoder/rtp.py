import av
from av.container import Container
from av.stream import Stream
from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark import FileCapture
from pyshark.packet.packet import Packet

from rtsp_decoder.sdp import get_codec_context
from rtsp_decoder.sdp import H264_STARTING_SEQUENCE

from typing import Dict, Optional, List

import logging


class RTPDecoder:
    MAX_OUT_OF_ORDER_PACKETS = 50

    def __init__(self, output_path: str):
        self.container = av.open(output_path, "w")
        self.logger = logging.getLogger(__name__)
        self._codec_specific_rtp_packet_handlers = {
            "h264": self._h264_rtp_packet_handler
        }

    def decode_stream(self, rtp_capture: FileCapture, sdp: dict, track_id: str):
        """Assume rtp_capture is filtered so that all RTP packets we see are from the same stream"""
        codec_ctx = get_codec_context(sdp, track_id)
        if codec_ctx is None:
            self.logger.warning(f"Skipping unsupported codec")
            return

        self.logger.info(f"Decoding Stream with codec: {codec_ctx.name}")
        if codec_ctx.type == "video":
            stream = self.container.add_stream("h264", rate=30)
        elif codec_ctx.type == "audio":
            self.logger.warning(f"Audio ")
            # stream = self.container.add_stream("aac")
        else:
            raise ValueError(f"Unexpected codec type: {codec_ctx.type}")

        out_of_order_packets: Dict[int, Packet] = dict()
        expected_seq = None
        try:
            while True:
                packet = rtp_capture.next()
                if "RTP" in packet:
                    expected_seq = int(packet["RTP"].seq)
                    self.logger.debug(f"First seq is {expected_seq}")
                    break
        except StopIteration:
            raise ValueError("RTP stream not found")

        rtp_capture.reset()
        rtp_stream = filter(lambda x: "RTP" in x, rtp_capture)
        while True:
            try:
                if expected_seq in out_of_order_packets:
                    packet = out_of_order_packets.pop(expected_seq)
                else:
                    packet = next(rtp_stream)
            except StopIteration:
                if out_of_order_packets:
                    earliest_packet = min(out_of_order_packets.keys())
                    packet = out_of_order_packets.pop(earliest_packet)
                    expected_seq = int(packet["RTP"].seq)
                    self.logger.debug(
                        f"Out of order packet with seq {expected_seq} found after the end of the pcap file; Appending to the end"
                    )
                else:
                    break

            seq = int(packet["RTP"].seq)
            if seq != expected_seq:
                out_of_order_packets[seq] = packet
                if len(out_of_order_packets) > self.MAX_OUT_OF_ORDER_PACKETS:
                    self.logger.debug(
                        f"Could not find packet with sequence number {expected_seq}; Likely packet loss"
                    )
                    expected_seq += 1
                    expected_seq %= 1 << 16

                continue
            else:
                expected_seq += 1
                expected_seq %= 1 << 16

            self.logger.debug(f"Processing RTP packet with seq {seq}")
            self._handle_rtp_packet(self.container, stream, codec_ctx, packet)

        # Flush the encoder
        out_packet = stream.encode(None)
        self.container.mux(out_packet)

    def _handle_rtp_packet(
        self,
        container: Container,
        stream: Stream,
        codec_ctx: CodecContext,
        packet: Packet,
    ) -> None:
        """For some codecs we need special treatment"""
        out_packets = []
        if codec_ctx.name in self._codec_specific_rtp_packet_handlers:
            handler = self._codec_specific_rtp_packet_handlers[codec_ctx.name]
            out_packets = handler(codec_ctx, packet)
        else:
            chunk = bytes.fromhex(packet["RTP"].payload.raw_value)
            out_packets = codec_ctx.parse(chunk)

        self.logger.debug(f"Parsed {len(out_packets)} packets")
        for out_packet in out_packets:
            frames = codec_ctx.decode(out_packet)
            self.logger.debug(f"Decoded {len(frames)} frames")
            for frame in frames:
                encoded_packet = stream.encode(frame)
                self.container.mux(encoded_packet)

    # Taken from ffmpeg: `rtpdec_h264.c:h264_handle_packet`
    def _h264_rtp_packet_handler(
        self,
        codec_ctx: CodecContext,
        packet: Packet,
    ) -> List[AVPacket]:
        buf = bytes.fromhex(packet["RTP"].payload.raw_value)
        if len(buf) == 0:
            self.logger.error(f"RTP h264 invalid data")
            return

        nal = buf[0]
        nal_type = nal & 0x1F

        if nal_type >= 1 and nal_type <= 23:
            nal_type = 1

        self.logger.debug(f"Parsing H264 RTP packet with NAL type {nal_type}")
        out_packets = []
        if nal_type == 0 or nal_type == 1:
            out_packets = codec_ctx.parse(H264_STARTING_SEQUENCE + buf)
        elif nal_type == 24:
            # One packet, multiple NALs
            out_packets = self._handle_aggregated_h264_rtp_packet(codec_ctx, buf[1:])
        elif nal_type == 28:
            # Fragmented NAL
            out_packets = self._handle_fu_a_h264_rtp_packet(codec_ctx, buf)
        else:
            self.logger.error(
                f"Got H264 RTP packet with unsupported NAL type: {nal_type}"
            )

        return out_packets

    def _handle_fu_a_h264_rtp_packet(
        self, codec_ctx: CodecContext, buf: bytes
    ) -> List[AVPacket]:
        if len(buf) < 3:
            self.logger.error("Too short data for FU-A H.264 RTP packet")
            return []

        fu_indicator = buf[0]
        fu_header = buf[1]
        start_bit = fu_header >> 7
        nal_type = fu_header & 0x1F
        nal = fu_indicator & 0xE0 | nal_type

        buf = buf[2:]
        buffer_to_parse = b""
        if start_bit:
            buffer_to_parse += H264_STARTING_SEQUENCE
            buffer_to_parse += nal.to_bytes(1, byteorder="little")
        buffer_to_parse += buf

        return codec_ctx.parse(buffer_to_parse)

    def _handle_aggregated_h264_rtp_packet(
        self, codec_ctx: CodecContext, buf: bytes
    ) -> List[AVPacket]:
        """
        An aggregated packet is an array of NAL units.
        A NAL unit is a `uint16 nal_size` followed by a buffer of that size
        """
        out_packets = []
        while len(buf) > 2:
            nal_size_bytes = buf[:2]
            nal_size = int.from_bytes(nal_size_bytes, byteorder="little")
            buf = buf[2:]
            if nal_size <= len(buf):
                out_packets += codec_ctx.parse(H264_STARTING_SEQUENCE + buf[:nal_size])
                buf = buf[nal_size:]
            else:
                self.logger.error(f"nal size exceeds length: {nal_size} > {len(buf)}")
                break

        return out_packets

    def close(self):
        self.container.close()

    def __enter__(self) -> "RTPDecoder":
        return self

    def __exit__(self, exception_type, exception_value, exception_trace):
        self.close()
