import av
from av.container import Container
from av.stream import Stream
from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark import FileCapture
from pyshark.packet.packet import Packet

from rtsp_decoder.sdp import get_codec_context

from rtsp_decoder.codecs.rtp_common import CodecRTPDecoder
from rtsp_decoder.codecs.h264 import H264RTPDecoder

from typing import Dict, List

import logging


class RTPDecoder:
    MAX_OUT_OF_ORDER_PACKETS = 50

    def __init__(self, output_path: str):
        self.container = av.open(output_path, "w")
        self.logger = logging.getLogger(__name__)
        self._codec_specific_rtp_decoders: Dict[str, CodecRTPDecoder] = {
            "h264": H264RTPDecoder
        }

    def decode_stream(self, rtp_capture: FileCapture, sdp: dict, track_id: str):
        """Assume rtp_capture is filtered so that all RTP packets we see are from the same stream"""
        codec_ctx = get_codec_context(sdp, track_id)
        if codec_ctx is None:
            self.logger.warning(f"Skipping unsupported codec")
            return

        self.logger.info(f"Decoding stream with codec: {codec_ctx.name}")
        if codec_ctx.type == "video":
            stream = self.container.add_stream("h264", rate=30)
        elif codec_ctx.type == "audio":
            self.logger.warning(f"Audio is not implemented")
            return
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
        out_packets: List[AVPacket] = []
        if codec_ctx.name in self._codec_specific_rtp_decoders:
            codec_rtp_decoder = self._codec_specific_rtp_decoders[codec_ctx.name]
            out_packets = codec_rtp_decoder.handle_packet(codec_ctx, packet)
        else:
            chunk = bytes.fromhex(packet["RTP"].payload.raw_value)
            out_packets = codec_ctx.parse(chunk)

        self.logger.debug(f"Parsed {len(out_packets)} packets")
        for out_packet in out_packets:
            frames = codec_ctx.decode(out_packet)
            self.logger.debug(f"Decoded {len(frames)} frames")
            for frame in frames:
                encoded_packet = stream.encode(frame)
                container.mux(encoded_packet)

    def close(self):
        self.container.close()

    def __enter__(self) -> "RTPDecoder":
        return self

    def __exit__(self, exception_type, exception_value, exception_trace):
        self.close()
