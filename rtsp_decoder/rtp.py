import logging

from av.container import Container
from av.stream import Stream
from pyshark import FileCapture
from pyshark.packet.packet import Packet

from rtsp_decoder.rtsp import RTPStreamInfo
from rtsp_decoder.sdp import get_codec_name_from_sdp_media

from rtsp_decoder.codecs.rtp_codec import RTPCodec

from typing import Dict, Iterator, Optional


class RTPDecoder:
    MAX_OUT_OF_ORDER_PACKETS = 50

    def __init__(self, ssrc: int, stream_info: RTPStreamInfo):
        self.logger = logging.getLogger(__name__)
        self._display_filter = f"rtp.ssrc == {ssrc}"
        self._sdp_media = stream_info.sdp_media

    def decode_stream(
        self, pcap_path: str, container: Container, fast: bool = False
    ) -> None:
        codec_name = get_codec_name_from_sdp_media(self._sdp_media)
        stream_codec = RTPCodec(codec_name, self._sdp_media, fast)

        self.logger.info(f"Decoding stream with codec: {stream_codec.codec_name}")
        if stream_codec.codec_type == "video":
            out_stream = container.add_stream("h264", rate=30)
        elif stream_codec.codec_type == "audio":
            out_stream = container.add_stream("aac")
        else:
            raise ValueError(f"Unexpected codec type: {stream_codec.codec_type}")

        if fast:
            out_stream.thread_type = "AUTO"

        for packet in self._iterate_packets(pcap_path):
            self._handle_packet(container, out_stream, stream_codec, packet)

        self._flush_encoder(container, out_stream)

    def _handle_packet(
        self,
        container: Container,
        out_stream: Stream,
        stream_codec: RTPCodec,
        packet: Optional[Packet],
    ) -> None:
        out_packets = stream_codec.handle_packet(packet)
        self.logger.debug(f"Parsed {len(out_packets)} packets")
        for out_packet in out_packets:
            frames = stream_codec.decode(out_packet)
            self.logger.debug(f"Decoded {len(frames)} frames")
            for frame in frames:
                encoded_packet = out_stream.encode(frame)
                container.mux(encoded_packet)

    def _flush_encoder(self, container: Container, out_stream: Stream) -> None:
        out_packet = out_stream.encode(None)
        container.mux(out_packet)

    def _iterate_packets(self, pcap_path: str) -> Iterator[Packet]:
        with FileCapture(pcap_path, display_filter=self._display_filter) as rtp_capture:
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
                yield packet

        # Flush the decoder
        yield None
