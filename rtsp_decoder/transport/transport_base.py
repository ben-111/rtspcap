from abc import ABC, abstractmethod

import av
from av.container import Container
from av.stream import Stream
from pyshark.packet.packet import Packet
import logging

from rtsp_decoder.rtsp import TransportInformation
from rtsp_decoder.codecs.stream_codec import StreamCodec
from rtsp_decoder.sdp import get_stream_codec

from typing import Optional, Iterator


class TransportBase(ABC):
    @abstractmethod
    def _iterate_packets(self, pcap_path: str) -> Iterator[Packet]:
        ...

    def __init__(self, transport_info: TransportInformation):
        self.logger = logging.getLogger(__name__)
        self._protocol = transport_info.transport_header.protocol.casefold()
        self._transport_specific_data = transport_info.transport_specific_data

    def decode_stream(
        self,
        container: Container,
        pcap_path: str,
        sdp: dict,
        track_id: str,
    ) -> None:
        stream_codec = get_stream_codec(
            self._protocol, sdp, track_id, self._transport_specific_data
        )
        if stream_codec is None:
            self.logger.warning(f"Skipping unsupported codec")
            return

        self.logger.info(f"Decoding stream with codec: {stream_codec.codec_name}")
        if stream_codec.codec_type == "video":
            out_stream = container.add_stream("h264", rate=30)
        elif stream_codec.codec_type == "audio":
            out_stream = container.add_stream("aac")
        else:
            raise ValueError(f"Unexpected codec type: {stream_codec.codec_type}")

        for packet in self._iterate_packets(pcap_path):
            self._handle_packet(container, out_stream, stream_codec, packet)

        self._flush_encoder(container, out_stream)

    def _handle_packet(
        self,
        container: Container,
        out_stream: Stream,
        stream_codec: StreamCodec,
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
