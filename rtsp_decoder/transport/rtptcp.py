from pyshark import FileCapture
from pyshark.packet.packet import Packet

from rtsp_decoder.transport.transport_base import TransportBase
from rtsp_decoder.rtsp import TransportInformation

from typing import Iterator


class RTPOverTCPDecoder(TransportBase):
    def __init__(self, transport_info: TransportInformation, output_path: str):
        super().__init__(transport_info, output_path)
        self._display_filter = self._build_display_filter(transport_info)

    def _build_display_filter(self, transport_info: TransportInformation) -> str:
        transport_header = transport_info.transport_header
        stream_num = transport_info.rtsp_tcp_stream_num
        assert "ssrc" in transport_header.options
        ssrc = transport_header.options["ssrc"]

        display_filter = f"rtp.ssrc == 0x{ssrc}"
        return display_filter

    def _iterate_packets(self, pcap_path: str) -> Iterator[Packet]:
        with FileCapture(pcap_path, display_filter=self._display_filter) as rtp_capture:
            for packet in rtp_capture:
                yield packet

        # Flush the decoder
        yield None
