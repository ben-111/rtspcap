from rtsp_decoder.rtsp import TransportInformation

from rtsp_decoder.transport.transport_base import TransportBase
from rtsp_decoder.transport.rtp import RTPDecoder
from rtsp_decoder.transport.rtptcp import RTPOverTCPDecoder

from typing import Dict


class RTSPTransportDecoder:
    _DECODER_MAP: Dict[str, TransportBase] = {
        "rtp/avp": RTPDecoder,
        "rtp/avp/udp": RTPDecoder,
        # "rtp/avp/tcp": RTPOverTCPDecoder,
    }

    def __init__(self, transport_info: TransportInformation, output_path: str):
        protocol = transport_info.transport_header.protocol.casefold()
        if protocol not in self._DECODER_MAP:
            raise KeyError(f"Transport {protocol} not implemented")

        self._decoder = self._DECODER_MAP[protocol](transport_info, output_path)

    def decode_stream(self, pcap_path: str, sdp: dict, track_id: str):
        self._decoder.decode_stream(pcap_path, sdp, track_id)

    def close(self):
        self._decoder.close()

    def __enter__(self) -> "RTSPTransportDecoder":
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.close()
