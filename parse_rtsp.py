from binascii import unhexlify
from enum import Enum

from pyshark import FileCapture
import sdp_transform

from typing import NamedTuple, Dict


class RTSPTransportHeader(NamedTuple):
    protocol: str
    options: Dict[str, str]

    @classmethod
    def parse(cls, header_str: str) -> 'RTSPTransportHeader':
        transport_header_values = header_str.split(';')
        protocol = transport_header_values[0]
        options = dict()
        for option in transport_header_values[1:]:
            key, value = option.split('=', 1) if '=' in option else (option, None)
            options[key] = value

        return cls(protocol=protocol, options=options)


class RTSPTrack(NamedTuple):
    server_ip: str
    server_port: int
    client_port: int


class _State(Enum):
    GET_SDP = 0
    GET_TRACKS = 1


class RTSPDataExtractor:
    """
    Find the first RTSP stream, and extract from it the stream name, the sdp and the tracks
    """
    def __init__(self, pcap_path: str):
        self.stream_name = None
        self.sdp = None
        self.tracks = dict()

        # Currently only taking the first stream we find
        cap = FileCapture(pcap_path, display_filter=f'rtsp')
        first_rtsp = cap.next()
        tcp_stream = first_rtsp.tcp.stream
        self._cap = FileCapture(
            pcap_path,
            display_filter=f'rtsp and tcp.stream == {tcp_stream}',
            disable_protocol='sdp', # We disable sdp so we can access the SDP data directly
        )
        self._state_mapping = {
            _State.GET_SDP: self._get_sdp,
            _State.GET_TRACKS: self._get_tracks,
        }

        self._extract_rtsp_data()

    def _extract_rtsp_data(self):
        self._state = _State.GET_SDP
        while True:
            try:
                request = self._cap.next()
                response = self._cap.next()
                self._state_mapping[self._state](request, response)
            except StopIteration:
                break

    def _get_sdp(self, request, response):
        if hasattr(request.rtsp, 'method') and request.rtsp.method == 'DESCRIBE':
            self.stream_name = request.rtsp.url
            self.sdp = sdp_transform.parse(unhexlify(response.rtsp.data.replace(':', '')).decode())
            self._state = _State.GET_TRACKS

    def _get_tracks(self, request, response):
        if hasattr(request.rtsp, 'method') and request.rtsp.method == 'SETUP':
            track_id = request.rtsp.url
            transport = RTSPTransportHeader.parse(response.rtsp.transport)
            assert transport.protocol == 'RTP/AVP', f'Only RTP/AVP is supported, I\'m getting {transport_protocol}'
            server_ip = str(response.ip.src)
            client_port, _ = transport.options['client_port'].split('-', 1)
            server_port, _ = transport.options['server_port'].split('-', 1)
            assert 'source' not in transport.options, 'Different source is not supported'

            self.tracks[track_id] = RTSPTrack(
                server_ip=server_ip,
                server_port=int(server_port),
                client_port=int(client_port),
            )
