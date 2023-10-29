from abc import ABC, abstractmethod

from rtsp_decoder.rtsp import TransportInformation


class TransportBase(ABC):
    @abstractmethod
    def __init__(self, transport_info: TransportInformation, output_path: str):
        ...

    @abstractmethod
    def decode_stream(self, pcap_path: str, sdp: dict, track_id: str) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...
