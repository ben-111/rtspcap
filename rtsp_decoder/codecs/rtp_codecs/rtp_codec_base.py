from abc import ABC, abstractmethod
from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark.packet.packet import Packet

from typing import Dict, List, Optional, Tuple, Any


class RTPCodecBase(ABC):
    @property
    @abstractmethod
    def AV_CODEC_NAME(self) -> str:
        ...

    @classmethod
    @abstractmethod
    def get_codec_context(cls, sdp_media: dict) -> Tuple[CodecContext, Any]:
        ...

    @classmethod
    def handle_packet(
        cls,
        codec_ctx: CodecContext,
        packet: Optional[Packet],
        payload_ctx: Any,
    ) -> List[AVPacket]:
        out_packets = []
        if packet is not None:
            chunk = bytes.fromhex(packet["RTP"].payload.raw_value)
            out_packets = codec_ctx.parse(chunk)
        return out_packets

    @staticmethod
    def _parse_fmtp(sdp_media: dict) -> Dict[str, str]:
        fmtp_config: Dict[str, str] = dict()
        if "fmtp" in sdp_media and len(sdp_media["fmtp"]) > 0:
            fmtp_data = sdp_media["fmtp"][0]
            if "config" in fmtp_data:
                config = fmtp_data["config"]
                parameters = config.split("; ")
                for parameter in parameters:
                    key, value = parameter.split("=", 1)
                    fmtp_config[key.casefold()] = value
        return fmtp_config
