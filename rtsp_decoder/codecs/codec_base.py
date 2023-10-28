from abc import ABC, abstractmethod
from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark.packet.packet import Packet

from typing import Dict, List


class CodecBase(ABC):
    @staticmethod
    @abstractmethod
    def get_codec_context(sdp_media: dict) -> CodecContext:
        ...

    @staticmethod
    def handle_packet(
        codec_ctx: CodecContext,
        packet: Packet,
    ) -> List[AVPacket]:
        chunk = bytes.fromhex(packet["RTP"].payload.raw_value)
        return codec_ctx.parse(chunk)

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
                    fmtp_config[key] = value
        return fmtp_config
