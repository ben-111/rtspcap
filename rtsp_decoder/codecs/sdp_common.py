from abc import ABC, abstractmethod

from av.codec import CodecContext

from typing import Dict


def parse_fmtp(sdp_media: dict) -> Dict[str, str]:
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


class CodecSDPParser(ABC):
    @staticmethod
    @abstractmethod
    def get_codec_context(sdp_media: dict) -> CodecContext:
        ...
