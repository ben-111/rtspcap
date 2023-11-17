import re
from base64 import b64decode
from dataclasses import dataclass
import logging

from rtspcap.codecs.codec_base import CodecBase
from rtspcap.codecs.h264 import CodecH264
from rtspcap.codecs.h264 import H264_STARTING_SEQUENCE
from rtspcap.codecs.h264 import H264_INPUT_BUFFER_PADDING_SIZE

from av.codec import CodecContext
from av.packet import Packet as AVPacket

from rtspcap.task import RTPPacket

from typing import List, Optional, Tuple, Any


logger = logging.getLogger(__name__)


RTP_HEVC_PAYLOAD_HEADER_SIZE = 2
RTP_HEVC_DONL_FIELD_SIZE = 2
RTP_HEVC_DOND_FIELD_SIZE = 1
RTP_HEVC_FU_HEADER_SIZE = 1


@dataclass
class H265Context:
    profile_id: int = 0
    using_donl_field: bool = False


class CodecH265(CodecBase):
    AV_CODEC_NAME = "hevc"
    _SPROP_ATTRIBUTES = (
        "sprop-vps",
        "sprop-sps",
        "sprop-pps",
        "sprop-sei",
    )

    @classmethod
    def get_codec_context(cls, sdp_media: dict) -> Tuple[CodecContext, Any]:
        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, "r")
        width, height = cls._parse_framesize(sdp_media)
        codec_ctx.width = width
        codec_ctx.height = height

        h265_ctx = H265Context()
        fmtp = cls._parse_fmtp(sdp_media)

        if "profile-id" in fmtp:
            profile_id = int(fmtp["profile-id"])
            logger.debug(f"Found profile-id: {profile_id}")
            h265_ctx.profile_id = profile_id

        extradata = b""
        for sprop_attr in cls._SPROP_ATTRIBUTES:
            if sprop_attr in fmtp:
                for sprop_parameter_set in fmtp[sprop_attr].split(","):
                    extradata += H264_STARTING_SEQUENCE
                    extradata += b64decode(sprop_parameter_set)
                    extradata += b"\x00" * H264_INPUT_BUFFER_PADDING_SIZE

        if "sprop-max-don-diff" in fmtp and int(fmtp["sprop-max-don-diff"]):
            self.logger.debug("Found sprop-max-don-diff in SDP, using DON field")
            h265_ctx.using_donl_field = True

        if "sprop-depack-buf-nalus" in fmtp and int(fmtp["sprop-depack-buf-nalus"]):
            self.logger.debug("Found sprop-depack-buf-nalus in SDP, using DON field")
            h265_ctx.using_donl_field = True

        codec_ctx.extradata = extradata
        return codec_ctx, h265_ctx

    @classmethod
    def _parse_framesize(cls, sdp_media: dict) -> Tuple[int, int]:
        width = 0
        height = 0

        framesize_re = r"^framesize:\s*\d+\s+(\d+)-(\d+)$"

        if "invalid" in sdp_media:
            for extra_attr in sdp_media["invalid"]:
                if "value" in extra_attr:
                    re_match = re.search(framesize_re, extra_attr["value"])
                    if re_match is not None:
                        width, height = int(re_match[1]), int(re_match[2])

        return width, height

    # Taken from ffmpeg: `rtpdec_hevc.c:hevc_handle_packet`
    @classmethod
    def handle_packet(
        cls,
        codec_ctx: CodecContext,
        packet: Optional[RTPPacket],
        h265_ctx: H265Context,
    ) -> List[AVPacket]:
        """
        Decode the HEVC payload header according to section 4 of RFC 7798:

             0                   1
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |F|   Type    |  LayerId  | TID |
            +-------------+-----------------+

        Forbidden zero (F): 1 bit
        NAL unit type (Type): 6 bits
        NUH layer ID (LayerId): 6 bits
        NUH temporal ID plus 1 (TID): 3 bits
        """
        out_packets = []
        if not isinstance(h265_ctx, H265Context):
            logger.error("Expected H265 context")
            return out_packets

        if packet is None:
            return out_packets

        buf = packet.payload
        rtp_pl = buf
        if len(buf) < RTP_HEVC_PAYLOAD_HEADER_SIZE + 1:
            logger.error(f"Too short RTP/HEVC packet, got {len(buf)} bytes")
            return out_packets

        nal_type = (buf[0] >> 1) & 0x3F
        lid = ((buf[0] << 5) & 0x20) | ((buf[1] >> 3) & 0x1F)
        tid = buf[1] & 0x07

        if lid:
            logger.error("Multi-layer HEVC coding is not supported")
            return out_packets

        if not tid:
            logger.error("Illegal tmeporal ID in RTP/HEVC packet")
            return out_packets

        if nal_type > 50:
            logger.error(f"Unsupported (HEVC) NAL type ({nal_type})")
            return out_packets

        if nal_type == 48:
            # Aggregated packet - with two or more NAL units
            buf = buf[RTP_HEVC_DONL_FIELD_SIZE:]

            skip_between = 0
            if h265_ctx.using_donl_field:
                buf = buf[RTP_HEVC_DONL_FIELD_SIZE:]
                skip_between = RTP_HEVC_DOND_FIELD_SIZE

            out_packet += CodecH264.handle_aggregated_packet(
                codec_ctx, buf, skip_between
            )
        elif nal_type == 49:
            # Fragmentation unit (FU)
            # Decode the FU header
            #
            #    0 1 2 3 4 5 6 7
            #   +-+-+-+-+-+-+-+-+
            #   |S|E|  FuType   |
            #   +---------------+
            #
            # Start fragment (S): 1 bit
            # End fragment (E): 1 bit
            # FuType: 6 bits
            buf = buf[RTP_HEVC_PAYLOAD_HEADER_SIZE:]
            first_fragment = buf[0] & 0x80
            last_fragment = buf[0] & 0x40
            fu_type = buf[0] & 0x3F

            buf = buf[RTP_HEVC_FU_HEADER_SIZE:]

            if len(buf) == 0:
                logger.error(f"Too short RTP")
                return out_packets

            if h265_ctx.using_donl_field:
                buf = buf[RTP_HEVC_DONL_FIELD_SIZE:]

            logger.debug(f"FU type {fu_type} with {len(buf)} bytes")

            if len(buf) == 0:
                return out_packets

            if first_fragment and last_fragment:
                logger.error("Illegal combination of S and E bit in RTP/HEVC packet")
                return out_packets

            new_nal_header = bytearray(2)
            new_nal_header[0] = (rtp_pl[0] & 0x81) | (fu_type << 1)
            new_nal_header[1] = rtp_pl[1]

            out_packets += CodecH264.handle_frag_packet(
                codec_ctx, buf, first_fragment, bytes(new_nal_header)
            )

        elif nal_type == 50:
            # PACI packet
            logger.error("PACI packets for RTP/HEVC not supported")
        else:
            # NAL type in {32, 33, 34, 39} which are parameter sets, or its a single NAL unit packet
            out_packets += codec_ctx.parse(H264_STARTING_SEQUENCE + buf)

        return out_packets
