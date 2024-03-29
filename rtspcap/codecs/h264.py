from base64 import b64decode
import logging

from rtspcap.codecs.codec_base import CodecBase

from av.codec import CodecContext
from av.packet import Packet as AVPacket

from rtspcap.task import RTPPacket

from typing import List, Optional, Tuple, Any


logger = logging.getLogger(__name__)

H264_STARTING_SEQUENCE = b"\x00\x00\x00\x01"
H264_INPUT_BUFFER_PADDING_SIZE = 64


class CodecH264(CodecBase):
    AV_CODEC_NAME = "h264"

    # Taken from ffmpeg: `rtpdec_h264.c:ff_h264_parse_sprop_parameter_sets`
    @classmethod
    def get_codec_context(cls, sdp_media: dict) -> Tuple[CodecContext, Any]:
        fmtp = cls._parse_fmtp(sdp_media)
        extradata = b""
        if "sprop-parameter-sets" in fmtp:
            for sprop_parameter_set in fmtp["sprop-parameter-sets"].split(","):
                extradata += H264_STARTING_SEQUENCE
                extradata += b64decode(sprop_parameter_set)
                extradata += b"\x00" * H264_INPUT_BUFFER_PADDING_SIZE

        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, "r")
        codec_ctx.extradata = extradata
        return codec_ctx, None

    # Taken from ffmpeg: `rtpdec_h264.c:h264_handle_packet`
    @classmethod
    def handle_packet(
        cls,
        codec_ctx: CodecContext,
        packet: Optional[RTPPacket],
        _: Any,
    ) -> List[AVPacket]:
        out_packets = []
        if packet is None:
            return out_packets

        buf = packet.payload
        if len(buf) == 0:
            logger.error(f"RTP h264 invalid data")
            return out_packets

        nal = buf[0]
        nal_type = nal & 0x1F

        if nal_type >= 1 and nal_type <= 23:
            nal_type = 1

        logger.debug(f"Parsing H264 RTP packet with NAL type {nal_type}")
        if nal_type == 0 or nal_type == 1:
            out_packets = codec_ctx.parse(H264_STARTING_SEQUENCE + buf)
        elif nal_type == 24:
            # One packet, multiple NALs
            out_packets = cls.handle_aggregated_packet(codec_ctx, buf[1:])
        elif nal_type == 28:
            # Fragmented NAL
            out_packets = cls._handle_fu_a_packet(codec_ctx, buf)
        else:
            logger.error(f"Got H264 RTP packet with unsupported NAL type: {nal_type}")

        return out_packets

    @classmethod
    def _handle_fu_a_packet(cls, codec_ctx: CodecContext, buf: bytes) -> List[AVPacket]:
        if len(buf) < 3:
            logger.error("Too short data for FU-A H.264 RTP packet")
            return []

        fu_indicator = buf[0]
        fu_header = buf[1]
        start_bit = fu_header >> 7
        nal_type = fu_header & 0x1F
        nal = fu_indicator & 0xE0 | nal_type

        buf = buf[2:]
        return cls.handle_frag_packet(
            codec_ctx, buf, start_bit, nal.to_bytes(1, byteorder="little")
        )

    @classmethod
    def handle_frag_packet(
        cls, codec_ctx: CodecContext, buf: bytes, start_bit: int, nal_header: bytes
    ) -> List[AVPacket]:
        buffer_to_parse = b""
        if start_bit:
            buffer_to_parse += H264_STARTING_SEQUENCE
            buffer_to_parse += nal_header
        buffer_to_parse += buf

        return codec_ctx.parse(buffer_to_parse)

    @classmethod
    def handle_aggregated_packet(
        cls, codec_ctx: CodecContext, buf: bytes, skip_between: int = 0
    ) -> List[AVPacket]:
        """
        An aggregated packet is an array of NAL units.
        A NAL unit is a `uint16 nal_size` followed by a buffer of that size
        """
        out_packets = []
        while len(buf) > 2:
            nal_size_bytes = buf[:2]
            nal_size = int.from_bytes(nal_size_bytes, byteorder="little")
            buf = buf[2:]
            if nal_size > len(buf):
                logger.error(f"nal size exceeds length: {nal_size} > {len(buf)}")
                break

            out_packets += codec_ctx.parse(H264_STARTING_SEQUENCE + buf[:nal_size])
            buf = buf[nal_size + skip_between :]

        return out_packets
