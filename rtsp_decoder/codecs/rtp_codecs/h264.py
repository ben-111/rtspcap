from base64 import b64decode
from dataclasses import dataclass, field
from fractions import Fraction
import logging

from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark.packet.packet import Packet

from rtsp_decoder.rtsp import RTPInfo
from rtsp_decoder.codecs.rtp_codecs.rtp_codec_base import RTPCodecBase

from typing import List, Optional, Tuple, Any


logger = logging.getLogger(__name__)

H264_STARTING_SEQUENCE = b"\x00\x00\x00\x01"
_H264_INPUT_BUFFER_PADDING_SIZE = 64


@dataclass
class H264Context:
    first_seq: Optional[int] = None
    rtptime: Optional[int] = None
    time_base: Fraction = field(default_factory=Fraction)
    fragments_buf: bytes = b""
    last_fragment_seq: int = -1
    fragment_timestamp: int = 0


class RTPCodecH264(RTPCodecBase):
    AV_CODEC_NAME = "h264"

    # Taken from ffmpeg: `rtpdec_h264.c:ff_h264_parse_sprop_parameter_sets`
    @classmethod
    def get_codec_context(
        cls, sdp_media: dict, rtp_info: Optional[RTPInfo]
    ) -> Tuple[CodecContext, Any]:
        h264_ctx = H264Context()

        if rtp_info is not None:
            h264_ctx.first_seq = rtp_info.seq
            h264_ctx.rtptime = rtp_info.rtptime

        fmtp = cls._parse_fmtp(sdp_media)
        assert (
            "sprop-parameter-sets" in fmtp
        ), "Expected sprop-parameter-sets in fmtp of h264"
        extradata = b""
        for sprop_parameter_set in fmtp["sprop-parameter-sets"].split(","):
            extradata += H264_STARTING_SEQUENCE
            extradata += b64decode(sprop_parameter_set)
            extradata += b"\x00" * _H264_INPUT_BUFFER_PADDING_SIZE

        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, "r")
        codec_ctx.extradata = extradata

        clock_rate_in_hz = sdp_media["rtp"][0]["rate"]
        h264_ctx.time_base = Fraction(1, clock_rate_in_hz)
        return codec_ctx, h264_ctx

    # Taken from ffmpeg: `rtpdec_h264.c:h264_handle_packet`
    @classmethod
    def handle_packet(
        cls,
        codec_ctx: CodecContext,
        packet: Optional[Packet],
        h264_ctx: H264Context,
    ) -> List[AVPacket]:
        out_packets = []
        if packet is None:
            logger.debug("Packet is None")
            if h264_ctx.fragments_buf:
                out_packet = cls._create_av_packet(
                    h264_ctx.fragments_buf,
                    h264_ctx.time_base,
                    h264_ctx.fragment_timestamp,
                )
                logger.debug(f"PTS = {h264_ctx.fragment_timestamp}")
            out_packets.append(cls._create_av_packet())
            return out_packets

        buf = bytes.fromhex(packet["RTP"].payload.raw_value)
        if len(buf) == 0:
            logger.error(f"RTP h264 invalid data")
            return

        current_timestamp = int(packet["RTP"].timestamp)
        if h264_ctx.rtptime is None:
            logger.debug("Losing packet to get accurate timestamp")
            h264_ctx.rtptime = current_timestamp
            return out_packets

        nal = buf[0]
        nal_type = nal & 0x1F

        if nal_type >= 1 and nal_type <= 23:
            nal_type = 1

        current_timestamp -= h264_ctx.rtptime
        logger.debug(
            f"Parsing H264 RTP packet with NAL type {nal_type}, timestamp {current_timestamp}"
        )

        current_seq = int(packet["RTP"].seq)
        if (
            nal_type != 28
            and current_seq > 0
            and current_seq == (h264_ctx.last_fragment_seq + 1)
        ):
            out_packet = cls._create_av_packet(
                h264_ctx.fragments_buf, h264_ctx.time_base, h264_ctx.fragment_timestamp
            )
            logger.debug(f"PTS = {h264_ctx.fragment_timestamp}")
            h264_ctx.fragments_buf = b""
            h264_ctx.last_fragment_seq = -1
            out_packets.append(out_packet)

        if nal_type == 0 or nal_type == 1:
            out_packet = cls._create_av_packet(
                H264_STARTING_SEQUENCE + buf, h264_ctx.time_base, current_timestamp
            )
            logger.debug(f"PTS = {current_timestamp}")
            out_packets.append(out_packet)
        elif nal_type == 24:
            # One packet, multiple NALs
            out_packets += cls._handle_aggregated_packet(
                h264_ctx, buf[1:], current_timestamp
            )
        elif nal_type == 28:
            # Fragmented NAL
            out_packets += cls._handle_fu_a_packet(
                h264_ctx, buf, current_seq, current_timestamp
            )
        else:
            logger.error(f"Got H264 RTP packet with unsupported NAL type: {nal_type}")

        return out_packets

    @classmethod
    def _handle_fu_a_packet(
        cls, h264_ctx: H264Context, buf: bytes, seq: int, timestamp: int
    ) -> List[AVPacket]:
        out_packets = []
        if len(buf) < 3:
            logger.error("Too short data for FU-A H.264 RTP packet")
            h264_ctx.fragments_buf = b""
            return out_packets

        if h264_ctx.last_fragment_seq >= 0 and seq != (h264_ctx.last_fragment_seq + 1):
            h264_ctx.last_fragment_seq = -1
            logger.error("Lost a fragment")
            h264_ctx.fragments_buf = b""
            return out_packets

        fu_indicator = buf[0]
        fu_header = buf[1]
        start_bit = fu_header >> 7
        nal_type = fu_header & 0x1F
        nal = fu_indicator & 0xE0 | nal_type

        buf = buf[2:]
        buffer_to_parse = b""
        if start_bit:
            logger.debug("Starting fragment")
            h264_ctx.fragment_timestamp = timestamp
            if h264_ctx.fragments_buf:
                out_packet = cls._create_av_packet(
                    h264_ctx.fragments_buf, h264_ctx.time_base, timestamp
                )
                logger.debug(f"PTS = {timestamp}")
                h264_ctx.fragments_buf = b""
                h264_ctx.last_fragment_seq = -1
                out_packets.append(out_packet)

            buffer_to_parse += H264_STARTING_SEQUENCE
            buffer_to_parse += nal.to_bytes(1, byteorder="little")
        elif h264_ctx.last_fragment_seq < 0:
            logger.error("Lost a fragment")
            h264_ctx.fragments_buf = b""
            return out_packets

        h264_ctx.last_fragment_seq = seq
        buffer_to_parse += buf

        h264_ctx.fragments_buf += buffer_to_parse
        return out_packets

    @classmethod
    def _handle_aggregated_packet(
        cls, h264_ctx: H264Context, buf: bytes, timestamp: int
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
            if nal_size <= len(buf):
                out_packet = cls._create_av_packet(
                    H264_STARTING_SEQUENCE + buf[:nal_size],
                    h264_ctx.time_base,
                    timestamp,
                )
                logger.debug(f"PTS = {timestamp}")
                out_packets.append(out_packet)

                buf = buf[nal_size:]
            else:
                logger.error(f"nal size exceeds length: {nal_size} > {len(buf)}")
                break

        return out_packets
