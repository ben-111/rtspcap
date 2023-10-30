import logging
from enum import Enum
from fractions import Fraction
from dataclasses import dataclass, field

from av.codec import CodecContext
from av.packet import Packet as AVPacket

from pyshark.packet.packet import Packet

from rtsp_decoder.rtsp import RTPInfo
from rtsp_decoder.codecs.rtp_codecs.rtp_codec_base import RTPCodecBase

from typing import NamedTuple, List, Dict, Tuple, Any, Optional

logger = logging.getLogger(__name__)


_INT32_BIT_SIZE = 32
_SIGNED_INT32_LIMIT = 2 ** (_INT32_BIT_SIZE - 1)
INT32_MIN = -_SIGNED_INT32_LIMIT
INT32_MAX = _SIGNED_INT32_LIMIT - 1


class AACAttributeVaType(Enum):
    TYPE_INT = 0
    TYPE_STR = 1


class AACAttribute(NamedTuple):
    valtype: AACAttributeVaType
    range_min: int = 0
    range_max: int = 0


class AUHeader(NamedTuple):
    size: int = 0
    index: int = 0

    # Maybe will use one day
    cts_flag: int = 0
    cts: int = 0
    dts_flag: int = 0
    dts: int = 0
    rap_flag: int = 0
    streamstate: int = 0


MAX_RTP_PACKET_LENGTH = 8192


@dataclass
class AACContext:
    first_seq: Optional[int] = None
    rtptime: Optional[int] = None
    attributes: Dict[str, AACAttribute] = field(default_factory=dict)
    time_base: Fraction = field(default_factory=Fraction)
    au_duration: Optional[int] = None
    buf: bytes = b""
    expected_buf_size: int = 0
    timestamp: int = 0


class GetBitContext:
    def __init__(self, buffer: bytes):
        self.buffer = buffer
        self.bitpos = 0

    def get_bits(self, n: int) -> int:
        result = 0
        remaining_bits = n

        while remaining_bits > 0:
            if not len(self.buffer):
                raise ValueError("End of buffer reached early")

            current_byte = self.buffer[0]

            bits_to_read = min(remaining_bits, 8 - self.bitpos)
            mask = (1 << bits_to_read) - 1

            result <<= bits_to_read
            result |= (current_byte >> (8 - bits_to_read - self.bitpos)) & mask

            remaining_bits -= bits_to_read
            self.bitpos = (self.bitpos + bits_to_read) % 8

            if self.bitpos == 0:
                self.buffer = self.buffer[1:]

        return result


class RTPCodecMPEG4_GENERIC(RTPCodecBase):
    AV_CODEC_NAME = "aac"
    MAX_AAC_HBR_FRAME_SIZE = 8191
    _FMTP_ATTRIBUTES: Dict[str, AACAttribute] = {
        "sizelength": AACAttribute(
            valtype=AACAttributeVaType.TYPE_INT, range_min=0, range_max=32
        ),
        "indexlength": AACAttribute(
            valtype=AACAttributeVaType.TYPE_INT, range_min=0, range_max=32
        ),
        "indexdeltalength": AACAttribute(
            valtype=AACAttributeVaType.TYPE_INT, range_min=0, range_max=32
        ),
        "profile-level-id": AACAttribute(
            valtype=AACAttributeVaType.TYPE_INT,
            range_min=INT32_MIN,
            range_max=INT32_MAX,
        ),
        "streamtype": AACAttribute(
            valtype=AACAttributeVaType.TYPE_INT, range_min=0, range_max=0x3F
        ),
        "mode": AACAttribute(valtype=AACAttributeVaType.TYPE_STR),
    }

    # Taken from ffmpeg: `rtpdec_mpeg4.c:parse_sdp_line`
    @classmethod
    def get_codec_context(
        cls, sdp_media: dict, rtp_info: Optional[RTPInfo]
    ) -> Tuple[CodecContext, Any]:
        aac_ctx = AACContext()

        if rtp_info is not None:
            aac_ctx.first_seq = rtp_info.seq
            aac_ctx.rtptime = rtp_info.rtptime

        fmtp = RTPCodecBase._parse_fmtp(sdp_media)

        codec_ctx = CodecContext.create(cls.AV_CODEC_NAME, "r")
        if "config" in fmtp:
            codec_ctx.extradata = bytes.fromhex(fmtp["config"])
        else:
            logger.error("Expected config attribute in fmtp")

        rtp_data = sdp_media["rtp"][0]
        codec_ctx.layout = int(rtp_data["encoding"]) if "encoding" in rtp_data else 1

        clock_rate_in_hz = rtp_data["rate"]
        aac_ctx.time_base = Fraction(1, clock_rate_in_hz)

        for attr_name, attr_options in cls._FMTP_ATTRIBUTES.items():
            if attr_name in fmtp:
                logger.debug(f"Found attribute {attr_name}")
                value = None
                if attr_options.valtype == AACAttributeVaType.TYPE_INT:
                    try:
                        value = int(fmtp[attr_name])
                    except ValueError:
                        logger.error(f"The {attr_name} field is not a valid number")
                        continue

                    if value < attr_options.range_min or value > attr_options.range_max:
                        logger.error(
                            f"fmtp field {attr_name} should be in range "
                            + f"[{attr_options.range_min},{attr_options.range_max}] "
                            + f"(provided value: {value})"
                        )
                        continue
                elif attr_options.valtype == AACAttributeVaType.TYPE_STR:
                    value = str(fmtp[attr_name])
                else:
                    logger.error("Unexpected AAC attribute value type")
                    continue

                aac_ctx.attributes[attr_name] = value

        attrs = aac_ctx.attributes
        assert (
            "sizelength" in attrs and "indexlength" in attrs
        ), "Expected sizelength and indexlength"
        return codec_ctx, aac_ctx

    # Taken from ffmpeg: `rtpdec_mpeg4.c:aac_parse_packet`
    @classmethod
    def handle_packet(
        cls,
        codec_ctx: CodecContext,
        packet: Optional[Packet],
        aac_ctx: AACContext,
    ) -> List[AVPacket]:
        """
        RFC 3640 describes the format of the RTP packets carrying mpeg4 type streams.

        The RTP payload following the RTP header, contains three octet-
        aligned data sections, of which the first two MAY be empty.

         +---------+-----------+-----------+---------------+
         | RTP     | AU Header | Auxiliary | Access Unit   |
         | Header  | Section   | Section   | Data Section  |
         +---------+-----------+-----------+---------------+

        The first data section is the AU (Access Unit) Header Section, that
        contains one or more AU-headers; however, each AU-header MAY be
        empty, in which case the entire AU Header Section is empty.  The
        second section is the Auxiliary Section, containing auxiliary data;
        this section MAY also be configured empty.  The third section is the
        Access Unit Data Section, containing either a single fragment of one
        Access Unit or one or more complete Access Units.  The Access Unit
        Data Section MUST NOT be empty.

        The Marker bit is set to 1 to indicate that the RTP packet
        payload contains either the final fragment of a fragmented Access
        Unit or one or more complete Access Units.
        """
        out_packets = []
        if not isinstance(aac_ctx, AACContext):
            logger.error("Expected AAC context")
            return out_packets

        if packet is None:
            return out_packets

        buf = bytes.fromhex(packet["RTP"].payload.raw_value)
        try:
            au_headers, au_headers_section_size = cls._parse_mp4_au_headers(
                aac_ctx, buf
            )
        except ValueError as e:
            logger.error(f"Error parsing AU headers: {str(e)}")
            return out_packets

        current_au_timestamp = int(packet["RTP"].timestamp)
        current_seq = int(packet["RTP"].seq)
        if (
            aac_ctx.rtptime is None
            or aac_ctx.first_seq is None
            or (aac_ctx.au_duration is None and current_seq != aac_ctx.first_seq)
        ):
            logger.warning("Losing a packet to determine AU duration")
            aac_ctx.first_seq = current_seq + 1
            aac_ctx.rtptime = current_au_timestamp
            return out_packets
        elif aac_ctx.au_duration is None:
            diff = current_au_timestamp - aac_ctx.rtptime
            aac_ctx.au_duration = diff // len(au_headers)

        current_au_timestamp -= aac_ctx.rtptime
        buf = buf[au_headers_section_size:]
        if len(au_headers) == 1 and len(buf) < au_headers[0].size:
            # Packet is fragmented
            logger.debug(f"Fragmented AU")
            return cls._handle_fragmented_packet(
                aac_ctx, au_headers, packet, buf, current_au_timestamp
            )

        # Assuming no auxiliiary section
        logger.debug(f"Data section size: {len(buf)}")
        if not au_headers:
            return out_packets

        for au_header in au_headers:
            if len(buf) < au_header.size:
                logger.error("AU larger than packet size")
                return out_packets

            data = buf[: au_header.size]
            buf = buf[au_header.size :]
            out_packet = cls._create_av_packet(
                data, aac_ctx.time_base, current_au_timestamp
            )
            logger.debug(f"PTS = {current_au_timestamp}")
            current_au_timestamp += aac_ctx.au_duration
            out_packets.append(out_packet)

        return out_packets

    @classmethod
    def _handle_fragmented_packet(
        cls,
        aac_ctx: AACContext,
        au_headers: List[AUHeader],
        packet: Packet,
        buf: bytes,
        current_au_timestamp: int,
    ) -> List[AVPacket]:
        out_packets = []
        if len(aac_ctx.buf) == 0:
            # First fragment
            if au_headers[0].size > cls.MAX_AAC_HBR_FRAME_SIZE:
                logger.error("Invalid AU size")
                return out_packets

            aac_ctx.expected_buf_size = au_headers[0].size
            aac_ctx.timestamp = int(packet["RTP"].timestamp)

        if (
            aac_ctx.timestamp != int(packet["RTP"].timestamp)
            or au_headers[0].size != aac_ctx.expected_buf_size
            or len(aac_ctx.buf) + len(buf) > cls.MAX_AAC_HBR_FRAME_SIZE
        ):
            aac_ctx.expected_buf_size = 0
            aac_ctx.buf = bytes()
            logger.error("Invalid packet received")
            return out_packets

        aac_ctx.buf += buf

        if not int(packet["RTP"].marker):
            # There are more fragments
            return out_packets

        # Last fragment
        if len(aac_ctx.buf) != aac_ctx.expected_buf_size:
            aac_ctx.buf = b""
            logger.error("Missed some packets, discarding frame")
            return out_packets

        out_packet = cls._create_av_packet(
            aac_ctx.buf, aac_ctx.time_base, current_au_timestamp
        )
        aac_ctx.buf = b""
        out_packets.append(out_packet)
        return out_packets

    @classmethod
    def _parse_mp4_au_headers(
        cls, aac_ctx: AACContext, buf: bytes
    ) -> Tuple[List[AUHeader], int]:
        """
        When present, the AU Header Section consists of the AU-headers-length
        field, followed by a number of AU-headers.

        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- .. -+-+-+-+-+-+-+-+-+-+
        |AU-headers-length|AU-header|AU-header|      |AU-header|padding|
        |                 |   (1)   |   (2)   |      |   (n)   | bits  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- .. -+-+-+-+-+-+-+-+-+-+

        The AU-headers-length is a two octet field that specifies the length in bits
        of the immediately following AU-headers, excluding the padding bits.

        returns: List of AU headers, size of AU-Headers-Section in bytes.
        """
        if len(buf) < 2:
            raise ValueError("Invalid Data")

        # Assuming the AU headers section exists
        au_headers_length_in_bits = int.from_bytes(buf[:2], byteorder="big")
        buf = buf[2:]
        logger.debug(f"AU headers length in bits: {au_headers_length_in_bits}")

        # Calculate size of AU headers including the padding bits
        au_headers_length_bytes = (au_headers_length_in_bits + 7) // 8
        if au_headers_length_bytes > MAX_RTP_PACKET_LENGTH:
            raise ValueError("Invalid AU headers length")

        au_headers_section_size = 2 + au_headers_length_bytes

        if len(buf) < au_headers_length_bytes:
            raise ValueError("Invalid Data")

        get_bit_context = GetBitContext(buf[:au_headers_length_bytes])

        # Assuming only sizelength and indexlength fields exist in each AU header
        # and that indexlength == indexdeltalength
        au_header_size_in_bits = (
            aac_ctx.attributes["sizelength"] + aac_ctx.attributes["indexlength"]
        )
        logger.debug(f"AU header size in bits: {au_header_size_in_bits}")

        # FIXME: This is wrong if optional additional sections are present
        if (
            au_header_size_in_bits <= 0
            or (au_headers_length_in_bits % au_header_size_in_bits) != 0
        ):
            raise ValueError("Invalid AU header size")

        number_of_au_headers = au_headers_length_in_bits // au_header_size_in_bits
        current_index = 0
        au_headers = []
        for i in range(number_of_au_headers):
            size = get_bit_context.get_bits(aac_ctx.attributes["sizelength"])
            index = get_bit_context.get_bits(aac_ctx.attributes["indexlength"])
            if i == 0:
                current_index = index
            else:
                if index != 0:
                    raise ValueError("Interleaving not supported")
                current_index += index + 1
            au_header = AUHeader(size=size, index=current_index)
            logger.debug(f"Found AU Header: {au_header}")

            au_headers.append(au_header)

        return au_headers, au_headers_section_size

    @staticmethod
    def _create_av_packet(data: bytes, time_base: Fraction, timestamp: int) -> AVPacket:
        out_packet = AVPacket(data)
        out_packet.time_base = time_base
        out_packet.pts = timestamp
        out_packet.dts = timestamp
        return out_packet
