import av
from pyshark import FileCapture
from pyshark.packet.packet import Packet

from typing import Dict, Optional

import logging

class RTPDecoder:
    MAX_OUT_OF_ORDER_PACKETS = 20
    def __init__(self, output_path: str):
        self.container = av.open(output_path, 'w')
        self.logger = logging.getLogger(self.__name__)

    def decode_stream(self, rtp_capture: FileCapture, config: Dict[str, str], codec: str, rate: int):
        """Assume rtp_capture is filtered so that all RTP packets we see are from the same stream"""
        input_codec_ctx = av.codec.CodecContext.create(codec, 'r')
        if input_codec_ctx.type == 'video':
            stream = self.container.add_stream('h264', rate=30)
            if 'config' in config:
                input_codec_ctx.extradata = bytes.fromhex(config['config'])
        # TODO: support audio
        # elif input_codec_ctx.type == 'audio':
        #     stream = self.container.add_stream('aac')
        #     input_codec_ctx.rate = rate
        #     input_codec_ctx.channels = config['channels']
        else:
            self.logger.warning(f'Unsupported stream type: {input_codec_ctx.type}, with codec: {codec}, skipping')
            return

        out_of_order_packets: Dict[int, Packet] = dict()
        expected_seq = None
        rtp_stream = filter(lambda x: 'RTP' in x, rtp_capture)
        try:
            expected_seq = int(next(rtp_stream)['RTP'].seq) + 1
        except StopIteration:
            raise ValueError('RTP stream not found')

        for packet in rtp_stream:
            seq = int(packet['RTP'].seq)
            if seq != expected_seq:
                if seq in out_of_order_packets:
                    packet = out_of_order_packets.pop(seq)
                else:
                    if len(out_of_order_packets) > self.MAX_OUT_OF_ORDER_PACKETS:
                        # We likely lost a packet
                        expected_seq += 1
                    else:
                        out_of_order_packets[seq] = packet
                    continue

            chunk = bytes.fromhex(packet['RTP'].payload.raw_value)
            out_packets = input_codec_ctx.parse(chunk)
            for out_packet in out_packets:
                frames = input_codec_ctx.decode(out_packet)
                for frame in frames:
                    encoded_packet = stream.encode(frame)
                    self.container.mux(encoded_packet)

            expected_seq += 1
        
        # Flush the encoder
        out_packet = stream.encode(None)
        self.container.mux(out_packet)

    def close(self):
        self.container.close()
