import logging

from typing import TypeVar, Generic, Dict, Optional, List, Iterator, Tuple

T = TypeVar("T")


class Reassembler(Generic[T]):
    """
    This class is a generic best-effort reassembler.
    """

    def __init__(self, seq_bit_size: int, max_out_of_order: int):
        self.logger = logging.getLogger(__name__)
        self._seq_bit_size = seq_bit_size
        self._max_out_of_order = max_out_of_order
        self._out_of_order_packets: Dict[int, T] = {}
        self._expected_seq: Optional[int] = None
        self._output_queue: List[Tuple[Optional[T], bool]] = []
        self._done: bool = False

    def get_output_packets(self) -> Iterator[Tuple[Optional[T], bool]]:
        while self._output_queue:
            packet_and_skipped = self._output_queue.pop(0)
            yield packet_and_skipped

    def _increment_expected_seq(self) -> None:
        self._expected_seq += 1
        self._expected_seq %= 1 << self._seq_bit_size

    def process(self, packet: Optional[T], seq: int = -1) -> None:
        """
        Process a packet with a sequence number.
        If packet is None, assume end of processing.
        """
        if self._done:
            raise ValueError("Reassembler is done")

        if self._expected_seq is None:
            self._expected_seq = seq
            self.logger.debug(f"First seq is {self._expected_seq}")

        # Dump all remaining packets at the end
        if packet is None:
            self._done = True
            while self._out_of_order_packets:
                earliest_packet_seq = min(self._out_of_order_packets.keys())
                skipped = earliest_packet_seq != self._expected_seq
                self.logger.debug(
                    f"Out of order packet with seq {earliest_packet_seq} found after the end of the packets; Appending to the end"
                )
                packet = self._out_of_order_packets.pop(earliest_packet_seq)
                self._output_queue.append((packet, skipped))
                if skipped:
                    self._expected_seq = earliest_packet_seq

                self._increment_expected_seq()

            self._output_queue.append((None, False))
            return

        # If an out-of-order packet was given, save it to the side until max_out_of_order
        # packets are reached. Then, rebase the expected seq and dump all applicable packets
        if seq != self._expected_seq:
            self._out_of_order_packets[seq] = packet
            if len(self._out_of_order_packets) < self._max_out_of_order:
                return

            self.logger.debug(
                f"Could not find packet with sequence number {self._expected_seq}; Likely packet loss"
            )
            if self._out_of_order_packets:
                self._expected_seq = min(self._out_of_order_packets.keys())
                self._output_queue.append(
                    (self._out_of_order_packets.pop(self._expected_seq), True)
                )
                while True:
                    self._increment_expected_seq()
                    if self._expected_seq not in self._out_of_order_packets:
                        break

                    self._output_queue.append(
                        (self._out_of_order_packets.pop(self._expected_seq), False)
                    )

            else:
                self._increment_expected_seq()

            return

        # Else, put the packet in the output queue
        self._output_queue.append((packet, False))
        self._increment_expected_seq()
