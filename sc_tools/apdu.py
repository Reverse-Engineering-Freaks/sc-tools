"""APDU"""

from typing import Literal

LeLiteral = Literal["max"]


def max_lc_le(extended_apdu: bool) -> int:
    """Get Max Lc/Le value

    Returns:
        int: Max Lc/Le value
    """

    return 0x10000 if extended_apdu else 0x100


class CommandApdu:
    """Command APDU"""

    def __init__(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes | None = None,
        le: int | LeLiteral = 0x00,
        extended: bool = True,
    ) -> None:
        """Constructor

        Args:
            cla (int): CLA
            ins (int): INS
            p1 (int): P1
            p2 (int): P2
            data (bytes | None, optional): Data. Defaults to None.
            le (int | LeLiteral, optional): Le. Defaults to 0x00.
            extended (bool, optional): Is extended. Defaults to True.
        """

        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.le = le
        self.extended = extended

    def max_lc_le(self) -> int:
        """Get Max Lc/Le value

        Returns:
            int: Max Lc/Le value
        """

        return max_lc_le(self.extended)

    def lc_le_bytes(self, lc_le: int) -> bytes:
        """Get Lc/Le bytes

        Args:
            lc_le (int): Lc/Le value

        Raises:
            ValueError: Invalid argument `lc_le`

        Returns:
            bytes: Lc/Le value as bytes
        """

        if lc_le < 0x01:
            raise ValueError("Argument `lc_le` must be greater than or equal 0x01.")
        if self.extended:
            if 0x10000 < lc_le:
                raise ValueError("Argument `lc_le` must be less than or equal 0x10000.")
        else:
            if 0x100 < lc_le:
                raise ValueError("Argument `lc_le` must be less than or equal 0x100.")

        if self.extended:
            if lc_le == 0x10000:
                return b"\x00\x00\x00"
            return b"\x00" + lc_le.to_bytes(length=2, byteorder="big")
        else:
            if lc_le == 0x100:
                return b"\x00"
            return lc_le.to_bytes(length=1)

    def to_bytes(self) -> bytes:
        """To bytes

        Raises:
            ValueError: Invalid property `data`

        Returns:
            bytes: The instance as bytes
        """

        if self.data is not None and self.max_lc_le() < len(self.data):
            raise ValueError("Property `data` length out of capcacity.")

        buffer = bytearray()
        buffer.append(self.cla)
        buffer.append(self.ins)
        buffer.append(self.p1)
        buffer.append(self.p2)
        if self.data is not None:
            buffer.extend(self.lc_le_bytes(len(self.data)))
            buffer.extend(self.data)
        if isinstance(self.le, int) and self.le != 0x00:
            buffer.extend(self.lc_le_bytes(self.le))
        elif self.le == "max":
            buffer.extend(self.lc_le_bytes(self.max_lc_le()))
        return bytes(buffer)
