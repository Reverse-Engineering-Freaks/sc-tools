"""APDU"""

from typing import Literal

ExtendedLiteral = Literal[False, "allow", "force"]
LeLiteral = Literal["max"]


class CommandApdu:
    """Command APDU"""

    @staticmethod
    def __lc_bytes(lc: int, extended: bool) -> bytes:
        """Get Lc as bytes

        Args:
            lc (int): Lc
            extended (bool): Extended

        Raises:
            ValueError: Invalid argument `lc`

        Returns:
            bytes: Lc as bytes
        """

        if extended:
            if lc < 0x01 or 0x10000 < lc:
                raise ValueError("Argument `lc` out of range. (0x01 <= lc <= 0x10000)")
        else:
            if lc < 0x01 or 0x100 < lc:
                raise ValueError("Argument `lc` out of range. (0x01 <= lc <= 0x100)")

        return lc.to_bytes(length=2 if extended else 1, byteorder="big")

    @staticmethod
    def __le_bytes(le: int, extended: bool) -> bytes:
        """Get Le as bytes

        Args:
            le (int): Le
            extended (bool): Extended

        Raises:
            ValueError: Invalid argument `le`

        Returns:
            bytes: Le as bytes
        """

        if extended:
            if le < 0x01 or 0x10000 < le:
                raise ValueError("Argument `le` out of range. (0x01 <= le <= 0x10000)")
        else:
            if le < 0x01 or 0x100 < le:
                raise ValueError("Argument `le` out of range. (0x01 <= le <= 0x100)")

        if extended and le == 0x10000:
            return b"\x00\x00"
        if not extended and le == 0x100:
            return b"\x00"
        return le.to_bytes(length=2 if extended else 1, byteorder="big")

    def __init__(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes | None = None,
        le: int | LeLiteral = 0x00,
        extended: ExtendedLiteral = "allow",
    ) -> None:
        """Constructor

        Args:
            cla (int): CLA
            ins (int): INS
            p1 (int): P1
            p2 (int): P2
            data (bytes | None, optional): Data. Defaults to None.
            le (int | LeLiteral, optional): Le. Defaults to 0x00.
            extended (ExtendedLiteral, optional): Extended restriction. Defaults to "allow".
        """

        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.le = le
        self.extended = extended

    def to_bytes(self) -> bytes:
        """To bytes

        Raises:
            ValueError: Invalid property `data`

        Returns:
            bytes: The instance as bytes
        """

        le = self.le
        if le == "max":
            if self.extended != False:
                le = 0x10000
            else:
                le = 0x100
        lc = len(self.data) if self.data is not None else 0x00
        extended = self.extended == "force" or (
            self.extended == "allow" and 0x100 <= lc or 0x100 < le
        )

        buffer = bytearray()
        buffer.append(self.cla)
        buffer.append(self.ins)
        buffer.append(self.p1)
        buffer.append(self.p2)
        if extended:
            buffer.append(0x00)
        if self.data is not None:
            buffer.extend(CommandApdu.__lc_bytes(lc, extended))
            buffer.extend(self.data)
        if le != 0x00:
            buffer.extend(CommandApdu.__le_bytes(le, extended))
        return bytes(buffer)
