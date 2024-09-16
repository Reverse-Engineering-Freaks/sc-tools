"""Card Connection"""

import logging
from nfc.tag.tt4 import Type4Tag
from smartcard.CardConnection import CardConnection as PyscardCardConnection
from typing import Callable, Literal

from .apdu import max_lc_le, CommandApdu
from .card_response import CardResponseStatusType, CardResponseStatus, CardResponseError


FciLiteral = Literal["first", "next", False]


class CardConnection:
    """Card Connection Wrapper"""

    def __init__(
        self,
        transmit: Callable[[bytes], tuple[CardResponseStatus, bytes]],
        allow_extended_apdu=False,
        identifier: bytes | None = None,
    ) -> None:
        """Constructor

        Args:
            transmit (Callable[[bytes], tuple[CardResponseStatus, bytes]]): Transmit function
            allow_extended_apdu (bool, optional): Allow Extended APDU. Defaults to False.
            identifier (bytes | None, optional): Identifier for NFC. Defaults to None.
        """

        self.__logger = logging.getLogger(__name__)

        self.__transmit = transmit
        self.allow_extended_apdu = allow_extended_apdu
        self.identifier = identifier

    def transmit(
        self, command: bytes, raise_error: bool = True
    ) -> tuple[CardResponseStatus, bytes]:
        """Transmit

        Args:
            command (bytes): Command
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            CardResponseError: Card returned error response

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        command_hex = command.hex(" ").upper()
        self.__logger.debug(f"SC <- {command_hex}")

        status, data = self.__transmit(command)
        status_type = status.status_type()

        sw_hex = format(status.sw, "04X")
        if len(data) != 0:
            data_hex = data.hex(" ").upper()
            self.__logger.debug(f"SC -> {data_hex} - SW: {sw_hex} ({status_type.name})")
        else:
            self.__logger.debug(f"SC -> SW: {sw_hex} ({status_type.name})")

        if raise_error and status_type != CardResponseStatusType.NORMAL_END:
            raise CardResponseError(status)
        return status, data

    def read_binary(
        self,
        cla: int = 0x00,
        offset: int = 0,
        limit: int | None = None,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """READ BINARY

        Args:
            cla (int, optional): CLA. Defaults to 0x00.
            offset (int, optional): Offset. Defaults to 0.
            limit (int | None, optional): Limit. Defaults to None.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `offset`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if limit is None:
            limit = "max"

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")
        if offset < 0x0000 or 0xFFFF < offset:
            raise ValueError(
                "Argument `offset` out of range. (0x0000 <= offset <= 0xFFFF)"
            )

        command = CommandApdu(
            cla,
            0xB0,
            offset >> 8,
            offset & 0xFF,
            le=limit,
            extended=self.allow_extended_apdu,
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def read_all_binary(
        self,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """READ (ALL) BINARY

        Args:
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            CardResponseError: Card returned error response

        Returns:
            tuple[CardResponseStatus, bytes]: Last Response Status and entire Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        max_bulk_read_length = max_lc_le(self.allow_extended_apdu)
        status, data = self.read_binary(cla=cla, offset=0x0000, raise_error=raise_error)
        chunk_data = data
        while len(chunk_data) == max_bulk_read_length:
            offset = len(data)
            status, chunk_data = self.read_binary(
                cla=cla, offset=offset, raise_error=False
            )
            status_type = status.status_type()
            if (
                status_type
                == CardResponseStatusType.OFFSET_SPECIFIED_OUT_OF_THE_EF_RANGE
            ):
                # Reached to End of Data
                break
            if raise_error and status_type != CardResponseStatusType.NORMAL_END:
                raise CardResponseError(status)
            data += chunk_data
        return status, data

    def read_record(
        self,
        cla: int = 0x00,
        limit: int | None = None,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """READ RECORD(S)

        Args:
            cla (int, optional): CLA. Defaults to 0x00.
            limit (int | None, optional): Limit. Defaults to None.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if limit is None:
            limit = "max"

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(
            cla,
            0xB2,
            0x01,
            0x05,
            le=limit,
            extended=self.allow_extended_apdu,
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def select_df(
        self,
        df_id: bytes,
        fci: FciLiteral = False,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """SELECT FILE (DF)

        Args:
            df_id (bytes): DF Ientifier
            fci (bool, optional): Get File Control Information
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(cla, 0xA4, 0x04, 0x0C, data=df_id, extended=False)
        if fci == "first":
            command.p2 = 0x00
            command.le = "max"
        elif fci == "next":
            command.p2 = 0x02
            command.le = "max"
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def select_ef(
        self,
        ef_id: bytes,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """SELECT FILE (EF)

        Args:
            ef_id (bytes): EF Identifier
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `ef_id`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")
        if len(ef_id) != 2:
            raise ValueError("Argument `ef_id` length must be 2.")

        command = CommandApdu(cla, 0xA4, 0x02, 0x0C, data=ef_id, extended=False)
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def verify(
        self,
        key: bytes | None = None,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """VERIFY

        Args:
            key (bytes | None, optional): Key. Defaults to None.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(cla, 0x20, 0x00, 0x80, data=key, extended=False)
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def internal_authenticate(
        self,
        challenge: bytes,
        response_length: int | None = None,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """INTERNAL AUTHENTICATE

        Args:
            challenge (bytes): Challenge
            response_length (int, Optional): Response length. Defaults to None.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if response_length is None:
            response_length = "max"

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(
            cla, 0x88, 0x00, 0x80, data=challenge, le=response_length, extended=False
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def external_authenticate(
        self,
        authenticate_code: bytes | None = None,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """EXTERNAL AUTHENTICATE

        Args:
            authenticate_code (bytes | None, optional): Authenticate Code. Defaults to None.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(
            cla, 0x82, 0x00, 0x80, data=authenticate_code, extended=False
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def get_data(
        self,
        tag: bytes,
        simplified_encoding: bool = False,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """GET DATA

        Args:
            tag (bytes): Tag
            simplified_encoding (bool, optional): Simplified encoding. Defaults to False.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `tag`

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """
        if cla < 0x00:
            raise ValueError("Argument `cla` must be greater than or equal 0x00.")
        if 0xFF < cla:
            raise ValueError("Argument `cla` must be less than or equal 0xFF.")
        if simplified_encoding:
            if len(tag) != 1:
                raise ValueError(
                    "Argument `tag` length must be 1 for simplified encoding."
                )
            if tag[0] < 0x01 or 0xFE < tag[0]:
                raise ValueError(
                    "Argument `tag[0]` out of range. (0x01 <= tag[0] <= 0xFE)"
                )
        else:
            if len(tag) == 1:
                if tag[0] < 0x01 or 0xFE < tag[0]:
                    raise ValueError(
                        "Argument `tag[0]` out of range. (0x01 <= tag[0] <= 0xFE)"
                    )
            elif len(tag) == 2:
                tag_int = tag[0] << 8 | tag[1]
                if tag_int < 0x1F1F or 0xFFFF < tag_int:
                    raise ValueError(
                        "Argument `tag` out of range. (0x1F1F <= tag <= 0xFFFF)"
                    )
            else:
                raise ValueError("Argument `tag` length must be 1 or 2.")

        if simplified_encoding:
            command = CommandApdu(
                cla,
                0xCA,
                0x02,
                tag[0],
                le="max",
                extended=self.allow_extended_apdu,
            )
        else:
            if len(tag) == 1:
                command = CommandApdu(
                    cla,
                    0xCA,
                    0x00,
                    tag[0],
                    le="max",
                    extended=self.allow_extended_apdu,
                )
            else:
                command = CommandApdu(
                    cla,
                    0xCA,
                    tag[0],
                    tag[1],
                    le="max",
                    extended=self.allow_extended_apdu,
                )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def jpki_sign(
        self,
        input: bytes,
        raise_error: bool = True,
    ) -> tuple[CardResponseStatus, bytes]:
        """JPKI Sign (PERFORM SECURITY OPERATION)

        Args:
            input (bytes): Input
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Returns:
            tuple[CardResponseStatus, bytes]: Response Status and Data
        """

        command = CommandApdu(
            0x80, 0x2A, 0x00, 0x80, data=input, le="max", extended=False
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)


def create_card_connection(
    connection: PyscardCardConnection | Type4Tag,
    allow_extended_apdu: bool = False,
) -> CardConnection:
    """Create Card Connection

    Args:
        connection (PyscardCardConnection | Type4Tag): PC/SC connection or NFC Type 4 Tag connection
        allow_extended_apdu (bool, optional): Allow Extended APDU. Defaults to False.

    Returns:
        CardConnection: CardConnection instance
    """

    if isinstance(connection, PyscardCardConnection):

        def transmit(
            command: bytes | bytearray,
        ) -> tuple[CardResponseStatus, bytes]:
            data, sw1, sw2 = connection.transmit(list(command))
            sw = sw1 << 8 | sw2
            response_status = CardResponseStatus(sw)
            return response_status, bytes(data)

        return CardConnection(transmit, allow_extended_apdu=allow_extended_apdu)

    elif isinstance(connection, Type4Tag):

        def transmit(
            command: bytes | bytearray,
        ) -> tuple[CardResponseStatus, bytes]:
            *data, sw1, sw2 = connection.transceive(command)
            sw = sw1 << 8 | sw2
            response_status = CardResponseStatus(sw)
            return response_status, bytes(data)

        return CardConnection(
            transmit,
            allow_extended_apdu=allow_extended_apdu,
            identifier=connection.identifier,
        )
