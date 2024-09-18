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
        transmit: Callable[[bytes], tuple[bytes, CardResponseStatus]],
        auto_get_response: bool = True,
        allow_extended_apdu=False,
        identifier: bytes | None = None,
        transmit_callback: (
            Callable[[bytes, bytes, CardResponseStatus], None] | None
        ) = None,
    ) -> None:
        """Constructor

        Args:
            transmit (Callable[[bytes], tuple[bytes, CardResponseStatus]]): Transmit function
            auto_get_response (bool, optional): Enable automatic getting remaining response data. Defaults to True.
            allow_extended_apdu (bool, optional): Allow Extended APDU. Defaults to False.
            identifier (bytes | None, optional): Identifier for NFC. Defaults to None.
            transmit_callback (Callable[[bytes, bytes, CardResponseStatus], None] | None, Optional): Transmit callback. Defaults to None.
        """

        self.__logger = logging.getLogger(__name__)

        self.__transmit = transmit
        self.auto_get_response = auto_get_response
        self.allow_extended_apdu = allow_extended_apdu
        self.identifier = identifier
        self.transmit_callback = transmit_callback

        self.last_response_status: CardResponseStatus | None = None
        self.last_response_data: bytes = b""
        self.selected_df: bytes | None = None
        self.selected_ef: bytes | None = None

    def transmit(
        self, command: bytes, raise_error: bool = True
    ) -> tuple[bytes, CardResponseStatus]:
        """Transmit

        Args:
            command (bytes): Command
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            CardResponseError: Card returned error response

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """

        command_hex = command.hex(" ").upper()
        self.__logger.debug(f"< {command_hex}")

        self.last_response_data, self.last_response_status = self.__transmit(command)

        response_data = self.last_response_data + self.last_response_status.sw.to_bytes(
            length=2, byteorder="big"
        )
        response_data_hex = response_data.hex(" ").upper()
        sw_hex = format(self.last_response_status.sw, "04X")
        status_type = self.last_response_status.status_type()
        self.__logger.debug(f"> {response_data_hex}")
        self.__logger.debug(f"SW: 0x{sw_hex} ({status_type.name})")

        if self.transmit_callback is not None:
            self.transmit_callback(
                command, self.last_response_data, self.last_response_status
            )

        if (
            raise_error
            and status_type != CardResponseStatusType.NORMAL_END
            and status_type
            != CardResponseStatusType.NORMAL_END_WITH_REMAINING_DATA_LENGTH
        ):
            raise CardResponseError(self.last_response_status)

        if self.auto_get_response and self.last_response_status.data_remaining() != 0:
            self.last_response_data, self.last_response_status = self.get_response(
                recursive=False, cla=command[0], raise_error=raise_error
            )
            return self.last_response_data, self.last_response_status

        return self.last_response_data, self.last_response_status

    def read_binary(
        self,
        cla: int = 0x00,
        offset: int = 0,
        limit: int | None = None,
        raise_error: bool = True,
    ) -> tuple[bytes, CardResponseStatus]:
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
            tuple[bytes, CardResponseStatus]: Response Data and Status
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
    ) -> tuple[bytes, CardResponseStatus]:
        """READ (ALL) BINARY

        Args:
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            CardResponseError: Card returned error response

        Returns:
            tuple[bytes, CardResponseStatus]: Last Response Status and entire Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        max_bulk_read_length = max_lc_le(self.allow_extended_apdu)
        data, status = self.read_binary(cla=cla, offset=0x0000, raise_error=raise_error)
        chunk_data = data
        while len(chunk_data) == max_bulk_read_length:
            offset = len(data)
            chunk_data, status = self.read_binary(
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
        return data, status

    def read_record(
        self,
        record_number: int = 0x01,
        cla: int = 0x00,
        limit: int | None = None,
        raise_error: bool = True,
    ) -> tuple[bytes, CardResponseStatus]:
        """READ RECORD(S)

        Args:
            record_number (int, Optional): Record number. Defaults to 0x01.
            cla (int, optional): CLA. Defaults to 0x00.
            limit (int | None, optional): Limit. Defaults to None.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """

        if limit is None:
            limit = "max"

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(
            cla,
            0xB2,
            record_number,
            0x04,
            le=limit,
            extended=self.allow_extended_apdu,
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def read_all_record(
        self,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[bytes, CardResponseStatus]:
        """READ (ALL) RECORD

        Args:
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            CardResponseError: Card returned error response

        Returns:
            tuple[bytes, CardResponseStatus]: Last Response Status and entire Data
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        data = b""
        for record_number in range(0x01, 0x100):
            chunk_data, status = self.read_record(
                record_number, cla=cla, raise_error=False
            )
            status_type = status.status_type()
            if status_type == CardResponseStatusType.NO_RECORD_TO_BE_ACCESSED:
                # Reached to End of Data
                break
            if raise_error and status_type != CardResponseStatusType.NORMAL_END:
                raise CardResponseError(status)
            data += chunk_data
        return data, status

    def select_df(
        self,
        df_id: bytes,
        fci: FciLiteral = False,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[bytes, CardResponseStatus]:
        """SELECT FILE (DF)

        Args:
            df_id (bytes): DF Ientifier
            fci (FciLiteral, optional): Get File Control Information. Defaults to False.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        self.selected_df = df_id
        self.selected_ef = None

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
    ) -> tuple[bytes, CardResponseStatus]:
        """SELECT FILE (EF)

        Args:
            ef_id (bytes): EF Identifier
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `ef_id`

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")
        if len(ef_id) != 2:
            raise ValueError("Argument `ef_id` length must be 2.")

        self.selected_ef = ef_id

        command = CommandApdu(cla, 0xA4, 0x02, 0x0C, data=ef_id, extended=False)
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def verify(
        self,
        key: bytes | None = None,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[bytes, CardResponseStatus]:
        """VERIFY

        Args:
            key (bytes | None, optional): Key. Defaults to None.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
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
    ) -> tuple[bytes, CardResponseStatus]:
        """INTERNAL AUTHENTICATE

        Args:
            challenge (bytes): Challenge
            response_length (int | None, Optional): Response length. Defaults to None.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
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
    ) -> tuple[bytes, CardResponseStatus]:
        """EXTERNAL AUTHENTICATE

        Args:
            authenticate_code (bytes | None, optional): Authenticate Code. Defaults to None.
            cla (int, optional): CLA. Defaults to 0x00.
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(
            cla, 0x82, 0x00, 0x80, data=authenticate_code, extended=False
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)

    def get_response(
        self,
        limit: int | None = None,
        recursive: bool = True,
        cla: int = 0x00,
        raise_error: bool = True,
    ):
        if limit is None:
            limit = self.last_response_status.data_remaining()

        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

        command = CommandApdu(
            cla,
            0xC0,
            0x00,
            0x00,
            le=limit,
            extended=self.allow_extended_apdu,
        )
        data, status = self.transmit(command.to_bytes())
        while recursive and self.last_response_status.data_remaining() != 0:
            command.le = self.last_response_status.data_remaining()
            chunk_data, status = self.transmit(command.to_bytes(), raise_error=False)
            status_type = status.status_type()
            if raise_error and status_type != CardResponseStatusType.NORMAL_END:
                raise CardResponseError(status)
            data += chunk_data
        return data, status

    def get_data(
        self,
        tag: bytes,
        simplified_encoding: bool = False,
        cla: int = 0x00,
        raise_error: bool = True,
    ) -> tuple[bytes, CardResponseStatus]:
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
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """
        if cla < 0x00 or 0xFF < cla:
            raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")
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
    ) -> tuple[bytes, CardResponseStatus]:
        """JPKI Sign (PERFORM SECURITY OPERATION)

        Args:
            input (bytes): Input
            raise_error (bool, optional): Raise error when card error response returned. Defaults to True.

        Returns:
            tuple[bytes, CardResponseStatus]: Response Data and Status
        """

        command = CommandApdu(
            0x80, 0x2A, 0x00, 0x80, data=input, le="max", extended=False
        )
        return self.transmit(command.to_bytes(), raise_error=raise_error)


def create_card_connection(
    connection: PyscardCardConnection | Type4Tag,
    auto_get_response: bool = True,
    allow_extended_apdu: bool = False,
) -> CardConnection:
    """Create Card Connection

    Args:
        connection (PyscardCardConnection | Type4Tag): PC/SC connection or NFC Type 4 Tag connection
        auto_get_response (bool, optional): Enable automatic getting remaining response data. Defaults to True.
        allow_extended_apdu (bool, optional): Allow Extended APDU. Defaults to False.

    Returns:
        CardConnection: CardConnection instance
    """

    if isinstance(connection, PyscardCardConnection):

        def transmit(
            command: bytes | bytearray,
        ) -> tuple[bytes, CardResponseStatus]:
            data, sw1, sw2 = connection.transmit(list(command))
            sw = sw1 << 8 | sw2
            response_status = CardResponseStatus(sw)
            return bytes(data), response_status

        return CardConnection(
            transmit,
            auto_get_response=auto_get_response,
            allow_extended_apdu=allow_extended_apdu,
        )

    elif isinstance(connection, Type4Tag):

        def transmit(
            command: bytes | bytearray,
        ) -> tuple[bytes, CardResponseStatus]:
            *data, sw1, sw2 = connection.transceive(command)
            sw = sw1 << 8 | sw2
            response_status = CardResponseStatus(sw)
            return bytes(data), response_status

        return CardConnection(
            transmit,
            allow_extended_apdu=allow_extended_apdu,
            auto_get_response=auto_get_response,
            identifier=connection.identifier,
        )
