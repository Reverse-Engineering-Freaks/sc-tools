"""SC Explorer CLI"""

import datetime
import fire
import logging
import os
from typing import Self

from sc_tools.dump_binary import dump_binary
from sc_tools.card_response import CardResponseStatus
from sc_tools.card_connection import create_card_connection
from sc_tools.methods import (
    CardFileAttribute,
    list_cla_ins,
    list_p1_p2,
    list_ef,
    list_do,
    search_df,
)
from sc_tools.readers import (
    list_contact_reader,
    connect_with_contact,
    list_contactless_reader,
    connect_contactless,
)


class ScExplorerCli:
    """Constructor

    Args:
        nfc (bool, optional): Use NFC reader. Defaults to False.
        reader (str | int, optional): Reader descriptor. Reader name or index in list. Defaults to 0.
        allow_extended_apdu (bool, optional): Allow Extended APDU. Defaults to False.
        disable_transceive_log (bool, optional): Disable transceive log (not system log). Defaults to False.
        log_level (str, optional): Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}

    Raises:
        ValueError: Invalid argument `nfc`
        ValueError: Invalid argument `reader`
    """

    @staticmethod
    def __config_logger(level: str) -> None:
        """Config logger

        Args:
            level (str): Log level
        """

        logging.basicConfig(
            level=level,
            format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
        )

    def __init__(
        self,
        nfc=False,
        reader=0,
        allow_extended_apdu=False,
        disable_transceive_log=False,
        log_level="INFO",
    ) -> None:
        """Constructor

        Args:
            nfc (bool, optional): Use NFC reader. Defaults to False.
            reader (str | int, optional): Reader descriptor. Reader name or index in list. Defaults to 0.
            allow_extended_apdu (bool, optional): Allow Extended APDU. Defaults to False.
            disable_transceive_log (bool, optional): Disable transceive log (not system log). Defaults to False.
            log_level (str, optional): Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}

        Raises:
            ValueError: Invalid argument `nfc`
            ValueError: Invalid argument `reader`
            ValueError: Invalid argument `disable_transceive_log`
        """

        ScExplorerCli.__config_logger(log_level)
        self.__logger = logging.getLogger(__name__)

        if not isinstance(nfc, bool):
            raise ValueError("Argument `nfc` must be bool.")
        if (
            reader is not None
            and not isinstance(reader, str)
            and not isinstance(reader, int)
        ):
            raise ValueError("Argument `reader` must be str or int.")
        if not isinstance(allow_extended_apdu, bool):
            raise ValueError("Argument `allow_extended_apdu` must be bool.")
        if not isinstance(disable_transceive_log, bool):
            raise ValueError("Argument `disable_transceive_log` must be bool.")

        if reader is None:
            # List reader
            if nfc:
                readers = list_contactless_reader()
                for i, reader in enumerate(readers):
                    print(f"{i}: {reader[1]}")
                exit(0)
            else:
                readers = list_contact_reader()
                for i, reader in enumerate(readers):
                    print(f"{i}: {reader.name}")
                exit(0)

        if nfc:
            connection = connect_contactless(reader)
            self.__logger.info(
                f"Connected to card `{connection.identifier.hex().upper()}`."
            )
        else:
            connection = connect_with_contact(reader)
            self.__logger.info("Connected to card.")

        self.__connection = create_card_connection(
            connection, allow_extended_apdu=allow_extended_apdu
        )

        # Transceive log
        if not disable_transceive_log:
            transceive_log_filename = (
                "transceive_"
                + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                + ".log"
            )
            self.transceive_log_file = open(transceive_log_filename, "a")

            def transmit_callback(
                command: bytes,
                response_data: bytes,
                response_status: CardResponseStatus,
            ) -> None:
                now = datetime.datetime.now().isoformat()
                self.transceive_log_file.write(f"[{now}]\n")
                self.transceive_log_file.write(f"< {command.hex(' ').upper()}\n")
                self.transceive_log_file.write("> ")
                if len(response_data) != 0:
                    self.transceive_log_file.write(
                        f"{response_data.hex('' '').upper()} "
                    )
                sw_bytes = response_status.sw.to_bytes(length=2, byteorder="big")
                self.transceive_log_file.write(f"{sw_bytes.hex(' ').upper()} \n")
                self.transceive_log_file.write(
                    f"SW: 0x{format(response_status.sw, '04X')} "
                )
                self.transceive_log_file.write(
                    f"({response_status.status_type().name})\n"
                )
                self.transceive_log_file.write("\n")

            self.__connection.transmit_callback = transmit_callback

    def __str__(self) -> str:
        return self.__last_response_to_str()

    def __last_response_to_str(self) -> str:
        """Last response to str

        Returns:
            str: Last response as str
        """

        message = ""
        if self.__connection.last_response_status is None:
            message = "No last response"
        else:
            if len(self.__connection.last_response_data) != 0:
                message += "Data:\n"
                message += dump_binary(self.__connection.last_response_data)
                message += "\n"
            message += "SW: 0x"
            message += format(self.__connection.last_response_status.sw, "04X")
            message += " ("
            message += self.__connection.last_response_status.status_type().name
            message += ")"
        return message

    def print_response(self) -> Self:
        """Print last response

        Returns:
            Self: This instance
        """
        print(self.__last_response_to_str())
        return self

    def dump_response(self, file_path) -> Self:
        """Dump last response data

        Args:
            file_path (str): Destination file path

        Raises:
            ValueError: Invalid arguemnt `file_path`

        Returns:
            Self: This instance
        """

        if not isinstance(file_path, str):
            raise ValueError("Argument `file_path` must be str.")

        with open(file_path, "wb") as file:
            file.write(self.__connection.last_response_data)

        return self

    def command(self, command) -> Self:
        """Send Command APDU

        Args:
            command (bytes): Command APDU as hex string

        Raises:
            ValueError: Invalid arguement `command`

        Returns:
            Self: This instance
        """

        if not isinstance(command, str):
            raise ValueError("Argument `command` must be str.")

        command = command.replace(" ", "")
        command_bytes = bytes.fromhex(command)
        self.__connection.transmit(command_bytes, raise_error=False)

        return self

    def read_binary(self, cla=0x00) -> Self:
        """READ (ALL) BINARY

        Args:
            cla (int, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid arguemnt `cla`

        Returns:
            Self: This instance
        """

        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")

        self.__connection.read_all_binary(cla=cla)

        return self

    def read_record(self, cla=0x00) -> Self:
        """READ RECORD(S)

        Args:
            cla (int, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid arguemnt `cla`

        Returns:
            Self: This instance
        """

        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")

        self.__connection.read_all_record(cla=cla)

        return self

    def select_df(self, df_id, fci=False, cla=0x00) -> Self:
        """SELECT FILE (DF)

        Args:
            df_id (bytes): DF identifier as hex string
            fci (bool, optional): Get File Control Information
            cla (int, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid arguemnt `df_id`
            ValueError: Invalid arguemnt `cla`

        Returns:
            Self: This instance
        """

        if not isinstance(df_id, str):
            raise ValueError("Argument `df_id` must be str.")
        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")
        if not isinstance(fci, bool):
            raise ValueError("Argument `file_control_information` must be int.")

        df_id = df_id.replace(" ", "")
        df_id_bytes = bytes.fromhex(df_id)
        self.__connection.select_df(df_id_bytes, fci, cla=cla)

        return self

    def select_ef(self, ef_id, cla=0x00) -> Self:
        """SELECT FILE (EF)

        Args:
            ef_id (bytes): EF identifier as hex string
            cla (int, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid arguemnt `ef_id`
            ValueError: Invalid arguemnt `cla`

        Returns:
            Self: This instance
        """

        if not isinstance(ef_id, str):
            raise ValueError("Argument `ef_id` must be str.")
        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")

        ef_id = ef_id.replace(" ", "")
        ef_id_bytes = bytes.fromhex(ef_id)
        self.__connection.select_ef(ef_id_bytes, cla=cla)

        return self

    def verify(self, key=None, cla=0x00) -> Self:
        """VERIFY

        Args:
            key (bytes | None, optional): Key. Defaults to None.
            cla (hexadecimal, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid arguemnt `key`
            ValueError: Invalid arguemnt `cla`

        Returns:
            Self: This instance
        """

        if key is not None and not isinstance(key, str):
            raise ValueError("Argument `key` must be str.")
        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")

        key_bytes = None
        if key is not None:
            key_bytes = str(key).encode("ascii")
        self.__connection.verify(key_bytes, cla=cla)

        return self

    def get_data(self, tag: bytes, simplified_encoding=False, cla=0x00) -> Self:
        """GET DATA

        Args:
            tag (bytes): Tag
            simplified_encoding (bool, optional): Simplified encoding. Defaults to False.
            cla (hexadecimal, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid argument `tag`
            ValueError: Invalid argument `cla`

        Returns:
            _Self: This instance
        """

        if not isinstance(tag, str):
            raise ValueError("Argument `tag` must be str.")
        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")

        tag = tag.replace(" ", "")
        tag_bytes = bytes.fromhex(tag)
        self.__connection.get_data(tag_bytes, simplified_encoding, cla=cla)

        return self

    def jpki_sign(self, input) -> Self:
        """JPKI Sign (PERFORM SECURITY OPERATION)

        Args:
            input (bytes): Input as hex string

        Raises:
            ValueError: Invalid arguemnt `input`

        Returns:
            Self: This instance
        """

        if not isinstance(input, str):
            raise ValueError("Argument `input` must be str.")

        input = input.replace(" ", "")
        input_bytes = bytes.fromhex(input)
        self.__connection.jpki_sign(input_bytes)

        return self

    def list_cla_ins(
        self, cla_start=0x00, cla_end=0x100, ins_start=0x00, ins_end=0x100
    ) -> Self:
        """List valid CLA-INS

        Args:
            cla_start (int, optional): CLA start. Defaults to 0x00.
            cla_end (int, optional): CLA end. Defaults to 0x100.
            ins_start (int, optional): INS start. Defaults to 0x00.
            ins_end (int, optional): INS end. Defaults to 0x100.

        Raises:
            ValueError: Invalid arguemnt `cla_start`
            ValueError: Invalid arguemnt `cla_end`
            ValueError: Invalid arguemnt `ins_start`
            ValueError: Invalid arguemnt `ins_end`

        Returns:
            Self: This instance
        """

        if not isinstance(cla_start, int):
            raise ValueError("Argument `cla_start` must be int.")
        if not isinstance(cla_end, int):
            raise ValueError("Argument `cla_end` must be int.")
        if not isinstance(ins_start, int):
            raise ValueError("Argument `ins_start` must be int.")
        if not isinstance(ins_end, int):
            raise ValueError("Argument `ins_end` must be int.")

        list_cla_ins(self.__connection, cla_start, cla_end, ins_start, ins_end)

        return self

    def list_p1_p2(
        self, cla, ins, p1_start=0x00, p1_end=0x100, p2_start=0x00, p2_end=0x100
    ) -> Self:
        """List valid P1-P2

        Args:
            cla (int): CLA
            ins (int): INS
            p1_start (int, optional): P1 start. Defaults to 0x00.
            p1_end (int, optional): P1 end. Defaults to 0x100.
            p2_start (int, optional): P2 start. Defaults to 0x00.
            p2_end (int, optional): P2 end. Defaults to 0x100.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `ins`
            ValueError: Invalid argument `p1_start`
            ValueError: Invalid argument `p1_end`
            ValueError: Invalid argument `p2_start`
            ValueError: Invalid argument `p2_end`

        Returns:
            Self: This instance
        """

        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")
        if not isinstance(ins, int):
            raise ValueError("Argument `ins` must be int.")
        if not isinstance(p1_start, int):
            raise ValueError("Argument `p1_start` must be int.")
        if not isinstance(p1_end, int):
            raise ValueError("Argument `p1_end` must be int.")
        if not isinstance(p2_start, int):
            raise ValueError("Argument `p2_start` must be int.")
        if not isinstance(p2_end, int):
            raise ValueError("Argument `p2_end` must be int.")

        p1_p2_list = list_p1_p2(
            self.__connection, cla, ins, p1_start, p1_end, p2_start, p2_end
        )

        return self

    def list_ef(
        self,
        cla=0x00,
        start=0x0000,
        end=0x10000,
        dump_path=None,
    ) -> Self:
        """List EF

        Args:
            cla (int, optional): CLA. Defaults to 0x00.
            start (int, optional): DF identifier start. Defaults to 0x0000.
            end (int, optional): DF identifier end. Defaults to 0x10000.
            dump_path (str | None, optional): Set directory path to dump response data to file. Defaults to None.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `start`
            ValueError: Invalid argument `end`
            ValueError: Invalid argument `dump_path`

        Returns:
            Self: This instance
        """

        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")
        if not isinstance(start, int):
            raise ValueError("Argument `start` must be int.")
        if not isinstance(end, int):
            raise ValueError("Argument `end` must be int.")
        if dump_path is not None and not isinstance(dump_path, str):
            raise ValueError("Argument `dump_path` must be str.")

        def found_callback(ef_id: bytes, ef_attribute: CardFileAttribute) -> None:
            if dump_path is None:
                return

            # Dump to file
            file_name = ""
            if self.__connection.selected_df is None:
                file_name += "DEFAULT_DF"
            else:
                file_name += self.__connection.selected_df.hex().upper()
            file_name += "_EF_"
            file_name += ef_id.hex().upper()

            data = None
            if CardFileAttribute.WEF_TRANSPARENT in ef_attribute:
                file_name += "_TRANSPARENT"
                self.__connection.select_ef(ef_id, cla=cla)
                status, data = self.__connection.read_all_binary(cla=cla)
            if CardFileAttribute.WEF_RECORD in ef_attribute:
                self.__connection.select_ef(ef_id, cla=cla)
                status, data = self.__connection.read_record(cla=cla)
                file_name += "_RECORD"
            if data is None:
                return

            file_name += ".bin"

            file_path = os.path.join(dump_path, file_name)
            with open(file_path, "wb") as file:
                file.write(data)

        ef_list = list_ef(
            self.__connection,
            cla=cla,
            start=start,
            end=end,
            found_callback=found_callback,
        )

        return self

    def list_do(
        self,
        cla=0x00,
        dump_path=None,
    ) -> Self:
        """List Data Object

        Args:
            cla (hexadecimal, optional): _description_. Defaults to 0x00.
            dump_path (str | None, optional): Set path to dump response data to file. Defaults to None.

        Raises:
            ValueError: Invalid argument `cla`
            ValueError: Invalid argument `dump_path`

        Returns:
            Self: This instance
        """

        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")
        if dump_path is not None and not isinstance(dump_path, str):
            raise ValueError("Argument `dump_path` must be str.")

        def found_callback(tag: bytes, simplified_encoding: bool, data: bytes) -> None:
            if dump_path is None:
                return

            # Dump to file
            file_name = ""
            if self.__connection.selected_df is None:
                file_name += "DEFAULT_DF"
            else:
                file_name += self.__connection.selected_df.hex().upper()
            if simplified_encoding:
                file_name += "_SIMPLIFIED_DO_"
            else:
                file_name += "_DO_"
            file_name += f"{tag.hex().upper()}.bin"
            file_path = os.path.join(dump_path, file_name)
            with open(file_path, "wb") as file:
                file.write(data)

        do_list = list_do(self.__connection, cla=cla, found_callback=found_callback)

        return self

    def search_df(
        self,
        cla=0x00,
    ) -> Self:
        """Search DF

        Args:
            cla (hexadecimal, optional): CLA. Defaults to 0x00.

        Raises:
            ValueError: Invalid argument `cla`

        Returns:
            Self: This instance
        """

        if not isinstance(cla, int):
            raise ValueError("Argument `cla` must be int.")

        df_list = search_df(self.__connection, cla=cla)

        return self


def main():
    fire.Fire(ScExplorerCli)


if __name__ == "__main__":
    main()
