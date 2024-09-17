"""Usable methods for Smart Cards"""

from ber_tlv.tlv import Tlv
import csv
from enum import Flag
from importlib.resources import files
from iso3166 import Country, countries
from tqdm import tqdm
from typing import Callable

from .apdu import CommandApdu
from .card_response import CardResponseStatusType, CardResponseStatus, CardResponseError
from .card_connection import CardConnection


class CardFileAttribute(Flag):
    UNKNOWN = 0x00000000
    WEF_TRANSPARENT = 0x00000001
    WEF_RECORD = 0x00000002
    IEF_VERIFY_KEY = 0x00000010
    IEF_INTERNAL_AUTHENTICATE_KEY = 0x00000020
    IEF_EXTERNAL_AUTHENTICATE_KEY = 0x00000040
    LOCKED = 0x00000100
    VERIFICATION_REQUIRED = 0x00000200
    VERIFICATION_UNLIMITED = 0x00000400
    JPKI_SIGN_PRIVATE_KEY = 0x00001000


def list_cla_ins(
    connection: CardConnection,
    cla_start: int = 0x00,
    cla_end: int = 0x100,
    ins_start: int = 0x00,
    ins_end: int = 0x100,
) -> list[tuple[int, int, CardResponseStatusType]]:
    """List valid CLA-INS

    Args:
        connection (CardConnection): Card Connection
        cla_start (int, optional): CLA start. Defaults to 0x00.
        cla_end (int, optional): CLA end. Defaults to 0x100.
        ins_start (int, optional): INS start. Defaults to 0x00.
        ins_end (int, optional): INS end. Defaults to 0x100.

    Raises:
        ValueError: Invalid argument `cla_start`
        ValueError: Invalid argument `cla_end`
        ValueError: Invalid argument `ins_start`
        ValueError: Invalid argument `ins_end`

    Returns:
        list[tuple[int, int, CardResponseStatusType]]: List of valid CLA-INS and Response Status
    """

    if cla_start < 0x00 or 0x100 < cla_start:
        raise ValueError(
            "Argument `cla_start` out of range. (0x00 <= cla_start <= 0x100)"
        )
    if cla_end < 0x00 or 0x100 < cla_end:
        raise ValueError("Argument `cla_end` out of range. (0x00 <= cla_end <= 0x100)")
    if ins_start < 0x00 or 0x100 < ins_start:
        raise ValueError(
            "Argument `ins_start` out of range. (0x00 <= ins_start <= 0x100)"
        )
    if ins_end < 0x00 or 0x100 < ins_end:
        raise ValueError("Argument `ins_end` out of range. (0x00 <= ins_end <= 0x100)")

    cla_ins_list: list[tuple[int, int, CardResponseStatusType]] = []
    for cla in tqdm(range(cla_start, cla_end), desc="List valid CLA-INS"):
        for ins in range(ins_start, ins_end):
            command = CommandApdu(
                cla, ins, 0x00, 0x00, extended=connection.allow_extended_apdu
            )
            data, status = connection.transmit(command.to_bytes(), raise_error=False)
            if not status.is_cla_valid():
                break
            if not status.is_cla_ins_valid():
                continue
            cla_hex = format(cla, "02X")
            ins_hex = format(ins, "02X")
            sw_hex = format(status.sw, "04X")
            status_type = status.status_type()
            tqdm.write(
                f"CLA {cla_hex}, INS {ins_hex} found with status {sw_hex} ({status_type})."
            )
            cla_ins_list.append((cla, ins, status))
    return cla_ins_list


def list_p1_p2(
    connection: CardConnection,
    cla: int,
    ins: int,
    p1_start: int = 0x00,
    p1_end: int = 0x100,
    p2_start: int = 0x00,
    p2_end: int = 0x100,
) -> list[tuple[int, int, CardResponseStatusType]]:
    """List valid P1-P2

    Args:
        connection (CardConnection): Card Connection
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
        list[tuple[int, int, CardResponseStatusType]]: List of valid P1-P2 and Response Status
    """

    if cla < 0x00 or 0xFF < cla:
        raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")
    if ins < 0x00 or 0xFF < ins:
        raise ValueError("Argument `ins` out of range. (0x00 <= ins <= 0xFF)")
    if p1_start < 0x00 or 0x100 < p1_start:
        raise ValueError(
            "Argument `p1_start` out of range. (0x00 <= p1_start <= 0x100)"
        )
    if p1_end < 0x00 or 0x100 < p1_end:
        raise ValueError("Argument `p1_end` out of range. (0x00 <= p1_end <= 0x100)")
    if p2_start < 0x00 or 0x100 < p2_start:
        raise ValueError(
            "Argument `p2_start` out of range. (0x00 <= p2_start <= 0x100)"
        )
    if p2_end < 0x00 or 0x100 < p2_end:
        raise ValueError("Argument `p2_end` out of range. (0x00 <= p2_end <= 0x100)")

    p1_p2_list: list[tuple[bytes, CardResponseStatusType]] = []
    for p1 in tqdm(range(p1_start, p1_end), desc="List valid P1-P2"):
        for p2 in range(p2_start, p2_end):
            # No Le
            command = CommandApdu(
                cla, ins, p1, p2, extended=connection.allow_extended_apdu
            )
            data, status = connection.transmit(command.to_bytes(), raise_error=False)
            if not status.is_cla_ins_valid():
                raise RuntimeError("Invalid CLA-INS.")
            status_type = status.status_type()
            if status.is_p1_p2_valid():
                p1_hex = format(p1, "02X")
                p2_hex = format(p2, "02X")
                sw_hex = format(status.sw, "04X")
                tqdm.write(
                    f"P1 {p1_hex}, P2 {p2_hex}, No Le found with status {sw_hex} ({status_type})."
                )
                p1_p2_list.append((p1, p2, status))
                continue
            # Le=MAX
            command.le = "max"
            data, status = connection.transmit(command.to_bytes(), raise_error=False)
            status_type = status.status_type()
            if status.is_p1_p2_valid():
                p1_hex = format(p1, "02X")
                p2_hex = format(p2, "02X")
                sw_hex = format(status.sw, "04X")
                tqdm.write(
                    f"P1 {p1_hex}, P2 {p2_hex}, Le=MAX found with status {sw_hex} ({status_type})."
                )
                p1_p2_list.append((p1, p2, status))
                continue
    return p1_p2_list


def attribute_ef(
    connection: CardConnection,
    cla: int = 0x00,
) -> CardFileAttribute:
    """Attribute EF

    Args:
        connection (CardConnection): Card Connection
        cla (int, optional): CLA. Defaults to 0x00.

    Raises:
        ValueError: Invalid argument `cla`

    Returns:
        CardFileAttribute: EF Attribute
    """

    if cla < 0x00 or 0xFF < cla:
        raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

    ef_attribute = CardFileAttribute.UNKNOWN

    # IEF/VERIFY_KEY
    data, status = connection.verify(None, cla=cla, raise_error=False)
    status_type = status.status_type()
    if status_type == CardResponseStatusType.VERIFICATION_UNMATCHING:
        ef_attribute = CardFileAttribute.IEF_VERIFY_KEY
        if status.verification_remaining() is None:
            ef_attribute |= CardFileAttribute.VERIFICATION_UNLIMITED
        if status.verification_remaining() == 0:
            ef_attribute |= CardFileAttribute.LOCKED
        return ef_attribute
    if status_type == CardResponseStatusType.REFERENCED_IEF_LOCKED:
        return CardFileAttribute.IEF_VERIFY_KEY | CardFileAttribute.LOCKED

    # IEF/INTERNAL_AUTHENTICATE_KEY
    data, status = connection.internal_authenticate(
        b"\x00\x00\x00\x00\x00\x00\x00\x00", cla=cla, raise_error=False
    )
    status_type = status.status_type()
    if status_type == CardResponseStatusType.NORMAL_END:
        ef_attribute |= CardFileAttribute.IEF_INTERNAL_AUTHENTICATE_KEY

    # IEF/EXTERNAL_AUTHENTICATE_KEY
    data, status = connection.external_authenticate(None, cla=cla, raise_error=False)
    status_type = status.status_type()
    if status_type == CardResponseStatusType.VERIFICATION_UNMATCHING:
        ef_attribute |= CardFileAttribute.IEF_EXTERNAL_AUTHENTICATE_KEY
        if status.verification_remaining() is None:
            ef_attribute |= CardFileAttribute.VERIFICATION_UNLIMITED
        if status.verification_remaining() == 0:
            ef_attribute |= CardFileAttribute.LOCKED
    if status_type == CardResponseStatusType.REFERENCED_IEF_LOCKED:
        ef_attribute |= (
            CardFileAttribute.IEF_EXTERNAL_AUTHENTICATE_KEY | CardFileAttribute.LOCKED
        )

    # IEF/JPKI_SIGN_PRIVATE_KEY
    data, status = connection.jpki_sign(
        b"\x30\x31\x30\x0D\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        raise_error=False,
    )
    status_type = status.status_type()
    if status_type == CardResponseStatusType.NORMAL_END:
        ef_attribute |= CardFileAttribute.JPKI_SIGN_PRIVATE_KEY
    if status_type == CardResponseStatusType.SECURITY_STATUS_NOT_FULFILLED:
        ef_attribute |= (
            CardFileAttribute.JPKI_SIGN_PRIVATE_KEY
            | CardFileAttribute.VERIFICATION_REQUIRED
        )
    if status_type == CardResponseStatusType.REFERENCED_IEF_LOCKED:
        ef_attribute |= (
            CardFileAttribute.JPKI_SIGN_PRIVATE_KEY | CardFileAttribute.LOCKED
        )

    # IEF/EXTERNAL_AUTHENTICATE_KEY or IEF/JPKI_SIGN_PRIVATE_KEY
    if ef_attribute != CardFileAttribute.UNKNOWN:
        return ef_attribute

    # WEF/BINARY
    data, status = connection.read_binary(cla=cla, raise_error=False)
    status_type = status.status_type()
    if status_type == CardResponseStatusType.NORMAL_END:
        return CardFileAttribute.WEF_TRANSPARENT
    if status_type == CardResponseStatusType.SECURITY_STATUS_NOT_FULFILLED:
        return CardFileAttribute.VERIFICATION_REQUIRED

    # WEF/RECORD
    data, status = connection.read_record(cla=cla, raise_error=False)
    status_type = status.status_type()
    if status_type == CardResponseStatusType.NORMAL_END:
        return CardFileAttribute.WEF_RECORD
    if status_type == CardResponseStatusType.SECURITY_STATUS_NOT_FULFILLED:
        return CardFileAttribute.VERIFICATION_REQUIRED

    return CardFileAttribute.UNKNOWN


def list_ef(
    connection: CardConnection,
    cla: int = 0x00,
    start: int = 0x0000,
    end: int = 0x10000,
    found_callback: Callable[[bytes, CardFileAttribute], None] | None = None,
) -> list[tuple[bytes, CardFileAttribute]]:
    """List EF

    Args:
        connection (CardConnection): Card Connection
        cla (int, optional): CLA. Defaults to 0x00.
        start (int, optional): Start EF identifier. Defaults to 0x0000.
        end (int, optional): End EF identifier. Defaults to 0x10000.
        found_callback (Callable[[bytes, CardFileAttribute], None], optional): Found callback. Defaults to None.

    Raises:
        ValueError: Invalid argument `cla`
        ValueError: Invalid argument `start`
        ValueError: Invalid argument `end`
        CardResponseError: Card returned error response

    Returns:
        list[tuple[bytes, CardFileAttribute]]: List of EF identifier and Response Status
    """

    if cla < 0x00 or 0xFF < cla:
        raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")
    if start < 0x00:
        raise ValueError("Argument `start` must be greater than or equal 0x0000.")
    if 0x10000 < start:
        raise ValueError("Argument `start` must be less than or equal 0x10000.")
    if end < 0x0000:
        raise ValueError("Argument `end` must be greater than or equal 0x0000.")
    if 0x10000 < end:
        raise ValueError("Argument `end` must be less than or equal 0x10000.")

    ef_list: list[tuple[bytes, CardFileAttribute]] = []
    for ef_id in tqdm(range(start, end), desc="List EF"):
        if ef_id == 0x3FFF or ef_id == 0xFFFF:
            # RFU
            continue
        ef_id_bytes = ef_id.to_bytes(length=2, byteorder="big")
        data, status = connection.select_ef(ef_id_bytes, cla=cla, raise_error=False)
        if not status.is_cla_ins_valid():
            raise RuntimeError("Cannot list EF in current DF.")
        status_type = status.status_type()
        if (
            status_type == CardResponseStatusType.NORMAL_END
            or status_type == CardResponseStatusType.FILE_CONTROL_INFORMATION_FAILURE
        ):
            ef_attribute = attribute_ef(connection, cla=cla)
            tqdm.write(f"EF {ef_id_bytes.hex().upper()} ({ef_attribute.name}) found.")
            ef_list.append((ef_id_bytes, ef_attribute))
            if found_callback is not None:
                found_callback(ef_id_bytes, ef_attribute)
            continue
        if status_type == CardResponseStatusType.NO_FILE_TO_BE_ACCESSED:
            continue
        raise CardResponseError(status)
    return ef_list


def list_do(
    connection: CardConnection,
    cla: int = 0x00,
    found_callback: Callable[[bytes, bool, bytes], None] | None = None,
) -> list[tuple[bytes, bool]]:
    """List Data Object

    Args:
        connection (CardConnection): Card Connection
        cla (int, optional): CLA. Defaults to 0x00.
        found_callback (Callable[[bytes, bool, bytes], None], optional): Found callback. Defaults to None.

    Raises:
        ValueError: Invalid argument `cla`

    Returns:
        list[tuple[bytes, bool]]: List of tag and simplified encoding
    """

    if cla < 0x00 or 0xFF < cla:
        raise ValueError("Argument `cla` out of range. (0x00 <= cla <= 0xFF)")

    do_list: list[tuple[bytes, bool]] = []

    # 1 byte tag
    for tag in tqdm(range(0x01, 0xFF), desc="List Data Object (1 byte tag)"):
        tag_bytes = tag.to_bytes(length=1)
        data, status = connection.get_data(tag_bytes, cla=cla, raise_error=False)
        if not status.is_cla_ins_valid():
            raise RuntimeError("Cannot list DO in current DF.")
        status_type = status.status_type()
        if (
            status_type == CardResponseStatusType.NORMAL_END
            or status_type == CardResponseStatusType.INCORRECT_LC_LE_FIELD
        ):
            tqdm.write(f"Data Object {tag_bytes.hex().upper()} (1 byte tag) found.")
            do_list.append((tag_bytes, False))
            if found_callback is not None:
                found_callback(tag_bytes, False, data)

    # Simplified encoding
    for tag in tqdm(range(0x01, 0xFF), desc="List Data Object (Simplified encoding)"):
        tag_bytes = tag.to_bytes(length=1)
        data, status = connection.get_data(
            tag_bytes, simplified_encoding=True, cla=cla, raise_error=False
        )
        if not status.is_cla_ins_valid():
            raise RuntimeError("Cannot list DO in current DF.")
        status_type = status.status_type()
        if (
            status_type == CardResponseStatusType.NORMAL_END
            or status_type == CardResponseStatusType.INCORRECT_LC_LE_FIELD
        ):
            tqdm.write(
                f"Data Object {tag_bytes.hex().upper()} (Simplified encoding) found."
            )
            do_list.append((tag_bytes, True))
            if found_callback is not None:
                found_callback(tag_bytes, True, data)

    # 2 byte tag
    for tag in tqdm(range(0x1F1F, 0x10000), desc="List Data Object (2 byte tag)"):
        tag_bytes = tag.to_bytes(length=2, byteorder="big")
        data, status = connection.get_data(tag_bytes, cla=cla, raise_error=False)
        if not status.is_cla_ins_valid():
            raise RuntimeError("Cannot list DO in current DF.")
        status_type = status.status_type()
        if (
            status_type == CardResponseStatusType.NORMAL_END
            or status_type == CardResponseStatusType.INCORRECT_LC_LE_FIELD
        ):
            tqdm.write(f"Data Object {tag_bytes.hex().upper()} (2 byte tag) found.")
            do_list.append((tag_bytes, False))
            if found_callback is not None:
                found_callback(tag_bytes, False, data)

    return do_list


def search_df(
    connection: CardConnection,
    cla: int = 0x00,
    found_callback: Callable[[bytes], None] | None = None,
) -> list[bytes]:
    """Search DF

    Args:
        connection (CardConnection): Card Connection
        cla (int, optional): CLA. Defaults to 0x00.
        found_callback (Callable[[bytes], None] | None, optional): Found callback. Defaults to None.

    Returns:
        list[bytes]: List of DF identifier
    """

    def df_id_by_fci(fci: bytes) -> bytes:
        fci_tlv = Tlv.parse(fci)
        fci_tag = next(
            (tag_value for tag_value in fci_tlv if tag_value[0] == 111), None
        )
        if fci_tag is None:
            # No FCI tag
            return
        # print(fci_tag)
        if not isinstance(fci_tag[1], list):
            # No valid FCI payload
            return
        df_id_tag = next(
            (tag_value for tag_value in fci_tag[1] if tag_value[0] == 132), None
        )
        if df_id_tag is None:
            # No DF ID tag
            return
        return df_id_tag[1]

    def search_df_by_partial_id(
        partial_df_id: bytes,
        found_callback: Callable[[bytes], None] | None = None,
    ):
        data, status = connection.select_df(partial_df_id, cla=cla, raise_error=False)
        if not status.is_cla_ins_valid():
            raise RuntimeError("Cannot search DF on this card.")
        status_type = status.status_type()
        if status_type != CardResponseStatusType.NORMAL_END:
            # No RID
            return
        data, status = connection.select_df(
            partial_df_id, fci="first", cla=cla, raise_error=False
        )
        status_type = status.status_type()
        if status_type != CardResponseStatusType.NORMAL_END:
            # Cannot get FCI
            return
        df_id = df_id_by_fci(data)
        if df_id is None:
            return
        found_callback(df_id)
        while True:
            data, status = connection.select_df(
                partial_df_id, fci="next", cla=cla, raise_error=False
            )
            status_type = status.status_type()
            if status_type != CardResponseStatusType.NORMAL_END:
                # Cannot get FCI
                break
            df_id = df_id_by_fci(data)
            if df_id is None:
                break
            found_callback(df_id)

    with files("sc_tools").joinpath(
        "well_known_rids.csv"
    ).open() as well_known_rids_file:
        well_known_rids = list(csv.DictReader(well_known_rids_file))

    df_list: list[bytes] = []

    def local_found_callback(df_id: bytes) -> None:
        found_df = next(
            (local_df_id for local_df_id in df_list if local_df_id == df_id), None
        )
        if found_df is None:
            df_list.append(df_id)
            if found_callback is not None:
                found_callback(df_id)

        well_known_rid_local = next(
            (rid for rid in well_known_rids if bytes.fromhex(rid["RID"]) == df_id[0:5]),
            None,
        )
        if well_known_rid_local is not None:
            message = "DF `"
            message += df_id.hex(" ").upper()
            message += "` ("
            if len(well_known_rid_local["Provider"]) == 0:
                message += "N/A"
            else:
                message += well_known_rid_local["Provider"]
            message += "; "
            if len(well_known_rid_local["Country"]) == 0:
                message += "N/A"
            else:
                message += "Registered in "
                message += well_known_rid_local["Country"]
            message += ") found."
            tqdm.write(message)
            return

        country: Country | None = None
        if df_id[0] & 0xF0 == 0xD0:
            country_code = int(df_id.hex()[1:4])
            country = countries.get(country_code)

        if country is None:
            tqdm.write(f"DF `{df_id.hex(' ').upper()}` found.")
        else:
            tqdm.write(
                f"DF `{df_id.hex(' ').upper()}` (Registered in {country.name}) found."
            )

    # Brute-force
    for partial_df_id in tqdm(range(0x00, 0x100), desc="Search DF by Brute-force"):
        search_df_by_partial_id(
            bytes([partial_df_id]), found_callback=local_found_callback
        )

    # Well-known RIDs
    for well_known_rid in tqdm(
        list(well_known_rids), desc="Search DF by Well-known RIDs"
    ):
        rid_bytes = bytes.fromhex(well_known_rid["RID"])
        search_df_by_partial_id(rid_bytes, found_callback=local_found_callback)

    return df_list
