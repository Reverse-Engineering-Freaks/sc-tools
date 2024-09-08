"""Smart Card Readers"""

import nfc
from nfc.clf.transport import USB as NFCUsb
from nfc.tag.tt4 import Type4Tag
from smartcard.System import readers as pyscard_readers
from smartcard.reader.Reader import Reader as SCReader


def list_contact_reader() -> list[SCReader]:
    """List contact reader

    Returns:
        list[SCReader]: List of contact reader
    """

    return pyscard_readers()


def connect_with_contact(reader: int | str) -> SCReader:
    """Connect with contact

    Args:
        reader (int | str): Reader descriptor

    Raises:
        RuntimeError: No reader
        ValueError: Specified reader not found
        ValueError: Argument `reader` out of index

    Returns:
        SCReader: PC/SC connection instance
    """

    sc_readers: list[SCReader] = list_contact_reader()
    if len(sc_readers) == 0:
        raise RuntimeError("No reader.")

    if isinstance(reader, str):
        # By name
        reader_index = next(
            (i for i, entry in enumerate(sc_readers) if entry.name == reader),
            None,
        )
        if reader_index is None:
            raise ValueError(f"Reader `{reader}` not found.")
        connection = sc_readers[reader_index].createConnection()
    elif isinstance(reader, int):
        # By index
        if reader < 0 or len(sc_readers) <= reader:
            raise ValueError("Argument `reader` out of index.")
        connection = sc_readers[reader].createConnection()
    connection.connect()
    return connection


def list_contactless_reader() -> list[tuple[str, str]]:
    """List contactless reader

    Returns:
        list[tuple[str, str]]: List of device ID and name
    """

    nfc_readers: list[tuple[str, str]] = []
    for vid, pid, bus, dev in NFCUsb.find("usb"):
        if (vid, pid) in nfc.clf.device.usb_device_map:
            path = "usb:{0:03d}:{1:03d}".format(bus, dev)
            try:
                clf = nfc.ContactlessFrontend(path)
                reader_name = f"{clf.device.vendor_name} {clf.device.product_name} {clf.device.chipset_name}"
                nfc_readers.append((path, reader_name))
                clf.close()
            except IOError:
                # Cannot access to device
                continue
    return nfc_readers


def connect_contactless(reader: int | str) -> Type4Tag:
    """Connect contactless

    Args:
        reader (int | str): Reader descriptor

    Raises:
        RuntimeError: No reader
        ValueError: Specified reader not found
        ValueError: Argument `reader` out of index

    Returns:
        Type4Tag: NFC Type 4 Tag connection
    """

    nfc_readers = list_contactless_reader()
    if len(nfc_readers) == 0:
        raise RuntimeError("No reader.")

    if isinstance(reader, str):
        # By name
        reader_index = next(
            (i for i, entry in enumerate(nfc_readers) if entry[1] == reader),
            None,
        )
        if reader_index is None:
            raise ValueError(f"Reader `{reader}` not found.")
        clf = nfc.ContactlessFrontend(nfc_readers[reader_index][0])
    elif isinstance(reader, int):
        # By index
        if reader < 0 or len(nfc_readers) <= reader:
            raise ValueError("Argument `reader` out of index.")
        clf = nfc.ContactlessFrontend(nfc_readers[reader][0])
    return clf.connect(rdwr={"on-connect": lambda tag: False})
