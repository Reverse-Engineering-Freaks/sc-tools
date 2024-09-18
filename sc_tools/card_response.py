"""Card Response"""

from enum import Enum, unique
from typing import Self


@unique
class CardResponseStatusType(Enum):
    """Card Response Type (SW1, SW2)"""

    UNDEFINED = 0x0000
    NORMAL_END_WITH_REMAINING_DATA_LENGTH = 0x61FF
    WARNING_NVRAM_STATUS_NOT_CHANGED = 0x62FF
    OUTPUT_DATA_FAILURE = 0x6281
    DF_LOCKED = 0x6283
    WARNING_NVRAM_STATUS_CHANGED = 0x63FF
    VERIFICATION_UNMATCHING = 0x6300
    FILE_FULL_DUE_TO_LAST_WRITING = 0x6381
    ERROR_NVRAM_STATUS_NOT_CHANGED = 0x64FF
    FILE_CONTROL_INFORMATION_FAILURE = 0x6400
    ERROR_NVRAM_STATUS_CHANGED = 0x65FF
    WRITING_TO_THE_MEMORY_FAILED = 0x6581
    SECURITY_RELATED_ISSUE = 0x66FF
    INCORRECT_LC_LE_FIELD = 0x6700
    CLA_FEATURE_NOT_PROVIDED = 0x68FF
    ACCESS_FEATURE_WITH_THE_SPECIFIED_LOGICAL_CHANNEL_NUMBER_NOT_PROVIDED = 0x6881
    SECURE_MESSAGING_FEATURE_NOT_PROVIDED = 0x6882
    COMMAND_NOT_PERMITTED = 0x69FF
    COMMAND_CONFLICTING_THE_FILE_STRUCTURE = 0x6981
    SECURITY_STATUS_NOT_FULFILLED = 0x6982
    REFERENCED_IEF_LOCKED = 0x6984
    COMMAND_USE_CONDITION_NOT_FULFILLED = 0x6985
    NO_CURRENT_EF = 0x6986
    NO_DATA_OBJECT_FOR_SECURE_MESSAGING = 0x6987
    SECURE_MESSAGING_CCS_ILLIGAL = 0x6988
    INCORRECT_PARAMETER_P1_P2 = 0x6AFF
    INCORRECT_DATA_FIELD_TAG = 0x6A80
    FEATURE_NOT_PROVIDED = 0x6A81
    NO_FILE_TO_BE_ACCESSED = 0x6A82
    NO_RECORD_TO_BE_ACCESSED = 0x6A83
    INSUFFICIENT_MEMORY_SPACE_IN_THE_FILE = 0x6A84
    LC_VALUE_CONFLICTING_THE_TLV_STRUCTURE = 0x6A85
    INCORRECT_P1_P2_VALUE = 0x6A86
    LC_VALUE_CONFLICTING_P1_P2 = 0x6A87
    REFERENCED_KEY_NOT_CORRECTLY_SET = 0x6A88
    OFFSET_SPECIFIED_OUT_OF_THE_EF_RANGE = 0x6B00
    INS_NOT_PROVIDED = 0x6D00
    CLASS_NOT_PROVIDED = 0x6E00
    SELF_DIAGNOSIS_FAILURE = 0x6F00
    NORMAL_END = 0x9000

    @classmethod
    def from_sw(cls, sw: int) -> Self:
        """From SW

        Args:
            sw (int): SW

        Returns:
            CardResponseStatusType: CardResponseStatusType instance
        """

        if sw & 0xFFF0 == 0x63C0:
            return CardResponseStatusType.VERIFICATION_UNMATCHING
        try:
            return cls(sw)
        except ValueError:
            pass
        try:
            return cls((sw & 0xFF00) | 0x00FF)
        except ValueError:
            pass
        return CardResponseStatusType.UNDEFINED


class CardResponseStatus:
    """Card Response Status"""

    def __init__(self, sw: int) -> None:
        """Constructor

        Args:
            sw (int): SW
        """

        self.sw = sw

    def status_type(self) -> CardResponseStatusType:
        """Get status type

        Returns:
            CardResponseStatusType: Status Type
        """

        return CardResponseStatusType.from_sw(self.sw)

    def verification_remaining(self) -> int | None:
        """Get verification remaining

        Raises:
            ValueError: The error is not 0x63XX

        Returns:
            int | None: If int that verification remaining, else verification unlimited
        """

        if self.sw & 0xFF00 != 0x6300:
            raise ValueError("The error is not 0x63XX (VERIFICATION_UNMATCHING).")
        if self.sw & 0x00F0 != 0x00C0:
            return
        return self.sw & 0x000F

    def is_cla_valid(self) -> bool:
        """Is CLA valid

        Returns:
            bool: True if CLA is valid, else False
        """

        return self.sw & 0xFF00 != 0x6800 and self.sw & 0xFF00 != 0x6E00

    def is_cla_ins_valid(self) -> bool:
        """Is CLA-INS valid

        Returns:
            bool: True if CLA-INS valid, else False
        """

        return self.is_cla_valid() and self.sw & 0xFF00 != 0x6D00

    def is_p1_p2_valid(self) -> bool:
        """Is P1-P2 valid

        Returns:
            bool: True if CLA-INS and P1-P2 valid, else True
        """

        status_type = self.status_type()
        return (
            self.is_cla_ins_valid()
            and status_type != CardResponseStatusType.INCORRECT_PARAMETER_P1_P2
            and status_type != CardResponseStatusType.FEATURE_NOT_PROVIDED
            and status_type != CardResponseStatusType.INCORRECT_P1_P2_VALUE
        )

    def is_lc_le_valid(self) -> bool:
        """Is Lc-Le valid

        Returns:
            bool: True if CLA-INS, P1-P2 and Le-Le valid, else True
        """

        status_type = self.status_type()
        return (
            self.is_p1_p2_valid()
            and status_type != CardResponseStatusType.INCORRECT_LC_LE_FIELD
        )


class CardResponseError(Exception):
    """Card Response Error"""

    def __init__(self, response_status: int | CardResponseStatus):
        """Constructor

        Args:
            response_status (int | CardResponseStatus): Response Status
        """

        if isinstance(response_status, int):
            self.status = CardResponseStatus(response_status)
        else:
            self.status = response_status
        self.message = f"The card returned {format(self.status.sw, '04X')} ({self.status.status_type().name})."
        super().__init__(self.message)
