#
# Copyright (c) 2021 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-4-Clause
#

SETTINGS_SECTOR_SIZE = 0x1000
SETTINGS_PARTITION_SIZE_DEFAULT = 0x2000

FLASH_ERASE_VALUE = b'\xff'

FLASH_SIZE = {
    'NRF52832': 0x80000,
    'NRF52833': 0x80000,
    'NRF52840': 0x100000,
    'NRF5340':  0x100000,
}

SETTINGS_PARTITION_SIZE_DEFAULT = {
    'NRF52832': 0x2000,
    'NRF52833': 0x2000,
    'NRF52840': 0x2000,
    'NRF5340':  0x4000,
}
