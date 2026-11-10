# SPDX-FileCopyrightText: 2026 Jose Manuel Caamaño González (jmcaamanog)
# SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)
#
# SPDX-License-Identifier: Apache-2.0

"""BIM Work Breakdown Structure (WBS) Matrix for Retail Store Roll-Outs.

Illustrative English package and discipline model for BIM coordination.
"""

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class BimMatrixEntry:
    """Mapping between Management Package and BIM Discipline."""

    package_code: str
    package_name: str
    discipline_code: str
    discipline_name: str


BIM_WBS_MATRIX: Final[tuple[BimMatrixEntry, ...]] = (
    BimMatrixEntry("200HVAC", "HVAC & Mechanical Works", "HVAC", "Heating, Ventilation & Air Conditioning"),
)


def get_matrix_entries_by_package(package_code: str) -> list[BimMatrixEntry]:
    """Retrieve all BIM discipline mappings for a management package."""
    return [entry for entry in BIM_WBS_MATRIX if entry.package_code.upper() == package_code.upper()]
