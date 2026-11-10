"""Adapted from selected parts of GCHQ CyberChef's Magic.mjs at revision 554a3b071e6388e80a0803e2ffccd5224cdc94e1.

https://github.com/gchq/CyberChef/blob/554a3b071e6388e80a0803e2ffccd5224cdc94e1/src/core/lib/Magic.mjs

Original implementation authored by n1474335 <n1474335@gmail.com>. Crown Copyright 2018. Licensed under the Apache
License, Version 2.0.

Rewritten from JavaScript to Python and modified by Inditex for use in CerbIA.

This implementation does not reproduce the complete CyberChef Magic operation.
"""

from ._preprocessor import SpeculativeDecodingPreprocessor

__all__ = ["SpeculativeDecodingPreprocessor"]
