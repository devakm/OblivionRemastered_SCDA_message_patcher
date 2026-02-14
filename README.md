# OblivionRemastered_SCDA_message_patcher

Python script to fix Oblivion CS compiler issue with localized script messages containing a variable

SCDA Message Patcher - Fix truncated format specifier strings in Oblivion ESP files.

Example ini file provided for Oscuro's_Oblivion_Overhaul.esp

Patches compiled script data (SCDA) fields in Oblivion ESP files to fix
truncated message strings with format specifiers.

Supported format specifiers:
    %g       - Float/int as whole number
    %.0f     - Float with 0 decimal places
    %.1f     - Float with 1 decimal place
    %.2f     - Float with 2 decimal places
    %.Nf     - Float with N decimal places (any digit)

Supports multiple scripts in a single config file.

Usage:
    python scda_message_patcher.py config.ini [--dry-run] [--validate] [--no-backup]

Config file format (INI):
    [Settings]
    esp_path = C:\\path\\to\\plugin.esp

    [ScriptEditorID]
    1 = LOC_SC_ScriptEditorID_ReplacementString_01
    2 = LOC_SC_ScriptEditorID_ReplacementString_02

    - [Settings] section: Required. Contains esp_path to the ESP/ESM file.
    - Each additional section name is the exact script Editor ID (EDID) to patch.
    - Keys (1, 2, 3...) define the order; strings are matched by file offset.
    - Values are the replacement LOC_ strings (must be EXACT same length as originals).
    - Comments: Lines starting with # or ; are ignored.
