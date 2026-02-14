#!/usr/bin/env python3
"""
SCDA Message Patcher - Fix truncated format specifier strings in Oblivion ESP files.

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
"""

import os
import re
import sys
import glob
import shutil
import struct
import logging
import argparse
import configparser
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Pattern

# Format specifier patterns to look for (regex for matching in bytes)
# Matches: " %g", " %.0f", " %.1f", " %.2f", etc.
FORMAT_PATTERN = re.compile(rb' %(?:g|\.\d+f)$')

# Individual patterns for reporting
FORMAT_SUFFIXES = [
    b" %g",      # %g format
    b" %.0f",    # 0 decimal places
    b" %.1f",    # 1 decimal place
    b" %.2f",    # 2 decimal places
    b" %.3f",    # 3 decimal places
    b" %.4f",    # 4 decimal places
]


def setup_logging(log_file: str, verbose: bool = True) -> logging.Logger:
    """Set up logging to both console and file."""
    
    logger = logging.getLogger('scda_patcher')
    logger.setLevel(logging.DEBUG)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # File handler - always verbose
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_format = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    return logger


class ScriptPatchData:
    """Data for patching a single script."""
    
    def __init__(self, script_name: str):
        self.script_name = script_name
        self.target_strings: List[str] = []
        self.scda_start: int = 0
        self.scda_size: int = 0
        self.record_offset: int = 0
        self.found_strings: List[Tuple[int, bytes, str]] = []  # (file_offset, current_value, format_type)


class SCDAMessagePatcher:
    """General-purpose SCDA message string patcher supporting multiple scripts."""
    
    def __init__(self, config_path: str, dry_run: bool = False, no_backup: bool = False):
        self.config_path = config_path
        self.dry_run = dry_run
        self.no_backup = no_backup
        self.logger: Optional[logging.Logger] = None
        
        # Parsed from config
        self.esp_path: str = ""
        self.scripts: List[ScriptPatchData] = []
        
    def log(self, level: int, msg: str, *args):
        """Log a message if logger is available."""
        if self.logger:
            self.logger.log(level, msg, *args)
        else:
            print(msg % args if args else msg)
    
    def debug(self, msg: str, *args):
        self.log(logging.DEBUG, msg, *args)
    
    def info(self, msg: str, *args):
        self.log(logging.INFO, msg, *args)
    
    def warning(self, msg: str, *args):
        self.log(logging.WARNING, msg, *args)
    
    def error(self, msg: str, *args):
        self.log(logging.ERROR, msg, *args)
        
    def load_config(self) -> bool:
        """Load configuration from file."""
        
        self.debug("Loading configuration from: %s", self.config_path)
        
        config = configparser.ConfigParser()
        config.read(self.config_path)
        
        # Settings section (optional)
        if 'Settings' in config:
            self.esp_path = config.get('Settings', 'esp_path', fallback='')
            self.debug("  ESP path from config: %s", self.esp_path or "(not specified)")
        
        if not self.esp_path:
            self.error("esp_path not specified in [Settings] section")
            return False
        
        # Each other section is a script name
        for section in config.sections():
            if section == 'Settings':
                continue
            
            script = ScriptPatchData(section)
            self.debug("  Found script section: [%s]", section)
            
            # Collect all string values from this section
            for key in config[section]:
                value = config.get(section, key).strip()
                if value and not value.startswith('#'):
                    script.target_strings.append(value)
                    self.debug("    %s = %s", key, value)
            
            if script.target_strings:
                self.scripts.append(script)
                self.debug("    Total strings: %d", len(script.target_strings))
        
        success = bool(self.esp_path and self.scripts)
        if success:
            self.debug("Configuration loaded successfully: %d script(s)", len(self.scripts))
        else:
            self.error("Configuration loading failed")
        
        return success
    
    def find_esp_file(self) -> bool:
        """Verify ESP file exists."""
        
        self.debug("Verifying ESP file exists...")
        
        if not self.esp_path:
            self.error("ESP file path not configured")
            return False
        
        if not os.path.exists(self.esp_path):
            # Try glob pattern
            self.debug("  Path not found directly, trying glob pattern...")
            files = glob.glob(self.esp_path)
            if files:
                self.esp_path = files[0]
                self.debug("  Resolved via glob: %s", self.esp_path)
            else:
                self.error("ESP file not found: %s", self.esp_path)
                return False
        
        file_size = os.path.getsize(self.esp_path)
        self.debug("  ESP file verified: %s (%d bytes)", self.esp_path, file_size)
        return True
    
    def find_script_scda(self, data: bytes, script: ScriptPatchData) -> bool:
        """Find the target script and SCDA field in ESP data."""
        
        script_name_bytes = script.script_name.encode('ascii')
        self.debug("  Searching for SCPT record with EDID='%s'...", script.script_name)
        
        # Search for SCPT records
        pos = 0
        scpt_count = 0
        
        while pos < len(data) - 20:
            # Look for SCPT record type
            if data[pos:pos+4] == b'SCPT':
                scpt_count += 1
                record_size = struct.unpack('<I', data[pos+4:pos+8])[0]
                record_start = pos
                record_data_start = pos + 20  # After header
                record_end = record_data_start + record_size
                
                # Search for EDID subrecord
                subpos = record_data_start
                found_script = False
                
                while subpos < record_end - 6:
                    sub_type = data[subpos:subpos+4]
                    sub_size = struct.unpack('<H', data[subpos+4:subpos+6])[0]
                    sub_data_start = subpos + 6
                    
                    if sub_type == b'EDID':
                        # Check if this is our target script
                        edid = data[sub_data_start:sub_data_start + sub_size - 1]  # Exclude null terminator
                        if edid == script_name_bytes:
                            found_script = True
                            self.debug("    Found matching EDID at record offset 0x%08X", record_start)
                    
                    elif sub_type == b'SCDA' and found_script:
                        script.scda_start = subpos
                        script.scda_size = sub_size
                        script.record_offset = record_start
                        self.debug("    SCDA subrecord: offset=0x%08X, size=%d bytes", subpos, sub_size)
                        return True
                    
                    subpos = sub_data_start + sub_size
                
                pos = record_end
            else:
                pos += 1
        
        self.debug("  Searched %d SCPT records, target not found", scpt_count)
        return False
    
    def detect_format_type(self, string_bytes: bytes) -> Optional[str]:
        """Detect what format specifier type the string ends with."""
        
        for suffix in FORMAT_SUFFIXES:
            if string_bytes.endswith(suffix):
                return suffix.decode('ascii').strip()
        
        # Check with regex for any %.Nf pattern
        if FORMAT_PATTERN.search(string_bytes):
            match = FORMAT_PATTERN.search(string_bytes)
            if match:
                return match.group(0).decode('ascii').strip()
        
        return None
    
    def find_format_strings(self, data: bytes, script: ScriptPatchData) -> bool:
        """Find all strings with format specifiers in SCDA."""
        
        scda_data_start = script.scda_start + 6  # After SCDA header
        scda_data = data[scda_data_start:scda_data_start + script.scda_size]
        
        # Search pattern: LOC_SC_{script_name}
        search_prefix = f"LOC_SC_{script.script_name}".encode('ascii')
        
        self.debug("  Searching SCDA for strings starting with: %s", search_prefix.decode('ascii'))
        self.debug("    SCDA data range: 0x%08X - 0x%08X (%d bytes)", 
                   scda_data_start, scda_data_start + script.scda_size, script.scda_size)
        
        script.found_strings = []
        pos = 0
        total_loc_strings = 0
        
        while pos < len(scda_data):
            # Find next occurrence of our prefix
            idx = scda_data.find(search_prefix, pos)
            if idx == -1:
                break
            
            # Extract the full string (until null terminator or non-printable)
            end = idx
            while end < len(scda_data) and 32 <= scda_data[end] < 127:
                end += 1
            
            string_bytes = scda_data[idx:end]
            file_offset = scda_data_start + idx
            total_loc_strings += 1
            
            # Check for any supported format specifier
            format_type = self.detect_format_type(string_bytes)
            
            if format_type:
                script.found_strings.append((file_offset, string_bytes, format_type))
                self.debug("    [%d] 0x%08X: '%s' (format: %s, len=%d)", 
                           len(script.found_strings), file_offset, 
                           string_bytes.decode('ascii'), format_type, len(string_bytes))
            else:
                self.debug("    0x%08X: '%s' (no format specifier, skipped)", 
                           file_offset, string_bytes.decode('ascii'))
            
            pos = end + 1
        
        # Sort by file offset
        script.found_strings.sort(key=lambda x: x[0])
        
        self.debug("  Found %d LOC strings total, %d with format specifiers", 
                   total_loc_strings, len(script.found_strings))
        
        return len(script.found_strings) > 0
    
    def validate_script(self, script: ScriptPatchData) -> bool:
        """Validate that replacement strings match found strings in length."""
        
        if len(script.found_strings) != len(script.target_strings):
            self.error("Count mismatch: found %d strings with format specifiers, config has %d",
                       len(script.found_strings), len(script.target_strings))
            return False
        
        self.debug("  Validating string lengths...")
        all_valid = True
        
        for i, ((offset, found_bytes, fmt_type), target) in enumerate(zip(script.found_strings, script.target_strings)):
            found_len = len(found_bytes)
            target_bytes = target.encode('ascii')
            target_len = len(target_bytes)
            
            if found_len != target_len:
                self.error("  [%d] Length mismatch: found=%d, target=%d", i+1, found_len, target_len)
                self.error("      Found:  '%s'", found_bytes.decode('ascii'))
                self.error("      Target: '%s'", target)
                all_valid = False
            else:
                self.debug("    [%d] Length OK: %d chars (format: %s)", i+1, found_len, fmt_type)
        
        return all_valid
    
    def apply_patches_to_data(self, data: bytearray, script: ScriptPatchData) -> int:
        """Apply patches for one script to data buffer. Returns count of patches applied."""
        
        patches_applied = 0
        
        for i, ((offset, found_bytes, fmt_type), target) in enumerate(zip(script.found_strings, script.target_strings)):
            target_bytes = target.encode('ascii')
            
            # Verify current content
            current = bytes(data[offset:offset + len(found_bytes)])
            
            if current == found_bytes:
                if not self.dry_run:
                    data[offset:offset + len(target_bytes)] = target_bytes
                patches_applied += 1
                self.info("      ✅ [%d] '%s'", i+1, found_bytes.decode('ascii'))
                self.info("            → '%s'", target)
                self.debug("         Offset: 0x%08X, Format: %s, Length: %d", offset, fmt_type, len(target_bytes))
            elif current == target_bytes:
                self.info("      ⏩ [%d] Already patched: '%s'", i+1, target)
            else:
                self.error("      ❌ [%d] Unexpected data at 0x%08X", i+1, offset)
                self.debug("         Expected: %s", found_bytes.hex())
                self.debug("         Found:    %s", current.hex())
        
        return patches_applied
    
    def verify_script_patches(self, data: bytes, script: ScriptPatchData) -> bool:
        """Verify patches for one script were applied correctly."""
        
        all_correct = True
        
        for i, ((offset, found_bytes, fmt_type), target) in enumerate(zip(script.found_strings, script.target_strings)):
            target_bytes = target.encode('ascii')
            current = data[offset:offset + len(target_bytes)]
            
            if current == target_bytes:
                self.info("      ✅ [%d]: Verified", i+1)
                self.debug("         '%s' at 0x%08X", target, offset)
            else:
                self.error("      ❌ [%d]: Verification failed at 0x%08X", i+1, offset)
                self.debug("         Expected: %s", target_bytes.hex())
                self.debug("         Found:    %s", current.hex())
                all_correct = False
        
        return all_correct
    
    def validate_only(self) -> bool:
        """Run validation without making changes."""
        
        self.info("=" * 70)
        self.info("SCDA Message Patcher - Validation Mode")
        self.info("=" * 70)
        self.debug("Timestamp: %s", datetime.now().isoformat())
        self.debug("Dry run: %s, No backup: %s", self.dry_run, self.no_backup)
        
        if not self.load_config():
            self.error("Failed to load config")
            return False
        
        self.info("")
        self.info("📋 Configuration:")
        self.info("   Config file: %s", self.config_path)
        self.info("   Scripts: %d", len(self.scripts))
        
        for script in self.scripts:
            self.info("      • %s: %d strings", script.script_name, len(script.target_strings))
        
        if not self.find_esp_file():
            return False
        
        self.info("")
        self.info("📂 ESP file: %s", self.esp_path)
        self.info("   Size: %s bytes", f"{os.path.getsize(self.esp_path):,}")
        
        self.debug("Reading ESP file into memory...")
        with open(self.esp_path, 'rb') as f:
            data = f.read()
        self.debug("ESP file loaded: %d bytes", len(data))
        
        all_valid = True
        format_counts: Dict[str, int] = {}
        
        for script in self.scripts:
            self.info("")
            self.info("─" * 50)
            self.info("📜 Script: %s", script.script_name)
            
            if not self.find_script_scda(data, script):
                self.error("   Script not found in ESP")
                all_valid = False
                continue
            
            self.info("   ✅ Found at offset 0x%08X", script.record_offset)
            self.info("   SCDA: %d bytes at 0x%08X", script.scda_size, script.scda_start)
            
            if self.find_format_strings(data, script):
                # Count format types
                for _, _, fmt_type in script.found_strings:
                    format_counts[fmt_type] = format_counts.get(fmt_type, 0) + 1
                
                self.info("")
                self.info("   Found %d strings with format specifiers:", len(script.found_strings))
                for offset, string, fmt_type in script.found_strings:
                    self.info("      0x%08X: %s", offset, string.decode('ascii'))
                    self.debug("                 Format: %s, Length: %d", fmt_type, len(string))
                
                self.info("")
                self.info("   Validating lengths:")
                if not self.validate_script(script):
                    all_valid = False
            else:
                # Check if already patched
                patched_count = sum(1 for t in script.target_strings if t.encode('ascii') in data)
                if patched_count == len(script.target_strings):
                    self.info("   ✅ All %d strings appear already patched", patched_count)
                else:
                    self.warning("   ⚠️ No format specifier strings found (%d/%d targets exist)", 
                                patched_count, len(script.target_strings))
        
        # Summary of format types found
        if format_counts:
            self.info("")
            self.info("📊 Format specifiers found:")
            for fmt_type, count in sorted(format_counts.items()):
                self.info("   %s: %d occurrence(s)", fmt_type, count)
        
        self.info("")
        self.info("=" * 70)
        
        return all_valid
    
    def run(self) -> bool:
        """Run the patcher."""
        
        self.info("=" * 70)
        self.info("SCDA Message Patcher")
        self.info("=" * 70)
        self.debug("Timestamp: %s", datetime.now().isoformat())
        self.debug("Mode: %s", "DRY RUN" if self.dry_run else "LIVE")
        self.debug("Backup: %s", "disabled" if self.no_backup else "enabled")
        
        # Load config
        if not self.load_config():
            self.error("Failed to load configuration")
            return False
        
        self.info("")
        self.info("📋 Configuration: %s", self.config_path)
        self.info("   Scripts to patch: %d", len(self.scripts))
        
        for script in self.scripts:
            self.info("")
            self.info("   📜 %s:", script.script_name)
            for i, s in enumerate(script.target_strings, 1):
                self.info("      %d. %s", i, s)
                self.debug("         Length: %d chars", len(s))
        
        # Find ESP
        if not self.find_esp_file():
            return False
        
        self.info("")
        self.info("📂 ESP file: %s", self.esp_path)
        self.info("   Size: %s bytes", f"{os.path.getsize(self.esp_path):,}")
        
        # Read file
        self.debug("Reading ESP file into memory...")
        with open(self.esp_path, 'rb') as f:
            data = bytearray(f.read())
        
        original_size = len(data)
        self.debug("ESP file loaded: %d bytes", original_size)
        
        # Find all scripts and their format strings first
        scripts_to_patch = []
        total_format_strings = 0
        
        for script in self.scripts:
            self.info("")
            self.info("─" * 50)
            self.info("🔍 Analyzing: %s", script.script_name)
            
            if not self.find_script_scda(bytes(data), script):
                self.error("   Script not found in ESP")
                continue
            
            self.info("   ✅ Found at 0x%08X, SCDA: %d bytes", script.record_offset, script.scda_size)
            
            if not self.find_format_strings(bytes(data), script):
                self.warning("   ⚠️ No format specifier strings found (may already be patched)")
                continue
            
            total_format_strings += len(script.found_strings)
            self.info("   Found %d replacement target(s)", len(script.found_strings))
            
            if not self.validate_script(script):
                self.error("   Validation failed, skipping this script")
                continue
            
            scripts_to_patch.append(script)
            self.info("   ✅ Validation passed")
        
        if not scripts_to_patch:
            self.warning("No scripts need patching")
            return True
        
        # Create backup
        backup_path = None
        if not self.dry_run and not self.no_backup:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.esp_path}.backup_scda_{timestamp}"
            self.info("")
            self.info("📦 Creating backup: %s", backup_path)
            self.debug("   Source size: %d bytes", original_size)
            shutil.copy2(self.esp_path, backup_path)
            self.debug("   Backup created successfully")
        
        if self.dry_run:
            self.info("")
            self.info("🔍 DRY RUN - No changes will be made")
        
        # Apply patches
        total_patches = 0
        
        self.info("")
        self.info("=" * 50)
        self.info("🔧 Applying patches:")
        
        for script in scripts_to_patch:
            self.info("")
            self.info("   📜 %s:", script.script_name)
            patches = self.apply_patches_to_data(data, script)
            total_patches += patches
            self.debug("   Applied %d patches for this script", patches)
        
        # Write changes
        if not self.dry_run and total_patches > 0:
            self.info("")
            self.info("💾 Writing changes...")
            self.debug("   Writing %d bytes to: %s", len(data), self.esp_path)
            with open(self.esp_path, 'wb') as f:
                f.write(data)
            
            new_size = len(data)
            self.info("   Total patches: %d", total_patches)
            self.info("   File size: %s bytes (original: %s)", f"{new_size:,}", f"{original_size:,}")
            
            if new_size != original_size:
                self.warning("   ⚠️ File size changed! This may indicate a problem.")
        
        # Verify
        if not self.dry_run and total_patches > 0:
            self.info("")
            self.info("🔍 Verifying patches:")
            self.debug("   Re-reading ESP file for verification...")
            
            with open(self.esp_path, 'rb') as f:
                verify_data = f.read()
            self.debug("   Verification data loaded: %d bytes", len(verify_data))
            
            all_verified = True
            for script in scripts_to_patch:
                self.info("")
                self.info("   📜 %s:", script.script_name)
                if not self.verify_script_patches(verify_data, script):
                    all_verified = False
            
            if not all_verified:
                self.error("")
                self.error("Verification failed!")
                if backup_path:
                    self.info("Backup available at: %s", backup_path)
                return False
        
        self.info("")
        self.info("=" * 70)
        self.info("✅ SUCCESS - Patched %d script(s), %d string(s)", len(scripts_to_patch), total_patches)
        self.info("=" * 70)
        
        if backup_path:
            self.debug("Backup saved at: %s", backup_path)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='SCDA Message Patcher - Fix truncated format specifier strings in Oblivion ESP files.\n'
                    'Supports: %g, %.0f, %.1f, %.2f, and other %.Nf patterns.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('config', help='Path to config file (.ini)')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without modifying')
    parser.add_argument('--validate', action='store_true', help='Validate current state only')
    parser.add_argument('--no-backup', action='store_true', help='Skip creating backup')
    parser.add_argument('--log', metavar='FILE', help='Log file path (default: scda_patcher_TIMESTAMP.log)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose console output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config):
        print(f"❌ Config file not found: {args.config}")
        sys.exit(1)
    
    # Setup logging
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = args.log or f"scda_patcher_{timestamp}.log"
    
    # Put log file next to the config file
    if not os.path.dirname(log_file):
        config_dir = os.path.dirname(os.path.abspath(args.config))
        log_file = os.path.join(config_dir, log_file)
    
    logger = setup_logging(log_file, verbose=True)  # Always verbose to console now
    logger.debug("=" * 70)
    logger.debug("SCDA Message Patcher - Log Started")
    logger.debug("=" * 70)
    logger.debug("Command line: %s", ' '.join(sys.argv))
    logger.debug("Config file: %s", os.path.abspath(args.config))
    logger.debug("Log file: %s", log_file)
    logger.debug("Options: dry_run=%s, validate=%s, no_backup=%s", 
                 args.dry_run, args.validate, args.no_backup)
    
    patcher = SCDAMessagePatcher(
        config_path=args.config,
        dry_run=args.dry_run,
        no_backup=args.no_backup
    )
    patcher.logger = logger
    
    try:
        if args.validate:
            success = patcher.validate_only()
        else:
            success = patcher.run()
    except Exception as e:
        logger.exception("Unexpected error occurred")
        success = False
    
    logger.debug("")
    logger.debug("=" * 70)
    logger.debug("Session completed: %s", "SUCCESS" if success else "FAILED")
    logger.debug("Log file: %s", log_file)
    logger.debug("=" * 70)
    
    print(f"\n📝 Log file: {log_file}")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
