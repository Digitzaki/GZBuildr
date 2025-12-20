"""
Pipeworks Bundle Parser
- Developed by Digitzaki
A GUI tool for parsing, extracting, and rebuilding GameCube/PS2 bundle files.

Features:
- Parse BDG/CMG/CMP/VOL bundle files and display contents
- Extract individual files by type
- Rebuild BDG/CMG/CMP/VOL files with modified content
- Drag-and-drop support
- Supports Pipeworks format (BDG/CMG/CMP/CLP/BDP) and .VOL format (experimental)
- Block size alignment restrictions, adjustable during rebuild.

To enable drag-and-drop functionality, install:
    pip install tkinterdnd2

If not installed, you can still use the Browse button to select files.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import struct
import os
import shutil

# Try to import drag-and-drop library
HAS_DND = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    pass


class PipeworksParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.file_data = None
        self.is_big_endian = False
        self.bundle_type = None  # 'pipeworks' or 'vol'
        self.string_offset = 0
        self.file_count = 0
        self.metadata_offset = 0
        self.main_data_offset = 0
        self.resource_data_offset = 0

    def read_bytes(self, offset, size):
        """Read bytes from file at specific offset"""
        return self.file_data[offset:offset + size]

    def read_long(self, offset):
        """Read 4-byte long (endianness based on file)"""
        endian = '>' if self.is_big_endian else '<'
        return struct.unpack(f'{endian}I', self.read_bytes(offset, 4))[0]

    def read_short(self, offset):
        """Read 2-byte short (endianness based on file)"""
        endian = '>' if self.is_big_endian else '<'
        return struct.unpack(f'{endian}H', self.read_bytes(offset, 2))[0]

    def read_byte(self, offset):
        """Read 1-byte"""
        return self.file_data[offset]

    def read_long_little(self, offset):
        """Read 4-byte little-endian long (for string table)"""
        return struct.unpack('<I', self.read_bytes(offset, 4))[0]

    def read_string(self, offset):
        """Read null-terminated string and clean it"""
        end = offset
        while end < len(self.file_data) and self.file_data[end] != 0:
            end += 1
        # Decode and strip control characters and extended ASCII
        raw_string = self.file_data[offset:end].decode('ascii', errors='ignore')
        # Keep only printable ASCII characters (32-126) and strip whitespace
        cleaned = ''.join(c for c in raw_string if 32 <= ord(c) <= 126)
        return cleaned.strip()

    def detect_file_type_from_extension(self, filename):
        """Detect file type from filename extension for VOL files"""
        ext = filename.lower().split('.')[-1] if '.' in filename else ''

        # Map common extensions to file types
        extension_map = {
            'cmp': 0,   # Static Mesh (compressed)
            'bdg': 0,   # Static Mesh bundle
            'cmg': 0,   # Static Mesh bundle
            'mesh': 0,  # Static Mesh
            'skel': 1,  # Skeleton
            'skl': 1,   # Skeleton
            'anim': 4,  # Animation
            'ani': 4,   # Animation
            'mat': 6,   # Material
            'dds': 9,   # Texture
            'tga': 9,   # Texture
            'png': 9,   # Texture
            'tex': 9,   # Texture
            'pvm': 9,   # Texture (PVM archive)
            'pal': 13,  # Palette
            'pwk': 16,  # PWK File
            'prx': 22,  # PRX File
            'loc': 23,  # Localization
            'txt': 23,  # Localization
            'zip': 24,  # Archive
            'mic': 25,  # Audio (MIC format)
            'bdp': 26,  # BDP File
            'pss': 27,  # Video (PSS format)
        }

        return extension_map.get(ext, 255)  # 255 = Unknown

    def get_file_info(self, file_num):
        """Extract file name and type from metadata and string table"""
        try:
            # Get metadata entry offset (16 bytes per entry)
            metadata_start = self.metadata_offset + (file_num * 0x10)
            entry_offset = metadata_start + 0x2

            # Get file type (1 byte)
            file_type = self.read_byte(entry_offset)

            # Skip 1 byte, then get string ID (4 bytes)
            str_id = self.read_long(entry_offset + 2)

            # Get string from string table
            str_entry = (str_id * 0x4) + 0x4
            str_offset_pos = self.string_offset + str_entry

            # String table is always little-endian
            str_offset = self.read_long_little(str_offset_pos)

            # Calculate final string position
            string_pos = self.string_offset + str_offset

            # Read the string
            name = self.read_string(string_pos)
            if not name:
                name = f"file_{file_num}"

            # Create folder structure based on file type (use decimal, not hex)
            folder_name = str(file_type)
            # Remove pipe character from filename as it causes extraction issues
            clean_name = name.replace('|', '_')
            full_name = f"{folder_name}/{clean_name}"

            # Read full metadata entry (16 bytes) for preservation
            metadata_bytes = self.read_bytes(metadata_start, 0x10)

            return full_name, file_type, metadata_bytes
        except Exception as e:
            return f"file_{file_num}", 0, None

    def parse(self):
        """Parse bundle file (Pipeworks or VOL format)"""
        results = []

        try:
            # Read entire file
            with open(self.filepath, 'rb') as f:
                self.file_data = f.read()

            # Check header to determine bundle type
            header = self.file_data[0:4].decode('ascii', errors='ignore')

            if header == "PVOL":
                self.bundle_type = 'vol'
                return self.parse_vol()
            elif self.file_data[0:9].decode('ascii', errors='ignore') == "Pipeworks":
                self.bundle_type = 'pipeworks'
                return self.parse_pipeworks()
            else:
                return [{"error": "Not a valid bundle file (expected 'Pipeworks' or 'PVOL' header)"}]

        except Exception as e:
            return [{"error": f"Error parsing file: {str(e)}"}]

    def parse_pipeworks(self):
        """Parse Pipeworks bundle file (BDG/CMG)"""
        results = []

        try:

            # Detect endianness at 0x2C (default little-endian)
            endian_check = struct.unpack('<H', self.file_data[0x2C:0x2E])[0]
            if endian_check == 0:
                self.is_big_endian = True

            # Read header values with proper endianness
            self.string_offset = self.read_long(0x34)
            self.file_count = self.read_short(0x62)
            self.metadata_offset = self.read_long(0x64)
            self.main_data_offset = self.read_long(0x68)
            self.resource_data_offset = self.read_long(0x70)

            # Start parsing TOC at 0x78
            toc_offset = 0x78

            for i in range(self.file_count):
                entry_offset = toc_offset + (i * 0x12)

                # Read file entry
                file_num = self.read_short(entry_offset)
                offset = self.read_long(entry_offset + 2)
                size = self.read_long(entry_offset + 6)
                res_offset = self.read_long(entry_offset + 10)
                res_size = self.read_long(entry_offset + 14)

                # Adjust offset
                actual_offset = offset + self.main_data_offset

                # Get file name and type from metadata
                name, file_type, metadata_bytes = self.get_file_info(file_num)

                results.append({
                    "file_num": file_num,
                    "name": name,
                    "offset": actual_offset,
                    "size": size,
                    "raw_offset": offset,
                    "toc_entry_offset": entry_offset,
                    "is_resource": False,
                    "file_type": file_type,
                    "metadata_bytes": metadata_bytes
                })

                # Add resource entry if it exists
                if res_size > 0:
                    actual_res_offset = res_offset + self.resource_data_offset
                    results.append({
                        "file_num": file_num,
                        "name": f"{name}.resource",
                        "offset": actual_res_offset,
                        "size": res_size,
                        "raw_offset": res_offset,
                        "toc_entry_offset": entry_offset,
                        "is_resource": True,
                        "file_type": file_type,
                        "metadata_bytes": metadata_bytes
                    })

            return results

        except Exception as e:
            return [{"error": f"Error parsing file: {str(e)}"}]

    def parse_vol(self):
        """Parse VOL bundle file (PS2 format)"""
        results = []

        try:
            # VOL files are always little-endian (PS2)
            self.is_big_endian = False

            # Read header
            # 0x00: "PVOL" signature (already verified)
            unk = struct.unpack('<I', self.file_data[4:8])[0]
            self.file_count = struct.unpack('<I', self.file_data[8:12])[0]
            self.main_data_offset = struct.unpack('<I', self.file_data[12:16])[0]

            # Calculate string table offset
            # TOC structure: 0xC bytes per entry (offset, size, file_id) + 4 bytes per file_id + 20 byte header
            self.string_offset = (0xC * self.file_count) + (4 * self.file_count) + 20

            # Start parsing TOC at 0x14 (20 bytes)
            toc_offset = 20

            # First pass: read TOC entries
            # Entry structure: OFFSET (4), SIZE (4), FILE_ID (4)
            toc_entries = []
            for i in range(self.file_count):
                entry_offset = toc_offset + (i * 0xC)

                offset = struct.unpack('<I', self.file_data[entry_offset:entry_offset + 4])[0]
                size = struct.unpack('<I', self.file_data[entry_offset + 4:entry_offset + 8])[0]
                file_id = struct.unpack('<I', self.file_data[entry_offset + 8:entry_offset + 12])[0]

                toc_entries.append({
                    'offset': offset,
                    'size': size,
                    'file_id': file_id,
                    'toc_entry_offset': entry_offset
                })

            # Second pass: read file names from string table
            name_offset = self.string_offset
            for i, entry in enumerate(toc_entries):
                # Read null-terminated string
                name_end = name_offset
                while name_end < len(self.file_data) and self.file_data[name_end] != 0:
                    name_end += 1

                name = self.file_data[name_offset:name_end].decode('ascii', errors='ignore')

                # Detect file type from extension
                file_type = self.detect_file_type_from_extension(name)

                results.append({
                    "file_num": i,
                    "name": name,
                    "offset": entry['offset'],
                    "size": entry['size'],
                    "raw_offset": entry['offset'],
                    "toc_entry_offset": entry['toc_entry_offset'],
                    "is_resource": False,
                    "file_type": file_type,
                    "metadata_bytes": None,
                    "file_id": entry['file_id']
                })

                # Move to next string (skip null terminator)
                name_offset = name_end + 1

            return results

        except Exception as e:
            return [{"error": f"Error parsing VOL file: {str(e)}"}]

    def extract_file(self, file_entry, output_dir):
        """Extract a single file from the bundle"""
        try:
            output_path = os.path.join(output_dir, file_entry['name'])

            # Create folder if it doesn't exist
            folder_path = os.path.dirname(output_path)
            if folder_path and not os.path.exists(folder_path):
                os.makedirs(folder_path)

            offset = file_entry['offset']
            size = file_entry['size']

            file_data = self.read_bytes(offset, size)

            with open(output_path, 'wb') as f:
                f.write(file_data)

            return True
        except Exception as e:
            print(f"Error extracting {file_entry['name']}: {e}")
            return False

    def detect_alignment(self, files):
        """Detect alignment by checking gaps between consecutive files"""
        alignments = []
        for i in range(len(files) - 1):
            current = files[i]
            next_file = files[i + 1]

            # Calculate where next file starts vs where current ends
            current_end = current['raw_offset'] + current['size']
            gap = next_file['raw_offset'] - current_end

            if gap > 0:
                # Check common alignments: 16, 32, 64, 128, 2048
                for align in [16, 32, 64, 128, 256, 512, 2048]:
                    if next_file['raw_offset'] % align == 0:
                        alignments.append(align)
                        break

        # Return most common alignment, or 16 as default
        if alignments:
            return max(set(alignments), key=alignments.count)
        return 16

    def read_replacement_file(self, filepath):
        """Read replacement file, handling both binary and hex-encoded text files"""
        with open(filepath, 'rb') as f:
            data = f.read()

        # Check if this is a hex-encoded text file
        # Hex files typically contain only hex chars (0-9, A-F, a-f) and whitespace
        try:
            text_data = data.decode('ascii').strip()
            # Remove all whitespace
            hex_string = ''.join(text_data.split())

            # Check if it's all hex characters
            if all(c in '0123456789ABCDEFabcdef' for c in hex_string):
                # This is a hex-encoded file, convert it to bytes
                print(f"    Detected hex-encoded text file, converting to binary")
                print(f"    Hex string length: {len(hex_string)} chars -> {len(hex_string)//2} bytes")
                return bytes.fromhex(hex_string)
        except (UnicodeDecodeError, ValueError):
            pass

        # Return as-is if not hex-encoded
        return data

    def find_replacement_file(self, replacement_dir, original_name):
        """
        Find replacement file with exact filename match.

        NOTE: CMG files are bundle containers (same as BDG), not mesh files.
        They should not be replaced with .mesh files or vice versa.
        Returns (filepath, actual_name) if found, or (None, None) if not found.
        """
        # Only look for exact filename match
        original_path = os.path.join(replacement_dir, original_name)
        if os.path.exists(original_path):
            return original_path, original_name

        return None, None

    def validate_texture_replacement(self, original_data, replacement_data, filename):
        """Validate texture replacement for common issues"""
        issues = []
        warnings = []

        # Check for common texture formats
        original_size = len(original_data)
        replacement_size = len(replacement_data)

        # Check if file has a known texture header
        if len(replacement_data) >= 4:
            header = replacement_data[0:4]
            # Check for DDS header (common texture format)
            if header == b'DDS ':
                warnings.append("DDS texture detected - ensure mipmaps are included")

        # Check for size mismatch
        if replacement_size != original_size:
            # Calculate size difference percentage
            size_diff_pct = abs(replacement_size - original_size) / original_size * 100

            if size_diff_pct > 50:
                issues.append(f"Large size change: {original_size} -> {replacement_size} ({size_diff_pct:.1f}%)")
                issues.append("This may indicate missing mipmaps or incorrect format")
            else:
                warnings.append(f"Size changed: {original_size} -> {replacement_size} ({size_diff_pct:.1f}%)")

        # Check for power-of-2 dimensions (common requirement for textures with mipmaps)
        # Estimate if this might be a raw texture by checking if size matches common formats
        # Common texture sizes: 4bpp (DXT1), 8bpp (DXT5), 16bpp, 32bpp
        common_bpp = [4/8, 8/8, 2, 4]  # bytes per pixel for various formats

        for bpp in common_bpp:
            # Check if size matches a square power-of-2 texture
            for size in [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]:
                expected_size = int(size * size * bpp)
                # For DXT compressed textures, include mipmap chain (adds ~33% to size)
                with_mipmaps = int(expected_size * 1.333)

                if replacement_size == expected_size:
                    warnings.append(f"Matches {size}x{size} texture without mipmaps (may cause low-res rendering)")
                    break
                elif replacement_size == with_mipmaps:
                    warnings.append(f"Appears to be {size}x{size} texture with mipmaps (good!)")
                    break

        return issues, warnings

    def validate_model_replacement(self, original_data, replacement_data, filename):
        """Validate model/mesh replacement for common issues"""
        issues = []
        warnings = []

        original_size = len(original_data)
        replacement_size = len(replacement_data)

        # CRITICAL: Mesh files contain internal offsets to vertex/index/submesh data
        # Changing the file size breaks these offsets, causing massive deformation
        if replacement_size > original_size:
            issues.append(f"CRITICAL: Model is LARGER than original ({replacement_size} > {original_size} bytes)")
            issues.append("Mesh files have internal offsets that break when size changes")
            issues.append("This causes vertices to be read from wrong locations → massive stretching")
            issues.append("SOLUTION: Reduce model complexity, lower poly count, or compress")
            issues.append("Models CANNOT exceed their original file size")

        # Check for internal pointers/offsets (common in model files)
        # Look for patterns that might indicate offset tables at the start
        if len(replacement_data) >= 16:
            # Check first 16 bytes for values that look like offsets
            potential_offsets = []
            for i in range(0, min(64, len(replacement_data)), 4):
                val = struct.unpack('<I', replacement_data[i:i+4])[0]
                # Offsets typically point within the file
                if 16 < val < len(replacement_data):
                    potential_offsets.append(val)

            if len(potential_offsets) >= 3:
                warnings.append(f"Detected {len(potential_offsets)} internal offset pointers")
                if replacement_size != original_size:
                    issues.append("Size changed in file with internal offsets!")
                    issues.append("Vertex/index/submesh data will be read from wrong locations")

        # Check for size change
        if replacement_size != original_size and replacement_size < original_size:
            size_diff_pct = abs(replacement_size - original_size) / original_size * 100

            if size_diff_pct > 50:
                warnings.append(f"Large size reduction: {original_size} -> {replacement_size} ({size_diff_pct:.1f}%)")
                warnings.append("Will be padded to original size to preserve mesh structure")

        return issues, warnings

    def pad_model_to_block_size(self, data, original_size):
        """Pad model data to match original block size to prevent stretching"""
        # Models must maintain exact block sizes or they stretch/deform
        # Common model block sizes: 512, 1024, 2048, 4096, 8192

        data_size = len(data)

        # If replacement is larger than original, we can't safely pad
        if data_size > original_size:
            return data

        # Pad to match original size exactly to preserve scale/transform data positions
        if data_size < original_size:
            padding_needed = original_size - data_size
            # Pad with zeros to reach original size
            padded_data = bytearray(data)
            padded_data.extend(b'\x00' * padding_needed)
            return bytes(padded_data)

        return data

    def get_alignment_for_type(self, file_type, detected_alignment):
        """Get appropriate alignment for file type, with CMG/CMP-specific handling"""

        # Check if custom alignments were provided (from GUI)
        if hasattr(self, 'custom_alignments') and file_type in self.custom_alignments:
            return self.custom_alignments[file_type]

        # Check if we're rebuilding a CMG or CMP bundle
        is_cmg = self.filepath.lower().endswith(".cmg")
        is_cmp = self.filepath.lower().endswith(".cmp")
        is_clp = self.filepath.lower().endswith(".clp")
        is_bdp = self.filepath.lower().endswith(".bdp")

        if is_cmg:
            # CMG-specific (DAMM)
            type_alignments = {
                0: 64,    # Static Mesh
                6: 16,    # Material
                9: 64,   # Texture
                13: 16,   # Palette
                17: 64,   # Rigged Mesh
                20: 16,   # Particle
            }
        elif is_cmp or is_bdp or is_clp:
            # PS2 Specific (CMP/BDP/CLP)
            type_alignments = {
                0: 128,    # Static Mesh
                6: 16,    # Material
                9: 64,   # Texture
                13: 16,   # Palette
                17: 128,   # Rigged Mesh
                20: 16,   # Particle
            }
        else:
            # BDG / UNLEASHED (WII)
            type_alignments = {
                0: 512,   # Static Mesh
                6: 16,    # Material
                9: 128,   # Texture
                13: 16,   # Palette
                17: 512,  # Rigged Mesh
                20: 16,   # Particle
            }

        return type_alignments.get(file_type, detected_alignment)

    def rebuild_bdg(self, output_bdg_path, file_entries, replacement_dir, custom_alignments=None):
        """Rebuild BDG file with replaced files"""
        try:
            # Store custom alignments for use in get_alignment_for_type
            self.custom_alignments = custom_alignments if custom_alignments else {}

            # Create a mutable copy of file_data
            new_data = bytearray(self.file_data)

            # First, get ALL files from the archive
            all_files = self.parse()

            # Detect alignment from original file structure
            main_files = [f for f in all_files if not f['is_resource']]
            resource_files = [f for f in all_files if f['is_resource']]

            detected_main_alignment = self.detect_alignment(sorted(main_files, key=lambda x: x['raw_offset']))
            detected_resource_alignment = self.detect_alignment(sorted(resource_files, key=lambda x: x['raw_offset'])) if resource_files else 16

            print(f"Detected base alignment - Main: {detected_main_alignment} bytes, Resource: {detected_resource_alignment} bytes")

            # Group ALL entries by file_num to handle main and resource files together
            file_groups = {}
            for entry in all_files:
                file_num = entry['file_num']
                if file_num not in file_groups:
                    file_groups[file_num] = {
                        'main': None,
                        'resource': None,
                        'toc_offset': entry['toc_entry_offset']
                    }

                if entry['is_resource']:
                    file_groups[file_num]['resource'] = entry
                else:
                    file_groups[file_num]['main'] = entry

            # Keep header and TOC structure
            header_size = self.main_data_offset
            header_and_toc = new_data[:header_size]

            # Build new data sections
            new_file_data = bytearray()
            new_resource_data = bytearray()

            # Determine endianness format
            endian = '>' if self.is_big_endian else '<'

            # Process files in TOC order (by file_num) to maintain consistency
            print(f"\nRebuilding {len(file_groups)} files...")
            for file_num in sorted(file_groups.keys()):
                group = file_groups[file_num]
                toc_offset = group['toc_offset']

                # Process main file
                main_offset = 0
                main_size = 0
                if group['main']:
                    entry = group['main']

                    # Get appropriate alignment for this file type
                    file_alignment = self.get_alignment_for_type(entry['file_type'], detected_main_alignment)

                    # Look for replacement file (exact filename match only)
                    replacement_path, actual_name = self.find_replacement_file(replacement_dir, entry['name'])

                    if replacement_path:
                        file_data = self.read_replacement_file(replacement_path)
                        original_data = self.read_bytes(entry['offset'], entry['size'])

                        original_size = len(file_data)
                        size_changed = len(file_data) != entry['size']
                        already_printed = False  # Track if we already printed status

                        # Validate replacement based on file type
                        issues = []
                        warnings = []

                        if entry['file_type'] == 9:  # Texture
                            issues, warnings = self.validate_texture_replacement(original_data, file_data, entry['name'])
                        elif entry['file_type'] in [0, 17]:  # Static/Rigged Mesh
                            issues, warnings = self.validate_model_replacement(original_data, file_data, entry['name'])

                            # CRITICAL: Pad models to original size to prevent stretching/deformation
                            if len(file_data) != entry['size']:
                                if len(file_data) > entry['size']:
                                    # Model is too large - MUST use original to prevent stretching
                                    issues.append(f"Model EXCEEDS original size by {len(file_data) - entry['size']} bytes")
                                    issues.append("Using ORIGINAL model to prevent map-wide stretching/deformation")

                                    # Print errors BEFORE falling back
                                    file_info = entry['name']
                                    if actual_name != entry['name']:
                                        file_info = f"{entry['name']} → {actual_name}"
                                    print(f"  File {file_num} ({file_info}): REJECTED - replacement too large!")
                                    for issue in issues:
                                        print(f"    ⚠ {issue}")
                                    for warning in warnings:
                                        print(f"    ⓘ {warning}")

                                    # Fall back to original data
                                    file_data = original_data
                                    issues = []  # Clear issues since we're using original
                                    warnings = []
                                    size_changed = False
                                    already_printed = True  # Already printed rejection message
                                    print(f"    → Using original model, size {len(file_data)}")
                                else:
                                    # Pad to original size
                                    file_data = self.pad_model_to_block_size(file_data, entry['size'])
                                    warnings.append(f"Padded model from {original_size} to {len(file_data)} bytes to prevent stretching")
                                    size_changed = False  # After padding, size matches
                        elif size_changed:
                            # Generic validation for other file types
                            size_diff_pct = abs(len(file_data) - entry['size']) / entry['size'] * 100
                            if size_diff_pct > 10:
                                warnings.append(f"Size changed: {entry['size']} -> {len(file_data)} ({size_diff_pct:.1f}%)")

                        # Print status (only if not already printed)
                        if not already_printed:
                            status = "replacement" if size_changed else "replacement (same size)"
                            size_info = f"size {len(file_data)}"
                            if entry['file_type'] in [0, 17] and len(file_data) == entry['size'] and original_size != entry['size']:
                                size_info = f"size {len(file_data)} (padded from {original_size})"

                            # Show if using alternative file
                            file_info = entry['name']
                            if actual_name != entry['name']:
                                file_info = f"{entry['name']} → {actual_name}"

                            print(f"  File {file_num} ({file_info}): Using {status}, {size_info}, align {file_alignment}")

                            # Print issues and warnings
                            for issue in issues:
                                print(f"    ⚠ CRITICAL: {issue}")
                            for warning in warnings:
                                print(f"    ⓘ {warning}")

                        if issues:
                            print(f"    ⚠ File may cause rendering issues or crashes!")
                    else:
                        file_data = self.read_bytes(entry['offset'], entry['size'])
                        type_info = ""
                        if entry['file_type'] in [0, 17]:
                            type_info = f" [Model: original size={entry['size']}]"
                        print(f"  File {file_num} ({entry['name']}): Using original, size {len(file_data)}, align {file_alignment}{type_info}")

                    # Calculate new offset with proper alignment
                    current_pos = len(new_file_data)
                    if current_pos > 0:
                        # Apply alignment padding based on file type
                        padding = (file_alignment - (current_pos % file_alignment)) % file_alignment
                        if padding > 0:
                            new_file_data.extend(b'\x00' * padding)

                    main_offset = len(new_file_data)
                    main_size = len(file_data)

                    # Add file data
                    new_file_data.extend(file_data)

                # Process resource file
                res_offset = 0
                res_size = 0
                if group['resource']:
                    entry = group['resource']

                    # Resources typically use the same alignment as their parent file type
                    resource_alignment = self.get_alignment_for_type(entry['file_type'], detected_resource_alignment)

                    # Look for replacement file (exact filename match only)
                    replacement_path, res_actual_name = self.find_replacement_file(replacement_dir, entry['name'])

                    if replacement_path:
                        resource_data = self.read_replacement_file(replacement_path)
                        original_data = self.read_bytes(entry['offset'], entry['size'])

                        original_res_size = len(resource_data)
                        size_changed = len(resource_data) != entry['size']
                        res_already_printed = False

                        # Validate resource based on file type
                        issues = []
                        warnings = []

                        if entry['file_type'] == 9:  # Texture resource (likely mipmaps)
                            issues, warnings = self.validate_texture_replacement(original_data, resource_data, entry['name'])
                            if size_changed:
                                issues.append("Texture resource size changed - this often contains mipmap data!")
                                issues.append("Missing mipmaps will cause low-resolution rendering at distance")
                        elif entry['file_type'] in [0, 17]:  # Model resource
                            # Models resources also need size preservation
                            if len(resource_data) != entry['size']:
                                if len(resource_data) > entry['size']:
                                    # Resource too large - fall back to original
                                    issues.append(f"Model resource EXCEEDS original by {len(resource_data) - entry['size']} bytes")
                                    issues.append("Using ORIGINAL resource to prevent deformation")

                                    res_info = entry['name'] if res_actual_name == entry['name'] else f"{entry['name']} → {res_actual_name}"
                                    print(f"    Resource ({res_info}): REJECTED - replacement too large!")
                                    for issue in issues:
                                        print(f"      ⚠ {issue}")

                                    resource_data = original_data
                                    issues = []
                                    warnings = []
                                    size_changed = False
                                    res_already_printed = True
                                    print(f"      → Using original resource, size {len(resource_data)}")
                                else:
                                    # Pad to original size
                                    resource_data = self.pad_model_to_block_size(resource_data, entry['size'])
                                    warnings.append(f"Padded resource from {original_res_size} to {len(resource_data)} bytes")
                                    size_changed = False

                        # Print status (only if not already printed)
                        if not res_already_printed:
                            status = "replacement" if size_changed else "replacement (same size)"
                            res_info = entry['name'] if res_actual_name == entry['name'] else f"{entry['name']} → {res_actual_name}"
                            print(f"    Resource ({res_info}): Using {status}, size {len(resource_data)}, align {resource_alignment}")

                            # Print issues and warnings
                            for issue in issues:
                                print(f"      ⚠ CRITICAL: {issue}")
                            for warning in warnings:
                                print(f"      ⓘ {warning}")
                    else:
                        resource_data = self.read_bytes(entry['offset'], entry['size'])
                        print(f"    Resource: Using original, size {len(resource_data)}, align {resource_alignment}")

                    # Calculate new offset with proper alignment
                    current_pos = len(new_resource_data)
                    if current_pos > 0:
                        # Apply alignment padding based on file type
                        padding = (resource_alignment - (current_pos % resource_alignment)) % resource_alignment
                        if padding > 0:
                            new_resource_data.extend(b'\x00' * padding)

                    res_offset = len(new_resource_data)
                    res_size = len(resource_data)

                    # Add resource data
                    new_resource_data.extend(resource_data)

                # Update entire TOC entry with new values
                # TOC entry structure (18 bytes):
                # +0: file_num (2 bytes) - keep original
                # +2: main_offset (4 bytes)
                # +6: main_size (4 bytes)
                # +10: resource_offset (4 bytes)
                # +14: resource_size (4 bytes)

                print(f"    Writing TOC at 0x{toc_offset:X}: offset={main_offset}, size={main_size}, res_offset={res_offset}, res_size={res_size}")

                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 2, main_offset)
                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 6, main_size)
                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 10, res_offset)
                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 14, res_size)

                # Verify what we wrote
                verify_offset = struct.unpack_from(f'{endian}I', header_and_toc, toc_offset + 2)[0]
                verify_size = struct.unpack_from(f'{endian}I', header_and_toc, toc_offset + 6)[0]
                print(f"    Verified TOC: offset={verify_offset}, size={verify_size}")

            # Add final padding to main data block to ensure resource block starts aligned
            if len(new_file_data) > 0:
                # Align to at least 2048 bytes for resource block start
                block_alignment = 2048
                padding = (block_alignment - (len(new_file_data) % block_alignment)) % block_alignment
                if padding > 0:
                    new_file_data.extend(b'\x00' * padding)
                    print(f"\nAdded {padding} bytes of padding to main data block for {block_alignment}-byte alignment")

            # Update resource block offset in header
            new_resource_block_offset = header_size + len(new_file_data)
            struct.pack_into(f'{endian}I', header_and_toc, 0x70, new_resource_block_offset)

            # Add final padding to resource data block to ensure file ends aligned
            if len(new_resource_data) > 0:
                # Align to 16 bytes for file end
                file_end_alignment = 16
                padding = (file_end_alignment - (len(new_resource_data) % file_end_alignment)) % file_end_alignment
                if padding > 0:
                    new_resource_data.extend(b'\x00' * padding)
                    print(f"Added {padding} bytes of padding to resource data block for {file_end_alignment}-byte alignment")

            print(f"\nFinal structure:")
            print(f"  Header + TOC size: {header_size} (0x{header_size:X})")
            print(f"  Main data size: {len(new_file_data)} (0x{len(new_file_data):X})")
            print(f"  Resource data offset: {new_resource_block_offset} (0x{new_resource_block_offset:X})")
            print(f"  Resource data size: {len(new_resource_data)} (0x{len(new_resource_data):X})")
            print(f"  Total file size: {header_size + len(new_file_data) + len(new_resource_data)} bytes")
            print(f"\n✓ Rebuild complete with proper alignment and validation\n")

            # Write new BDG file
            with open(output_bdg_path, 'wb') as f:
                f.write(header_and_toc)
                f.write(new_file_data)
                f.write(new_resource_data)

            return True

        except Exception as e:
            print(f"Error rebuilding BDG: {e}")
            import traceback
            traceback.print_exc()
            return False

    def rebuild_vol(self, output_vol_path, file_entries, replacement_dir):
        """Rebuild VOL file with replaced files"""
        try:
            # VOL files are simple: no alignment, no resource files, no size restrictions
            new_data = bytearray()

            # Get all files
            all_files = self.parse()

            print(f"\nRebuilding VOL with {len(all_files)} files...")

            # Collect file data and track offsets
            file_data_list = []
            total_size = 0

            for entry in all_files:
                # Look for replacement file
                replacement_path, actual_name = self.find_replacement_file(replacement_dir, entry['name'])

                if replacement_path:
                    file_data = self.read_replacement_file(replacement_path)
                    size_changed = len(file_data) != entry['size']

                    file_info = entry['name']
                    if actual_name != entry['name']:
                        file_info = f"{entry['name']} → {actual_name}"

                    status = "replacement" if size_changed else "replacement (same size)"
                    print(f"  File {entry['file_num']} ({file_info}): {status}, size {len(file_data)}")
                else:
                    file_data = self.read_bytes(entry['offset'], entry['size'])
                    print(f"  File {entry['file_num']} ({entry['name']}): Using original, size {len(file_data)}")

                file_data_list.append({
                    'data': file_data,
                    'name': entry['name'],
                    'file_id': entry.get('file_id', entry['file_num'])
                })
                total_size += len(file_data)

            # Calculate offsets
            header_size = 20
            toc_size = len(file_data_list) * 0xC
            data_start = header_size + toc_size

            # Build header
            new_data.extend(b'PVOL')
            new_data.extend(struct.pack('<I', 0))  # Unknown field
            new_data.extend(struct.pack('<I', len(file_data_list)))  # File count
            new_data.extend(struct.pack('<I', data_start))  # Data start offset
            new_data.extend(struct.pack('<I', 0))  # Padding/unknown

            # Build TOC
            current_offset = data_start
            for file_info in file_data_list:
                new_data.extend(struct.pack('<I', current_offset))  # Offset
                new_data.extend(struct.pack('<I', len(file_info['data'])))  # Size
                new_data.extend(struct.pack('<I', file_info['file_id']))  # File ID
                current_offset += len(file_info['data'])

            # Add file data
            for file_info in file_data_list:
                new_data.extend(file_info['data'])

            # Add string table
            for file_info in file_data_list:
                new_data.extend(file_info['name'].encode('ascii'))
                new_data.extend(b'\x00')  # Null terminator

            # Write output file
            with open(output_vol_path, 'wb') as f:
                f.write(new_data)

            print(f"\nSuccessfully rebuilt VOL: {output_vol_path}")
            print(f"Total size: {len(new_data)} bytes ({len(file_data_list)} files)")
            return True

        except Exception as e:
            print(f"Error rebuilding VOL: {e}")
            import traceback
            traceback.print_exc()
            return False


class ExtractWindow:
    FILE_TYPE_NAMES = {
        0: "Static Mesh",
        1: "Skeleton",
        2: "Interface (GSTE), IFL File, Lighting, MonsterData, LevelData, CityData, NeoSkyData",
        3: "Skeleton, Camera",
        4: "Animation, Skeleton, Camera",
        6: "Material",
        9: "Texture",
        13: "Palette",
        16: "PWK File",
        17: "Rigged Mesh",
        20: "Particle",
        21: "Camera, Path",
        22: "PRX File",
        23: "Localization",
        24: "Archive",
        25: "Audio",
        26: "BDP File",
        27: "Video"
    }

    def __init__(self, parent, file_entries, parser, output_text_callback):
        self.file_entries = file_entries
        self.parser = parser
        self.output_text_callback = output_text_callback

        self.window = tk.Toplevel(parent)
        self.window.title("Extract Files")
        self.window.geometry("700x700")
        self.window.transient(parent)
        # Remove grab_set() to allow non-modal behavior

        # Bring window to front when clicked
        self.window.bind("<FocusIn>", lambda e: self.window.lift())

        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Instructions and status
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 5))

        label = ttk.Label(top_frame, text="Select files to extract (click category to expand):")
        label.pack(side=tk.LEFT)

        total_files = len(file_entries)
        self.status_label = ttk.Label(top_frame, text=f"0 / {total_files} files selected")
        self.status_label.pack(side=tk.RIGHT)
        self.total_files = total_files

        # Create scrollable frame for categories
        scroll_container = ttk.Frame(main_frame)
        scroll_container.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(scroll_container, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        canvas = tk.Canvas(scroll_container, yscrollcommand=scrollbar.set, bg='white', highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=canvas.yview)

        # Create inner frame for content
        scrollable_frame = ttk.Frame(canvas)
        canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(canvas_frame, width=event.width)

        scrollable_frame.bind("<Configure>", on_frame_configure)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_frame, width=e.width))

        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def on_mousewheel_linux(event):
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")

        # Bind mouse wheel events
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        canvas.bind_all("<Button-4>", on_mousewheel_linux)
        canvas.bind_all("<Button-5>", on_mousewheel_linux)

        # Cleanup bindings when dialog closes
        def cleanup_bindings():
            try:
                canvas.unbind_all("<MouseWheel>")
                canvas.unbind_all("<Button-4>")
                canvas.unbind_all("<Button-5>")
            except:
                pass

        self.cleanup_bindings = cleanup_bindings
        self.window.protocol("WM_DELETE_WINDOW", lambda: (cleanup_bindings(), self.window.destroy()))

        # Group files by type
        self.files_by_type = {}
        for entry in file_entries:
            file_type = entry.get('file_type', 0)
            if file_type not in self.files_by_type:
                self.files_by_type[file_type] = []
            self.files_by_type[file_type].append(entry)

        # Store checkboxes and category state
        self.check_vars = {}
        self.category_vars = {}
        self.category_expanded = {}
        self.category_frames = {}
        self.category_content_frames = {}

        # Create collapsible sections for each file type
        for file_type in sorted(self.files_by_type.keys()):
            entries = self.files_by_type[file_type]
            type_name = self.FILE_TYPE_NAMES.get(file_type, f"Unknown Type {file_type}")

            # Category container
            category_container = ttk.Frame(scrollable_frame)
            category_container.pack(fill=tk.X, padx=5, pady=2)

            # Header frame (clickable to expand/collapse)
            header_frame = ttk.Frame(category_container, relief=tk.RAISED, borderwidth=1)
            header_frame.pack(fill=tk.X)

            # Track expansion state
            self.category_expanded[file_type] = False

            # Arrow and label
            arrow_label = ttk.Label(header_frame, text="▶", width=2)
            arrow_label.pack(side=tk.LEFT, padx=(5, 0))

            title_label = ttk.Label(header_frame, text=f"Type {file_type}: {type_name} ({len(entries)} files)")
            title_label.pack(side=tk.LEFT, pady=5)

            # Category select all checkbox
            category_var = tk.BooleanVar(value=False)
            self.category_vars[file_type] = category_var

            # Content frame (hidden by default)
            content_frame = ttk.Frame(category_container)
            self.category_content_frames[file_type] = content_frame
            self.category_frames[file_type] = {
                'arrow': arrow_label,
                'content': content_frame,
                'loaded': False
            }

            # Make header clickable
            def make_toggle(ft, arrow, content):
                def toggle(event=None):
                    self.toggle_category_expand(ft, arrow, content)
                return toggle

            toggle_func = make_toggle(file_type, arrow_label, content_frame)
            header_frame.bind("<Button-1>", toggle_func)
            arrow_label.bind("<Button-1>", toggle_func)
            title_label.bind("<Button-1>", toggle_func)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        # Left side buttons
        expand_all_btn = ttk.Button(button_frame, text="Expand All", command=self.expand_all)
        expand_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        collapse_all_btn = ttk.Button(button_frame, text="Collapse All", command=self.collapse_all)
        collapse_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        select_all_btn = ttk.Button(button_frame, text="Select All", command=self.select_all)
        select_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        deselect_all_btn = ttk.Button(button_frame, text="Deselect All", command=self.deselect_all)
        deselect_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        # Right side button
        extract_btn = ttk.Button(button_frame, text="Extract Selected", command=self.extract)
        extract_btn.pack(side=tk.RIGHT, padx=(5, 0))

    def toggle_category_expand(self, file_type, arrow_label, content_frame):
        """Expand or collapse a category"""
        is_expanded = self.category_expanded[file_type]

        if is_expanded:
            # Collapse
            content_frame.pack_forget()
            arrow_label.config(text="▶")
            self.category_expanded[file_type] = False
        else:
            # Expand
            content_frame.pack(fill=tk.X, padx=10, pady=5)
            arrow_label.config(text="▼")
            self.category_expanded[file_type] = True

            # Lazy load checkboxes if not already loaded
            if not self.category_frames[file_type]['loaded']:
                self.load_category_files(file_type, content_frame)
                self.category_frames[file_type]['loaded'] = True

    def load_category_files(self, file_type, content_frame):
        """Lazy load file checkboxes for a category"""
        entries = self.files_by_type[file_type]

        # Select all checkbox
        category_var = self.category_vars[file_type]
        category_cb = ttk.Checkbutton(
            content_frame,
            text="Select All in Category",
            variable=category_var,
            command=lambda: self.toggle_category_selection(file_type)
        )
        category_cb.pack(anchor=tk.W, pady=(0, 5))

        # Initialize check_vars dict for this category
        if file_type not in self.check_vars:
            self.check_vars[file_type] = []

        # Individual file checkboxes
        for entry in entries:
            var = tk.BooleanVar(value=False)
            var.trace_add('write', lambda *args: self.update_selection_count())
            self.check_vars[file_type].append((var, entry))

            # Extract just filename without folder
            display_name = entry['name'].split('/')[-1] if '/' in entry['name'] else entry['name']

            cb = ttk.Checkbutton(
                content_frame,
                text=f"  {display_name} ({entry['size']} bytes)",
                variable=var
            )
            cb.pack(anchor=tk.W, pady=1)

    def update_selection_count(self):
        """Update the status label with current selection count"""
        count = 0
        for file_type in self.check_vars:
            for var, entry in self.check_vars[file_type]:
                if var.get():
                    count += 1
        self.status_label.config(text=f"{count} / {self.total_files} files selected")

    def toggle_category_selection(self, file_type):
        """Toggle all files in a category"""
        state = self.category_vars[file_type].get()
        if file_type in self.check_vars:
            for var, entry in self.check_vars[file_type]:
                var.set(state)

    def expand_all(self):
        """Expand all categories"""
        for file_type in self.category_frames:
            if not self.category_expanded[file_type]:
                arrow = self.category_frames[file_type]['arrow']
                content = self.category_frames[file_type]['content']
                self.toggle_category_expand(file_type, arrow, content)

    def collapse_all(self):
        """Collapse all categories"""
        for file_type in self.category_frames:
            if self.category_expanded[file_type]:
                arrow = self.category_frames[file_type]['arrow']
                content = self.category_frames[file_type]['content']
                self.toggle_category_expand(file_type, arrow, content)

    def select_all(self):
        """Select all files in all categories"""
        # First expand all categories to load checkboxes
        self.expand_all()
        # Then select all
        for file_type in self.category_vars:
            self.category_vars[file_type].set(True)
            if file_type in self.check_vars:
                for var, entry in self.check_vars[file_type]:
                    var.set(True)

    def deselect_all(self):
        """Deselect all files in all categories"""
        for file_type in self.category_vars:
            self.category_vars[file_type].set(False)
            if file_type in self.check_vars:
                for var, entry in self.check_vars[file_type]:
                    var.set(False)

    def extract(self):
        """Extract selected files"""
        selected_files = []
        for file_type in self.check_vars:
            for var, entry in self.check_vars[file_type]:
                if var.get():
                    selected_files.append(entry)

        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to extract.")
            return

        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return

        # Extract files
        success_count = 0
        fail_count = 0

        for entry in selected_files:
            if self.parser.extract_file(entry, output_dir):
                success_count += 1
            else:
                fail_count += 1

        # Show results
        message = f"Extraction complete!\n\nSuccessful: {success_count}\nFailed: {fail_count}"
        messagebox.showinfo("Extraction Complete", message)

        # Update main window output
        self.output_text_callback(f"\n{message}\n")
        self.output_text_callback(f"Files extracted to: {output_dir}\n")

    def destroy(self):
        """Clean up and destroy window"""
        self.cleanup_bindings()
        self.window.destroy()


class RebuildWindow:
    def __init__(self, parent, parsed_files, parser, output_text_callback):
        self.parsed_files = parsed_files
        self.parser = parser
        self.output_text_callback = output_text_callback

        self.window = tk.Toplevel(parent)
        self.window.title("Rebuild Bundle")
        self.window.geometry("700x500")
        self.window.transient(parent)

        # Bring window to front when clicked
        self.window.bind("<FocusIn>", lambda e: self.window.lift())

        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Instructions
        instructions = ttk.Label(main_frame, text="Select the directory containing replacement files and output location:")
        instructions.pack(anchor=tk.W, pady=(0, 10))

        # Replacement directory section
        repl_frame = ttk.LabelFrame(main_frame, text="Replacement Files Directory", padding="5")
        repl_frame.pack(fill=tk.X, pady=(0, 10))
        repl_frame.columnconfigure(0, weight=1)

        self.repl_dir_var = tk.StringVar()
        repl_entry = ttk.Entry(repl_frame, textvariable=self.repl_dir_var, state='readonly')
        repl_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        repl_browse_btn = ttk.Button(repl_frame, text="Browse", command=self.browse_replacement_dir)
        repl_browse_btn.grid(row=0, column=1)

        # Output file section
        output_frame = ttk.LabelFrame(main_frame, text="Output Bundle File", padding="5")
        output_frame.pack(fill=tk.X, pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)

        self.output_file_var = tk.StringVar()
        self.output_file_var.trace_add('write', lambda *args: self.update_alignments_on_file_change())
        output_entry = ttk.Entry(output_frame, textvariable=self.output_file_var, state='readonly')
        output_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        output_browse_btn = ttk.Button(output_frame, text="Browse", command=self.browse_output_file)
        output_browse_btn.grid(row=0, column=1)

        # Create two-column layout: alignment controls on left, status on right
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        content_frame.columnconfigure(0, weight=0)  # Alignment controls - fixed width
        content_frame.columnconfigure(1, weight=1)  # Status - expandable
        content_frame.rowconfigure(0, weight=1)

        # Left side: Block Alignment controls
        alignment_frame = ttk.LabelFrame(content_frame, text="Block Alignment", padding="10")
        alignment_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W), padx=(0, 10))

        # Alignment options
        alignment_values = [16, 32, 64, 128, 256, 512, 1024, 2048]

        # File type labels and their IDs
        file_types = [
            ("Static Mesh", 0),
            ("Material", 6),
            ("Texture", 9),
            ("Palette", 13),
            ("Rigged Mesh", 17),
            ("Particle", 20)
        ]

        # Store dropdown variables and widgets
        self.alignment_vars = {}
        self.alignment_dropdowns = {}

        # Create dropdowns for each file type
        for idx, (type_name, type_id) in enumerate(file_types):
            # Label
            label = ttk.Label(alignment_frame, text=type_name, width=15, anchor='w')
            label.grid(row=idx, column=0, sticky=tk.W, pady=3, padx=(0, 10))

            # Dropdown - initially show N/A
            var = tk.StringVar(value='N/A')
            self.alignment_vars[type_id] = var
            dropdown = ttk.Combobox(
                alignment_frame,
                textvariable=var,
                values=['N/A'],
                state='disabled',
                width=8
            )
            dropdown.grid(row=idx, column=1, sticky=tk.W, pady=3)
            self.alignment_dropdowns[type_id] = dropdown

        # Add separator line and extension detected label
        separator_frame = ttk.Frame(alignment_frame, height=2, relief=tk.SUNKEN)
        separator_frame.grid(row=len(file_types), column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 5))

        self.extension_label = ttk.Label(alignment_frame, text="", foreground='red', font=('TkDefaultFont', 9))
        self.extension_label.grid(row=len(file_types) + 1, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))

        # Right side: Status section
        status_frame = ttk.LabelFrame(content_frame, text="Status", padding="5")
        status_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)

        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            wrap=tk.WORD,
            width=50,
            height=15,
            font=('Consolas', 9)
        )
        self.status_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        self.rebuild_btn = ttk.Button(button_frame, text="Rebuild Bundle", command=self.rebuild)
        self.rebuild_btn.pack(side=tk.RIGHT)

    def set_default_alignments(self):
        """Set default alignment values based on file extension"""
        # Detect file type from parser
        filepath = self.parser.filepath.lower()

        if filepath.endswith(".cmg"):
            # CMG-specific (DAMM)
            defaults = {
                0: 64,    # Static Mesh
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 64,   # Rigged Mesh
                20: 16,   # Particle
            }
        elif filepath.endswith(('.cmp', '.bdp', '.clp')):
            # PS2 Specific (CMP/BDP/CLP)
            defaults = {
                0: 128,   # Static Mesh
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 128,  # Rigged Mesh
                20: 16,   # Particle
            }
        else:
            # BDG / UNLEASHED (WII)
            defaults = {
                0: 512,   # Static Mesh
                6: 16,    # Material
                9: 128,   # Texture
                13: 16,   # Palette
                17: 512,  # Rigged Mesh
                20: 16,   # Particle
            }

        # Set the values
        for type_id, value in defaults.items():
            if type_id in self.alignment_vars:
                self.alignment_vars[type_id].set(value)

    def update_alignments_on_file_change(self):
        """Update alignment defaults when output file extension changes"""
        output_path = self.output_file_var.get()
        if not output_path:
            # Reset to N/A if no file selected
            for type_id in self.alignment_vars:
                self.alignment_vars[type_id].set('N/A')
                self.alignment_dropdowns[type_id].config(state='disabled', values=['N/A'])
            self.extension_label.config(text="")
            return

        filepath_lower = output_path.lower()

        # Detect extension
        ext = os.path.splitext(output_path)[1].upper().lstrip('.')
        if ext:
            self.extension_label.config(text=f".{ext} Detected")
        else:
            self.extension_label.config(text="")

        # Determine alignment values based on extension
        alignment_values = [16, 32, 64, 128, 256, 512, 1024, 2048]

        if filepath_lower.endswith(".cmg"):
            # CMG-specific (DAMM)
            defaults = {
                0: 64,    # Static Mesh
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 64,   # Rigged Mesh
                20: 16,   # Particle
            }
        elif filepath_lower.endswith(('.cmp', '.bdp', '.clp')):
            # PS2 Specific (CMP/BDP/CLP)
            defaults = {
                0: 128,   # Static Mesh
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 128,  # Rigged Mesh
                20: 16,   # Particle
            }
        else:
            # BDG / UNLEASHED (WII)
            defaults = {
                0: 512,   # Static Mesh
                6: 16,    # Material
                9: 128,   # Texture
                13: 16,   # Palette
                17: 512,  # Rigged Mesh
                20: 16,   # Particle
            }

        # Update the dropdown values and enable them
        for type_id, value in defaults.items():
            if type_id in self.alignment_vars:
                self.alignment_dropdowns[type_id].config(state='readonly', values=alignment_values)
                self.alignment_vars[type_id].set(value)

    def browse_replacement_dir(self):
        """Browse for replacement files directory"""
        directory = filedialog.askdirectory(title="Select Directory with Replacement Files")
        if directory:
            self.repl_dir_var.set(directory)
            self.status_text.insert(tk.END, f"Replacement directory: {directory}\n")

    def browse_output_file(self):
        """Browse for output bundle file location"""
        filepath = filedialog.asksaveasfilename(
            title="Save Rebuilt Bundle As",
            defaultextension=".BDG",
            filetypes=[
                ("Bundle Files", "*.BDG *.cmg *.cmp *.clp *.bdp"),
                ("BDG Files", "*.BDG"),
                ("CMG Files", "*.cmg"),
                ("CMP Files", "*.cmp"),
                ("CLP Files", "*.clp"),
                ("BDP Files", "*.bdp"),
                ("All Files", "*.*")
            ]
        )
        if filepath:
            self.output_file_var.set(filepath)
            self.status_text.insert(tk.END, f"Output file: {filepath}\n")

    def rebuild(self):
        """Perform the rebuild operation"""
        replacement_dir = self.repl_dir_var.get()
        output_path = self.output_file_var.get()

        if not replacement_dir:
            messagebox.showwarning("Missing Input", "Please select a replacement files directory.")
            return

        if not output_path:
            messagebox.showwarning("Missing Input", "Please select an output file location.")
            return

        # Get custom alignment values from dropdowns
        custom_alignments = {}
        for type_id, var in self.alignment_vars.items():
            value = var.get()
            if value != 'N/A':  # Only set if a value was selected
                try:
                    custom_alignments[type_id] = int(value)
                except ValueError:
                    pass  # Skip invalid values

        # Log alignment settings
        self.status_text.insert(tk.END, "\nBlock Alignment Settings:\n")
        type_names = {0: "Static Mesh", 6: "Material", 9: "Texture", 13: "Palette", 17: "Rigged Mesh", 20: "Particle"}
        for type_id, alignment in sorted(custom_alignments.items()):
            self.status_text.insert(tk.END, f"  {type_names.get(type_id, f'Type {type_id}')}: {alignment} bytes\n")
        self.status_text.insert(tk.END, "\n")

        # Perform rebuild
        self.status_text.insert(tk.END, "Rebuilding bundle file...\n")
        self.status_text.update()

        # Dispatch to appropriate rebuild method based on bundle type
        if self.parser.bundle_type == 'vol':
            success = self.parser.rebuild_vol(output_path, self.parsed_files, replacement_dir)
        else:
            # Pass custom alignments to rebuild function
            success = self.parser.rebuild_bdg(output_path, self.parsed_files, replacement_dir, custom_alignments)

        if success:
            messagebox.showinfo("Success", f"Bundle file rebuilt successfully!\n\nSaved to: {output_path}")
            self.status_text.insert(tk.END, f"✓ Bundle rebuilt successfully!\n")
            self.output_text_callback(f"\nBundle rebuilt successfully: {output_path}\n")
        else:
            messagebox.showerror("Error", "Failed to rebuild bundle file. Check console for errors.")
            self.status_text.insert(tk.END, "✗ Failed to rebuild bundle file.\n")
            self.output_text_callback("Failed to rebuild bundle file.\n")

    def destroy(self):
        """Destroy window"""
        self.window.destroy()


class PipeworksGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GZBuildr - Bundle Manager")
        self.root.geometry("800x600")

        self.parser = None
        self.parsed_files = []
        self.child_windows = []  # Track all child windows

        # Set up main window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_main_window_close)

        # Bring main window to front when clicked
        self.root.bind("<FocusIn>", lambda e: self.root.lift())

        # Configure style
        style = ttk.Style()
        style.theme_use('clam')

        # Main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        # File input section
        input_frame = ttk.LabelFrame(main_frame, text="Input File", padding="5")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(input_frame, textvariable=self.file_path_var)
        self.file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        # Make entry look readonly but still accept drag-and-drop
        self.file_entry.configure(state='readonly')

        browse_btn = ttk.Button(input_frame, text="Browse", command=self.browse_file)
        browse_btn.grid(row=0, column=1)

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, pady=(0, 10))

        parse_btn = ttk.Button(button_frame, text="Parse File", command=self.parse_file)
        parse_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.extract_btn = ttk.Button(button_frame, text="Extract", command=self.extract_files, state=tk.DISABLED)
        self.extract_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.rebuild_btn = ttk.Button(button_frame, text="Rebuild", command=self.rebuild_bdg, state=tk.DISABLED)
        self.rebuild_btn.pack(side=tk.LEFT)

        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        # Output text area with scrollbar
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.NONE,
            width=80,
            height=25,
            font=('Consolas', 9)
        )
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Enable drag and drop (must be after output_text is created)
        self.setup_drag_drop()

    def setup_drag_drop(self):
        """Setup drag and drop functionality for the file entry"""
        if HAS_DND:
            # Using tkinterdnd2
            try:
                self.file_entry.drop_target_register(DND_FILES)
                self.file_entry.dnd_bind('<<Drop>>', self.on_drop_tkdnd)
                self.output_text.insert(tk.END, "Drag-and-drop enabled\n")
                print("Drag-and-drop enabled (tkinterdnd2)")
            except Exception as e:
                self.output_text.insert(tk.END, f"Failed to setup drag-and-drop: {e}\n")
                print(f"Failed to setup drag-and-drop: {e}")
        else:
            # Show message that drag-and-drop is not available
            self.output_text.insert(tk.END, "\nDrag-and-drop not available.\n")
            self.output_text.insert(tk.END, "To enable, install: pip install tkinterdnd2\n\n")
            print("\nDrag-and-drop not available.")
            print("To enable, install: pip install tkinterdnd2")

    def on_drop_tkdnd(self, event):
        """Handle file drop event from tkinterdnd2"""
        try:
            # Get the file path from the event
            files = event.data

            # Handle different drop data formats
            if isinstance(files, str):
                # Parse the file path - tkinterdnd2 returns paths in curly braces
                filepath = files.strip()

                # Handle multiple files (space-separated, each in braces)
                # Example: "{C:/path/file1.bdg} {C:/path/file2.bdg}"
                if filepath.startswith('{'):
                    # Extract first file from braces
                    end_brace = filepath.find('}')
                    if end_brace > 0:
                        filepath = filepath[1:end_brace]
                    else:
                        filepath = filepath[1:]  # Remove leading brace only

                # Normalize path separators and resolve any path issues
                filepath = os.path.normpath(filepath)

                # Remove any remaining curly braces
                filepath = filepath.replace('{', '').replace('}', '')

            else:
                return

            # Verify it's a valid file
            if os.path.isfile(filepath):
                # Temporarily enable entry to update value
                self.file_entry.configure(state='normal')
                self.file_path_var.set(filepath)
                self.file_entry.configure(state='readonly')
                self.output_text.insert(tk.END, f"File loaded via drag-drop: {filepath}\n")
                print(f"File dropped: {filepath}")
            else:
                self.output_text.insert(tk.END, f"Invalid file path: {filepath}\n")
                print(f"Invalid file path from drop: {filepath}")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error handling drop: {e}\n")
            print(f"Error handling drop: {e}")
            import traceback
            traceback.print_exc()

    def browse_file(self):
        """Open file dialog to select a file"""
        filename = filedialog.askopenfilename(
            title="Select Bundle File",
            filetypes=[
                ("Bundle Files", "*.BDG *.cmg *.cmp *.clp *.bdp"),
                ("BDG Files", "*.BDG"),
                ("CMG Files", "*.cmg"),
                ("CMP Files", "*.cmp"),
                ("CLP Files", "*.clp"),
                ("BDP Files", "*.bdp"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.file_path_var.set(filename)

    def parse_file(self):
        """Parse the selected file and display results"""
        filepath = self.file_path_var.get()

        if not filepath:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "Please select a file first.\n")
            return

        if not os.path.exists(filepath):
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "File does not exist.\n")
            return

        # Clear output
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Parsing: {os.path.basename(filepath)}\n")

        # Add warning for .cmp files
        if filepath.lower().endswith(('.cmp', '.clp', '.bdp')):
            self.output_text.insert(tk.END, "\n⚠ WARNING: If modding Save The Earth, STE's engine has a limit of 2,130KB. \n[Unleashed PS2 does NOT have this limit.] \n")

        if filepath.lower().endswith('.vol'):
            self.output_text.insert(tk.END, "\n⚠ WARNING: Unfortunately, .VOL support is experimental and does not function correctly.\n")

        self.output_text.insert(tk.END, "=" * 80 + "\n\n")

        # Parse file
        self.parser = PipeworksParser(filepath)
        results = self.parser.parse()

        # Display results
        if results and "error" in results[0]:
            self.output_text.insert(tk.END, results[0]["error"] + "\n")
            self.parsed_files = []
            self.extract_btn.config(state=tk.DISABLED)
            self.rebuild_btn.config(state=tk.DISABLED)
        else:
            self.parsed_files = results

            # Header
            header = f"{'File #':<8} {'File Name':<40} {'Offset':<12} {'Size':<12}\n"
            separator = "-" * 80 + "\n"
            self.output_text.insert(tk.END, header)
            self.output_text.insert(tk.END, separator)

            # Data rows
            for entry in results:
                file_num = entry['file_num']
                name = entry['name']
                offset = entry['offset']
                size = entry['size']

                row = f"{file_num:<8} {name:<40} {offset:<12} {size:<12}\n"
                self.output_text.insert(tk.END, row)

            self.output_text.insert(tk.END, "\n")
            self.output_text.insert(tk.END, f"Total entries: {len(results)}\n")

            # Enable extract and rebuild buttons
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)

    def extract_files(self):
        """Open extraction window"""
        if not self.parsed_files or not self.parser:
            messagebox.showwarning("No Data", "Please parse a file first.")
            return

        # Create callback for window to update main output
        def output_callback(text):
            self.output_text.insert(tk.END, text)

        # Create non-modal extract window
        window = ExtractWindow(self.root, self.parsed_files, self.parser, output_callback)
        self.child_windows.append(window.window)

        # Remove from list when window is closed
        def on_window_close():
            if window.window in self.child_windows:
                self.child_windows.remove(window.window)
            window.destroy()

        window.window.protocol("WM_DELETE_WINDOW", on_window_close)

    def rebuild_bdg(self):
        """Open rebuild window"""
        if not self.parsed_files or not self.parser:
            messagebox.showwarning("No Data", "Please parse a file first.")
            return

        # Create callback for window to update main output
        def output_callback(text):
            self.output_text.insert(tk.END, text)

        # Create non-modal rebuild window
        window = RebuildWindow(self.root, self.parsed_files, self.parser, output_callback)
        self.child_windows.append(window.window)

        # Remove from list when window is closed
        def on_window_close():
            if window.window in self.child_windows:
                self.child_windows.remove(window.window)
            window.destroy()

        window.window.protocol("WM_DELETE_WINDOW", on_window_close)

    def on_main_window_close(self):
        """Close all child windows when main window closes"""
        # Close all child windows
        for window in self.child_windows[:]:  # Use slice to iterate over copy
            try:
                window.destroy()
            except:
                pass
        # Close main window
        self.root.destroy()


def main():
    # Use TkinterDnD.Tk if available for drag-and-drop support
    if HAS_DND:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    app = PipeworksGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
