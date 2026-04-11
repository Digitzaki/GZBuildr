"""
Pipeworks Bundle Parser
- Developed by Digitzaki
A GUI tool for parsing, extracting, and rebuilding GameCube/PS2 bundle files.

Features:
- Parse BDG/CMG/CMP/BDL/VOL bundle files and display contents
- Extract individual files by type
- Rebuild BDG/CMG/CMP/BDL/VOL files with modified content
- Drag-and-drop support
- Supports Pipeworks format (BDG/CMG/CMP/CLP/BDP/BDL) and .VOL format (experimental)
- Block size alignment restrictions, adjustable during rebuild.

To enable drag-and-drop functionality, install:
    pip install tkinterdnd2

If not installed, you can still use the Browse button to select files.
"""
import ctypes

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-monitor DPI aware
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

import struct
import os
import shutil


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
        """Parse Pipeworks bundle file (BDG/CMG/BDL/CMP)"""
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
        """Parse VOL bundle file (PS2 format) - based on VOL_Extract.BMS"""
        results = []

        try:
            # VOL files are always little-endian (PS2)
            self.is_big_endian = False

            # Read 16-byte header (matching BMS script exactly)
            # 0x00-03: Magic "PVOL"
            # 0x04-07: UNK
            # 0x08-0B: FILES count
            # 0x0C-0F: DATASTART (in BMS, but value meaning unclear)
            unk = struct.unpack('<I', self.file_data[4:8])[0]
            self.file_count = struct.unpack('<I', self.file_data[8:12])[0]
            datastart_field = struct.unpack('<I', self.file_data[12:16])[0]

            # Calculate string table offset (matching BMS exactly)
            # BMS formula: NAMEOFF = (0xC * FILES) + (4 * FILES) + 20
            # This accounts for: 16-byte header + TOC (12 bytes per file) + extra data (4 bytes per file) + 4 bytes
            self.string_offset = (12 * self.file_count) + (4 * self.file_count) + 20

            print(f"\n=== VOL Header ===")
            print(f"File count: {self.file_count}")
            print(f"DATASTART field: 0x{datastart_field:08X} ({datastart_field})")
            print(f"String table offset (calculated): 0x{self.string_offset:08X} ({self.string_offset})")

            # Start parsing TOC at offset 16 (after 16-byte header)
            toc_offset = 16

            # Read TOC entries (matching BMS exactly: OFFSET, SIZE, FID)
            toc_entries = []
            for i in range(self.file_count):
                entry_offset = toc_offset + (i * 0xC)

                file_offset = struct.unpack('<I', self.file_data[entry_offset:entry_offset + 4])[0]
                size = struct.unpack('<I', self.file_data[entry_offset + 4:entry_offset + 8])[0]
                file_id = struct.unpack('<I', self.file_data[entry_offset + 8:entry_offset + 12])[0]

                toc_entries.append({
                    'offset': file_offset,
                    'size': size,
                    'file_id': file_id,
                    'toc_entry_offset': entry_offset,
                    'raw_offset': file_offset
                })

            # Read file names from string table
            name_offset = self.string_offset
            for i, entry in enumerate(toc_entries):
                # Read null-terminated string
                name_end = name_offset
                while name_end < len(self.file_data) and self.file_data[name_end] != 0:
                    name_end += 1

                raw_name = self.file_data[name_offset:name_end].decode('ascii', errors='ignore')

                # Detect file type from extension
                file_type = self.detect_file_type_from_extension(raw_name)

                # Create folder-based structure for VOL files
                # Extract folder path and filename from the original name
                if '/' in raw_name or '\\' in raw_name:
                    # Already has folder structure
                    folder_name = raw_name.replace('\\', '/')
                else:
                    # Group by extension for flat files
                    ext = raw_name.split('.')[-1].upper() if '.' in raw_name else 'MISC'
                    folder_name = f"{ext}/{raw_name}"

                results.append({
                    "file_num": i,
                    "name": folder_name,
                    "offset": entry['offset'],  # Absolute offset for extraction
                    "size": entry['size'],
                    "raw_offset": entry['raw_offset'],  # Relative offset for rebuild
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
        Find replacement file with exact filename match (ignoring folder prefixes).

        NOTE: CMG files are bundle containers (same as BDG), not mesh files.
        They should not be replaced with .mesh files or vice versa.
        Returns (filepath, actual_name) if found, or (None, None) if not found.
        """
        # Extract basename for matching (ignore folder prefixes like "2/MONSTER_DATA0" -> "MONSTER_DATA0")
        basename = os.path.basename(original_name)

        # First, look for exact filename match including folders
        original_path = os.path.join(replacement_dir, original_name)
        if os.path.exists(original_path):
            return original_path, original_name

        # Second, look for basename match in root directory
        basename_path = os.path.join(replacement_dir, basename)
        if os.path.exists(basename_path):
            return basename_path, original_name

        # Third, search in subdirectories for basename match
        try:
            for item in os.listdir(replacement_dir):
                item_path = os.path.join(replacement_dir, item)
                if os.path.isdir(item_path):
                    subdir_file_path = os.path.join(item_path, basename)
                    if os.path.exists(subdir_file_path):
                        return subdir_file_path, original_name
        except (OSError, PermissionError):
            pass

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
        is_bdl = self.filepath.lower().endswith(".bdl")

        if is_cmg or is_bdl:
            # CMG/BDL-specific (DAMM/GameCube)
            type_alignments = {
                0: 64,    # Static Mesh
                2: 16,    # MONSTER_DATA (Stats/Config)
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

            # Build a map of file_num to actual file data (for files referenced by multiple TOC entries)
            # This handles cases where multiple TOC entries point to the same file_num
            file_data_map = {}
            for entry in all_files:
                file_num = entry['file_num']
                if file_num not in file_data_map:
                    file_data_map[file_num] = {'main': None, 'resource': None}

                if entry['is_resource']:
                    # Keep entry with largest size (handles dummy entries with size=0)
                    if file_data_map[file_num]['resource'] is None or entry['size'] > file_data_map[file_num]['resource']['size']:
                        file_data_map[file_num]['resource'] = entry
                else:
                    # Keep entry with largest size (handles dummy entries with size=0)
                    if file_data_map[file_num]['main'] is None or entry['size'] > file_data_map[file_num]['main']['size']:
                        file_data_map[file_num]['main'] = entry

            # Get all TOC entries in order (main files only, as they contain TOC offset info)
            toc_entries = sorted([f for f in all_files if not f['is_resource']], key=lambda x: x['toc_entry_offset'])

            # Keep header and TOC structure
            header_size = self.main_data_offset
            header_and_toc = new_data[:header_size]

            # Build new data sections
            new_file_data = bytearray()
            new_resource_data = bytearray()

            # Determine endianness format
            endian = '>' if self.is_big_endian else '<'

            # Track data that has already been written (to avoid writing duplicate file_num data multiple times)
            written_file_data = {}  # file_num -> {'main_offset': ..., 'main_size': ..., 'res_offset': ..., 'res_size': ...}

            # Process ALL TOC entries in order
            print(f"\nRebuilding {len(toc_entries)} TOC entries (referencing {len(file_data_map)} unique files)...")
            for toc_entry in toc_entries:
                file_num = toc_entry['file_num']
                toc_offset = toc_entry['toc_entry_offset']

                # Get the actual file data for this file_num
                file_info = file_data_map.get(file_num, {'main': None, 'resource': None})

                # Check if we've already written this file_num's data
                if file_num in written_file_data:
                    # Reuse offsets from when we first wrote this file_num
                    cached = written_file_data[file_num]
                    main_offset = cached['main_offset']
                    main_size = cached['main_size']
                    res_offset = cached['res_offset']
                    res_size = cached['res_size']

                    print(f"  TOC entry at 0x{toc_offset:X} (file_num={file_num}): Reusing previously written data")
                else:
                    # First time seeing this file_num, process and write the file data
                    main_offset = 0
                    main_size = 0
                    if file_info['main']:
                        entry = file_info['main']

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
                    if file_info['resource']:
                        entry = file_info['resource']

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

                    # Cache the written data for this file_num
                    written_file_data[file_num] = {
                        'main_offset': main_offset,
                        'main_size': main_size,
                        'res_offset': res_offset,
                        'res_size': res_size
                    }

                # Write TOC entry (whether new data or cached)
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
        """Rebuild VOL file with replaced files - based on VOL_Extract.BMS structure"""
        try:
            # Get all files
            all_files = self.parse()

            print(f"\nRebuilding VOL with {len(all_files)} files...")

            # Collect file data and track info
            file_data_list = []

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

                # Strip folder prefix from name when storing in VOL
                # VOL stores just the filename, not the folder structure we added
                original_name = entry['name']
                if '/' in original_name:
                    # Get just the filename part
                    stored_name = original_name.split('/')[-1]
                else:
                    stored_name = original_name

                file_data_list.append({
                    'data': file_data,
                    'name': stored_name,
                    'file_id': entry.get('file_id', entry['file_num'])
                })

            # Calculate offsets - VOL structure:
            # 1. Header: 16 bytes
            # 2. TOC: 12 bytes per file (offset, size, fid)
            # 3. String offset table: 4 bytes per file
            # 4. 4-byte gap (0x00000000)
            # 5. String table: null-terminated strings
            # 6. Padding (0xFF bytes) to align file data
            # 7. File data

            header_size = 16
            toc_size = len(file_data_list) * 0xC
            string_offset_table_size = len(file_data_list) * 4

            # String table starts after: header + TOC + string offset table + 4 bytes
            # This matches BMS formula: (12 * FILES) + (4 * FILES) + 20
            string_table_start = header_size + toc_size + string_offset_table_size + 4

            # Extract ORIGINAL string offset table and string data to preserve exact structure
            # The string offset table has special values that must be preserved
            original_string_offset_table_start = 16 + (len(file_data_list) * 12)
            original_string_offset_table_size = len(file_data_list) * 4
            original_string_offset_table = self.file_data[original_string_offset_table_start:original_string_offset_table_start + original_string_offset_table_size]

            # Extract original string data (starts after offset table + 4-byte size field)
            original_string_data_start = (12 * len(file_data_list)) + (4 * len(file_data_list)) + 20
            original_datastart = struct.unpack('<I', self.file_data[0x0C:0x10])[0]
            original_string_data_size = original_datastart - original_string_data_start
            string_table_data = bytearray(self.file_data[original_string_data_start:original_datastart])

            # String table end (this is the DATASTART value)
            string_table_end = string_table_start + len(string_table_data)

            # Get original alignment from first file offset
            original_first_file_offset = struct.unpack('<I', self.file_data[16:20])[0]

            # Use original alignment if possible, otherwise align to nearest power of 2
            if original_first_file_offset >= string_table_end:
                # Use original offset as data_start
                data_start = original_first_file_offset
            else:
                # Calculate alignment (common values: 0x100, 0x200, 0x400, 0x800, 0x1000)
                for align in [0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20]:
                    aligned = ((string_table_end + align - 1) // align) * align
                    if aligned >= string_table_end:
                        data_start = aligned
                        break
                else:
                    data_start = string_table_end

            padding_before_data = data_start - string_table_end

            # Build output
            new_data = bytearray()

            # Build header (16 bytes):
            # 0x00-03: Magic "PVOL"
            # 0x04-07: UNK (0x1001)
            # 0x08-0B: FILES count
            # 0x0C-0F: DATASTART (end of string table)
            new_data.extend(b'PVOL')
            new_data.extend(struct.pack('<I', 0x1001))  # UNK
            new_data.extend(struct.pack('<I', len(file_data_list)))  # FILES
            new_data.extend(struct.pack('<I', string_table_end))  # DATASTART = string table end

            # Build TOC (12 bytes per file: OFFSET, SIZE, FID)
            # Pre-calculate all file offsets with 16-byte alignment (last hex digit is 0)
            file_offsets = []
            current_file_offset = data_start
            for file_info in file_data_list:
                file_offsets.append(current_file_offset)
                # Move to next file
                current_file_offset += len(file_info['data'])
                # Align to NEXT 16-byte boundary, with minimum 16 bytes padding
                # If already aligned, add 16; otherwise add padding to reach next boundary
                padding = (16 - (current_file_offset % 16)) % 16
                if padding == 0:
                    padding = 16  # Minimum gap of 16 bytes
                current_file_offset += padding

            # Write TOC
            for i, file_info in enumerate(file_data_list):
                new_data.extend(struct.pack('<I', file_offsets[i]))  # OFFSET (absolute)
                new_data.extend(struct.pack('<I', len(file_info['data'])))  # SIZE
                new_data.extend(struct.pack('<I', file_info['file_id']))  # FID

            # Write ORIGINAL string offset table (preserve exact values)
            new_data.extend(original_string_offset_table)

            # Extract and preserve ORIGINAL string section size field
            original_size_field_pos = 16 + (len(file_data_list) * 12) + (len(file_data_list) * 4)
            original_string_section_size = struct.unpack('<I', self.file_data[original_size_field_pos:original_size_field_pos+4])[0]
            new_data.extend(struct.pack('<I', original_string_section_size))

            # Add string table
            new_data.extend(string_table_data)

            # Add padding to align file data section (use 0xFF like original)
            new_data.extend(b'\xFF' * padding_before_data)

            # Add file data with 16-byte alignment between files (last hex digit = 0)
            for i, file_info in enumerate(file_data_list):
                new_data.extend(file_info['data'])

                # Add 0xFF padding - minimum 16 bytes between files (except for last file)
                if i < len(file_data_list) - 1:
                    current_pos = len(new_data)
                    padding = (16 - (current_pos % 16)) % 16
                    if padding == 0:
                        padding = 16  # Minimum gap of 16 bytes
                    new_data.extend(b'\xFF' * padding)

            # Add padding at end - align to 16 bytes then add 16 more bytes (total 16-32 bytes)
            current_pos = len(new_data)
            padding = (16 - (current_pos % 16)) % 16
            new_data.extend(b'\xFF' * (padding + 16))

            # Write output file
            with open(output_vol_path, 'wb') as f:
                f.write(new_data)

            print(f"\n✓ VOL rebuilt successfully: {output_vol_path}")
            print(f"  Total size: {len(new_data)} bytes")
            print(f"  Files: {len(file_data_list)}")
            print(f"  Header: {header_size} bytes (0x00-0x0F)")
            print(f"  TOC: {toc_size} bytes (0x10-0x{15 + toc_size:X})")
            print(f"  String offset table: {string_offset_table_size} bytes (0x{16 + toc_size:X}-0x{15 + toc_size + string_offset_table_size:X})")
            print(f"  String table: {len(string_table_data)} bytes at 0x{string_table_start:X}")
            print(f"  String table ends (DATASTART): 0x{string_table_end:X}")
            print(f"  Padding: {padding_before_data} bytes (0xFF)")
            print(f"  File data start: 0x{data_start:X}")
            return True

        except Exception as e:
            print(f"Error rebuilding VOL: {e}")
            import traceback
            traceback.print_exc()
            return False

