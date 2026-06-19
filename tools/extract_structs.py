#!/usr/bin/env python3
"""Extract struct field layouts from DWARF debug info for Lancet sub-subject splitting.

Usage:
    python3 extract_structs.py <binary> [-o output.structs] [-s struct_name ...]

If no -s is given, extracts ALL structs with >= 2 members that contain a pointer field.
Output format (one struct per block):

    struct <name> <total_size>
      <field_name> <offset> <size> <is_pointer>
      ...

Lancet loads this via -struct_layout <file>.
"""

import argparse
import sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.dwarf.die import DIE
except ImportError:
    print("Error: pyelftools required. Install with: pip install pyelftools", file=sys.stderr)
    sys.exit(1)


def resolve_type_size(die, cu):
    """Follow DW_AT_type references to get the byte size of a type."""
    seen = set()
    current = die
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if 'DW_AT_byte_size' in current.attributes:
            return current.attributes['DW_AT_byte_size'].value
        if 'DW_AT_type' not in current.attributes:
            break
        type_offset = current.attributes['DW_AT_type'].value
        if hasattr(type_offset, 'value'):
            type_offset = type_offset.value
        abs_offset = type_offset + cu.cu_offset
        try:
            current = cu.get_DIE_from_refaddr(type_offset)
        except Exception:
            break
    return None


def is_pointer_type(die, cu):
    """Check if a type is a pointer (DW_TAG_pointer_type in the chain)."""
    seen = set()
    current = die
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if current.tag == 'DW_TAG_pointer_type':
            return True
        if 'DW_AT_type' not in current.attributes:
            break
        type_offset = current.attributes['DW_AT_type'].value
        try:
            current = cu.get_DIE_from_refaddr(type_offset)
        except Exception:
            break
    return False


def get_member_type_die(member_die, cu):
    """Get the DIE for a member's type."""
    if 'DW_AT_type' not in member_die.attributes:
        return None
    type_offset = member_die.attributes['DW_AT_type'].value
    try:
        return cu.get_DIE_from_refaddr(type_offset)
    except Exception:
        return None


def extract_structs(elf_path, filter_names=None):
    """Extract struct layouts from DWARF info."""
    results = {}

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print(f"Warning: {elf_path} has no DWARF debug info", file=sys.stderr)
            return results

        dwarf = elf.get_dwarf_info()

        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != 'DW_TAG_structure_type':
                    continue

                name_attr = die.attributes.get('DW_AT_name')
                size_attr = die.attributes.get('DW_AT_byte_size')
                if not name_attr or not size_attr:
                    continue

                name = name_attr.value
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                total_size = size_attr.value

                if filter_names and name not in filter_names:
                    continue
                if name in results:
                    continue

                fields = []
                for child in die.iter_children():
                    if child.tag != 'DW_TAG_member':
                        continue

                    fname_attr = child.attributes.get('DW_AT_name')
                    fname = fname_attr.value if fname_attr else b'?'
                    if isinstance(fname, bytes):
                        fname = fname.decode('utf-8', errors='replace')

                    foffset = 0
                    if 'DW_AT_data_member_location' in child.attributes:
                        loc = child.attributes['DW_AT_data_member_location']
                        if isinstance(loc.value, int):
                            foffset = loc.value
                        elif isinstance(loc.value, list):
                            # DWARF expression — try to evaluate simple cases
                            if len(loc.value) >= 2 and loc.value[0] == 0x23:  # DW_OP_plus_uconst
                                foffset = loc.value[1]

                    type_die = get_member_type_die(child, cu)
                    fsize = resolve_type_size(type_die, cu) if type_die else None
                    fptr = is_pointer_type(type_die, cu) if type_die else False

                    fields.append({
                        'name': fname,
                        'offset': foffset,
                        'size': fsize,
                        'is_pointer': fptr,
                    })

                if len(fields) < 2:
                    continue

                # Sort by offset
                fields.sort(key=lambda f: f['offset'])

                # Always compute sizes from offset differences — more reliable than
                # DWARF type resolution, which may return element size for arrays.
                for i, f in enumerate(fields):
                    if i + 1 < len(fields):
                        f['size'] = fields[i + 1]['offset'] - f['offset']
                    else:
                        f['size'] = total_size - f['offset']

                # Filter: only include structs with at least one pointer field
                # (unless explicitly requested)
                has_ptr = any(f['is_pointer'] for f in fields)
                if not filter_names and not has_ptr:
                    continue

                results[name] = {
                    'size': total_size,
                    'fields': fields,
                }

    return results


def write_output(structs, outfile):
    """Write struct layouts in Lancet-readable format."""
    with open(outfile, 'w') as f:
        f.write("# Lancet struct layout file — generated by extract_structs.py\n")
        f.write(f"# {len(structs)} structs extracted\n\n")

        for name, info in sorted(structs.items(), key=lambda x: x[0]):
            f.write(f"struct {name} {info['size']}\n")
            for field in info['fields']:
                ptr_flag = 1 if field['is_pointer'] else 0
                f.write(f"  {field['name']} {field['offset']} {field['size']} {ptr_flag}\n")
            f.write("\n")


def main():
    parser = argparse.ArgumentParser(description='Extract struct layouts from DWARF for Lancet')
    parser.add_argument('binary', help='ELF binary with debug info')
    parser.add_argument('-o', '--output', default=None, help='Output file (default: <binary>.structs)')
    parser.add_argument('-s', '--structs', nargs='+', default=None,
                        help='Specific struct names to extract (default: all with pointer fields)')
    parser.add_argument('--all', action='store_true',
                        help='Extract ALL structs, not just those with pointer fields')
    args = parser.parse_args()

    outfile = args.output or (args.binary + '.structs')
    filter_names = set(args.structs) if args.structs else None
    if args.all:
        filter_names = None

    print(f"Extracting struct layouts from {args.binary}...", file=sys.stderr)
    structs = extract_structs(args.binary, filter_names)
    print(f"Found {len(structs)} structs", file=sys.stderr)

    if not structs:
        print("No matching structs found. Is the binary compiled with -g?", file=sys.stderr)
        sys.exit(1)

    write_output(structs, outfile)
    print(f"Written to {outfile}", file=sys.stderr)

    # Print summary
    for name, info in sorted(structs.items()):
        ptr_fields = sum(1 for f in info['fields'] if f['is_pointer'])
        print(f"  {name}: {info['size']}B, {len(info['fields'])} fields, {ptr_fields} pointers")


if __name__ == '__main__':
    main()
