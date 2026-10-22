from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        sections = {s.name: s for s in elf.iter_sections()}
        rodata = sections['.rodata']
        rodata_data = rodata.data()
        rodata_addr = rodata['sh_addr']

        def read_str_at(va):
            if rodata_addr <= va < rodata_addr + len(rodata_data):
                off = va - rodata_addr
                end = rodata_data.find(b'\0', off)
                if end != -1:
                    return rodata_data[off:end].decode('utf-8', errors='replace')
            return f"<unknown rodata 0x{va:x}>"

        print("String at 0x10b87a:", repr(read_str_at(0x10b87a)))
        print("String at 0xf1d43:", repr(read_str_at(0xf1d43)))

        # Also let's check what functions are at 0x1401b40, 0x1401b50, 0x1402020
        # Check relocations or PLT
        dynsym = sections.get('.dynsym')
        symtab = sections.get('.symtab')

        # Check if 0x1402020 is PLT or a function
        plt = sections.get('.plt')
        print(f"PLT range: 0x{plt['sh_addr']:08x} - 0x{plt['sh_addr']+plt['sh_size']:08x}")

        # Look up nearest symbols to 0xe789e8, 0x1402020, 0x1401b40, 0x1401b50
        targets = [0xe789e8, 0xe78b38, 0x1401b40, 0x1401b50, 0x1402020, 0xe69268, 0xe78f6c, 0xe80104, 0x13faa74, 0xfbdd9c, 0xe802c0, 0xfa7214, 0xe80250]

        all_syms = []
        for s in elf.iter_sections():
            if isinstance(s, SymbolTableSection):
                for sym in s.iter_symbols():
                    st_val = sym['st_value']
                    if st_val != 0:
                        all_syms.append((st_val, sym['st_size'], sym.name))

        all_syms.sort()
        print(f"Found {len(all_syms)} symbols.")
        for t in targets:
            # Find exact or preceding symbol
            best = None
            for val, size, name in all_syms:
                if val <= t:
                    best = (val, size, name)
                else:
                    break
            if best:
                val, size, name = best
                print(f"0x{t:08x} -> {name} + 0x{t - val:x} (sym @ 0x{val:08x}, size {size})")
            else:
                print(f"0x{t:08x} -> no symbol found")

if __name__ == '__main__':
    main()
