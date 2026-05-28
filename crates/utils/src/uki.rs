/// Create a minimal valid PE file for testing UKI parsing
pub fn create_minimal_pe() -> Vec<u8> {
    let mut pe = Vec::new();
    let section_data_offset = 0x200u32; // Standard section alignment
    let section_data = b"quiet splash"; // Sample cmdline content

    // DOS header (64 bytes)
    pe.extend_from_slice(b"MZ"); // e_magic
    pe.extend_from_slice(&[0u8; 58]); // DOS header padding
    pe.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew (offset to PE header)

    // DOS stub padding to reach offset 0x80
    pe.resize(0x80, 0);

    // PE header (4 bytes)
    pe.extend_from_slice(b"PE\0\0");

    // COFF header (20 bytes)
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine (x64)
    pe.extend_from_slice(&1u16.to_le_bytes()); // number of sections
    pe.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // pointer to symbol table
    pe.extend_from_slice(&0u32.to_le_bytes()); // number of symbols
    pe.extend_from_slice(&0xF0u16.to_le_bytes()); // size of optional header
    pe.extend_from_slice(&0x2022u16.to_le_bytes()); // characteristics

    // Optional header (240 bytes for PE32+)
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // magic (PE32+)
    pe.extend_from_slice(&[0u8; 0xF0 - 2]); // rest of optional header filled with zeros

    // Section header (40 bytes)
    let mut section_header = [0u8; 40];
    section_header[..8].copy_from_slice(b".cmdline"); // name
    section_header[8..12].copy_from_slice(&(section_data.len() as u32).to_le_bytes()); // virtual_size
    section_header[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_address
    section_header[16..20].copy_from_slice(&(section_data.len() as u32).to_le_bytes()); // size_of_raw_data
    section_header[20..24].copy_from_slice(&section_data_offset.to_le_bytes()); // pointer_to_raw_data
    section_header[36..40].copy_from_slice(&0x40000040u32.to_le_bytes()); // characteristics (readable)
    pe.extend_from_slice(&section_header);

    // Pad to section data offset
    pe.resize(section_data_offset as usize, 0);

    // Section data
    pe.extend_from_slice(section_data);

    pe
}
