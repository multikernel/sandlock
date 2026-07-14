//! Compact binary control blob handed to the freestanding restore-stub through
//! an inherited memfd. Carries region/fd metadata, the checkpoint's GP register
//! file, and the anonymous page bytes; file-backed region bytes are NOT included
//! (the stub maps those from their files in a later pass). Little-endian,
//! versioned, append-only. The C stub in `checkpoint/restore-stub.c` mirrors
//! this layout byte-for-byte.

use crate::checkpoint::Checkpoint;

pub(crate) const BLOB_MAGIC: u32 = 0x534c_5242; // "SLRB"
pub(crate) const BLOB_VERSION: u32 = 1;

const HEADER_LEN: usize = 40;
const REGION_ENTRY_LEN: usize = 40;
const NO_DATA: u64 = u64::MAX;

/// Serialize `cp` into the control-blob wire format (see module docs).
pub(crate) fn serialize(cp: &Checkpoint) -> Vec<u8> {
    let ps = &cp.process_state;

    // Only anonymous, captured regions carry bytes. A region is "anon with
    // data" when a MemorySegment exists at its start.
    let n_regions = ps.memory_maps.len() as u32;

    let regs_len = (ps.regs.len() * 8) as u32;

    // Layout: header | region table | regs | anon data
    let region_table_len = ps.memory_maps.len() * REGION_ENTRY_LEN;
    let regs_off = HEADER_LEN + region_table_len;
    let anon_data_off = regs_off + regs_len as usize;

    let mut out = Vec::with_capacity(anon_data_off);
    // Header (fill region-table + regs + anon after).
    out.extend_from_slice(&BLOB_MAGIC.to_le_bytes());
    out.extend_from_slice(&BLOB_VERSION.to_le_bytes());
    out.extend_from_slice(&n_regions.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // n_fds (none yet)
    out.extend_from_slice(&(regs_off as u64).to_le_bytes());
    out.extend_from_slice(&regs_len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // _pad
    out.extend_from_slice(&(anon_data_off as u64).to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);

    // Region table. Compute each region's data_off into the anon blob as we go.
    let mut anon_blob: Vec<u8> = Vec::new();
    for m in &ps.memory_maps {
        let seg = ps.memory_data.iter().find(|s| s.start == m.start);
        let (src, data_off) = match seg {
            Some(s) => {
                let off = anon_blob.len() as u64;
                anon_blob.extend_from_slice(&s.data);
                (0u8, off) // anon with data
            }
            None => (1u8, NO_DATA), // file-backed / no captured data (filled from files later)
        };
        let prot = prot_bits(&m.perms);
        out.extend_from_slice(&m.start.to_le_bytes());
        out.extend_from_slice(&m.end.to_le_bytes());
        out.extend_from_slice(&prot.to_le_bytes());
        out.push(src);
        out.extend_from_slice(&[0u8; 3]); // _pad0
        out.extend_from_slice(&m.offset.to_le_bytes()); // file_off
        out.extend_from_slice(&data_off.to_le_bytes());
    }
    debug_assert_eq!(out.len(), regs_off);

    // GP register area.
    for r in &ps.regs {
        out.extend_from_slice(&r.to_le_bytes());
    }
    debug_assert_eq!(out.len(), anon_data_off);

    // Anon data.
    out.extend_from_slice(&anon_blob);
    out
}

fn prot_bits(perms: &str) -> u32 {
    let b = perms.as_bytes();
    let mut p = 0u32;
    if b.first() == Some(&b'r') { p |= libc::PROT_READ as u32; }
    if b.get(1) == Some(&b'w') { p |= libc::PROT_WRITE as u32; }
    if b.get(2) == Some(&b'x') { p |= libc::PROT_EXEC as u32; }
    p
}

#[cfg(test)]
mod tests {
    use super::{serialize, BLOB_MAGIC, BLOB_VERSION};
    use crate::checkpoint::{Checkpoint, MemoryMap, MemorySegment, ProcessState};
    use crate::sandbox::Sandbox;

    fn tiny_checkpoint() -> Checkpoint {
        Checkpoint {
            name: String::new(),
            policy: Sandbox::builder().build().unwrap(),
            process_state: ProcessState {
                pid: 1234,
                cwd: "/".into(),
                exe: "/x".into(),
                regs: (0..27u64).collect(),          // recognizable
                fpregs: Vec::new(),
                memory_maps: vec![MemoryMap {
                    start: 0x4500_0000_0000,
                    end: 0x4500_0000_1000,
                    perms: "rwxp".into(),
                    offset: 0,
                    path: None,
                }],
                memory_data: vec![MemorySegment {
                    start: 0x4500_0000_0000,
                    data: vec![0xC7u8; 0x1000],
                }],
            },
            fd_table: Vec::new(),
            cow_snapshot: None,
            app_state: None,
        }
    }

    #[test]
    fn blob_header_and_region_roundtrip() {
        let cp = tiny_checkpoint();
        let blob = serialize(&cp);

        // Header magic/version.
        assert_eq!(u32::from_le_bytes(blob[0..4].try_into().unwrap()), BLOB_MAGIC);
        assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), BLOB_VERSION);
        // One region, zero fds.
        assert_eq!(u32::from_le_bytes(blob[8..12].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(blob[12..16].try_into().unwrap()), 0);

        // Region-table entry (40 bytes at offset 40): the single region, byte-exact.
        let r0 = 40usize;
        assert_eq!(u64::from_le_bytes(blob[r0..r0 + 8].try_into().unwrap()), 0x4500_0000_0000, "region.start");
        assert_eq!(u64::from_le_bytes(blob[r0 + 8..r0 + 16].try_into().unwrap()), 0x4500_0000_1000, "region.end");
        assert_eq!(u32::from_le_bytes(blob[r0 + 16..r0 + 20].try_into().unwrap()),
                   (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32, "region.prot");
        assert_eq!(blob[r0 + 20], 0, "region.src = anon (has captured data)");
        assert_eq!(u64::from_le_bytes(blob[r0 + 24..r0 + 32].try_into().unwrap()), 0, "region.file_off");
        assert_eq!(u64::from_le_bytes(blob[r0 + 32..r0 + 40].try_into().unwrap()), 0, "region.data_off");

        // GP register area holds the 27 recognizable values.
        let regs_off = u64::from_le_bytes(blob[16..24].try_into().unwrap()) as usize;
        let regs_len = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
        assert_eq!(regs_len, 27 * 8);
        for i in 0..27u64 {
            let v = u64::from_le_bytes(
                blob[regs_off + i as usize * 8..regs_off + i as usize * 8 + 8]
                    .try_into().unwrap());
            assert_eq!(v, i);
        }

        // Anon data for the single region is all 0xC7, length 0x1000.
        let anon_off = u64::from_le_bytes(blob[32..40].try_into().unwrap()) as usize;
        assert_eq!(&blob[anon_off..anon_off + 0x1000], &[0xC7u8; 0x1000][..]);
    }
}
