use crate::checkpoint::{MemoryMap, MemorySegment};

/// One planned memory-restore action for a saved region.
#[allow(dead_code)] // used by the restore path (added in a later change)
#[derive(Debug)]
pub(crate) enum RestoreRegion {
    /// mmap MAP_FIXED from `path` at `offset`, prot from `perms`.
    RemapFromFile { start: u64, end: u64, perms: String, offset: u64, path: String },
    /// mmap MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, then write `data`.
    WriteBytes { start: u64, end: u64, perms: String, data: Vec<u8> },
}

/// Classify saved regions into restore actions. Special kernel maps
/// ([vdso]/[vvar]/[vsyscall]) are skipped: the kernel provides them in the
/// fresh process and they must not be overwritten. A region with captured
/// bytes becomes WriteBytes; otherwise a path-backed region becomes
/// RemapFromFile. Regions that are neither are left to the kernel/ABI.
#[allow(dead_code)] // used by the restore path (added in a later change)
pub(crate) fn build_memory_plan(
    maps: &[MemoryMap],
    data: &[MemorySegment],
) -> Vec<RestoreRegion> {
    let mut plan = Vec::new();
    for m in maps {
        if m.is_special() { continue; }
        if let Some(seg) = data.iter().find(|s| s.start == m.start) {
            plan.push(RestoreRegion::WriteBytes {
                start: m.start, end: m.end, perms: m.perms.clone(), data: seg.data.clone(),
            });
        } else if let Some(ref p) = m.path {
            if p.starts_with('/') {
                plan.push(RestoreRegion::RemapFromFile {
                    start: m.start, end: m.end, perms: m.perms.clone(),
                    offset: m.offset, path: p.clone(),
                });
            }
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{MemoryMap, MemorySegment};

    #[test]
    fn plan_classifies_regions() {
        let maps = vec![
            MemoryMap { start: 0x1000, end: 0x2000, perms: "r-xp".into(), offset: 0,
                        path: Some("/bin/app".into()) },          // code: remap from file
            MemoryMap { start: 0x3000, end: 0x4000, perms: "rw-p".into(), offset: 0,
                        path: None },                              // anon writable: write bytes
            MemoryMap { start: 0x5000, end: 0x6000, perms: "r--p".into(), offset: 0,
                        path: Some("[vvar]".into()) },             // special: skip
        ];
        let data = vec![MemorySegment { start: 0x3000, data: vec![7u8; 0x1000] }];
        let plan = build_memory_plan(&maps, &data);
        assert!(matches!(plan[0], RestoreRegion::RemapFromFile { .. }));
        assert!(matches!(plan[1], RestoreRegion::WriteBytes { .. }));
        assert_eq!(plan.len(), 2, "special regions are skipped, not planned");
    }
}
