// SPDX-License-Identifier: GPL-2.0-only
//! Explicit per-call diagnostics, not an audit WAL or a safety verdict.
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_sys as bpf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAGIC: u32 = 0x46414343;
const EVENT_BYTES: usize = 192;
const THREAD_LIMIT: usize = 8192;
const HEALTH: [&str; 17] = [
    "context_full",
    "pending_full",
    "object_read_failed",
    "nested_hooks",
    "unpaired_exit",
    "syscall_exit_pending",
    "unsupported_syscall_abi",
    "ring_drops",
    "fault_pending_full",
    "fault_unpaired",
    "fault_exit_pending",
    "syscall_mismatch",
    "multiple_vfs",
    "offset_read_failed",
    "mm_fault_pending_full",
    "mm_fault_unpaired",
    "mm_fault_exit_pending",
];
const REQUIRED_PROGRAMS: [&str; 14] = [
    "fa_sys_enter",
    "fa_sys_exit",
    "fa_read_enter",
    "fa_read_exit",
    "fa_readv_enter",
    "fa_readv_exit",
    "fa_dir_enter",
    "fa_dir_exit",
    "fa_open_file",
    "fa_fault_enter",
    "fa_fault_exit",
    "fa_mm_fault_enter",
    "fa_mm_fault_exit",
    "fa_task_exit",
];
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Parser)]
#[clap(about = "Opt-in per-call file access and filemap-fault diagnostic stream")]
struct Args {
    #[clap(long)]
    output_dir: PathBuf,
    #[clap(long)]
    bpf_object: PathBuf,
    #[clap(long)]
    bpf_sha256: String,
    #[clap(long, required = true)]
    cgroup: Vec<PathBuf>,
    #[clap(long)]
    run_id: String,
    #[clap(long, default_value = "1200")]
    max_seconds: u64,
    #[clap(long, default_value = "2147483648")]
    max_bytes: u64,
    /// Bounded kernel ring allocation: power of two, 16..512 MiB.
    #[clap(long, default_value = "67108864")]
    ring_bytes: u32,
    #[clap(long, default_value = "events")]
    mode: String,
    /// Explicit attachment choice; a mismatching BPF object is rejected.
    #[clap(long, default_value = "fentry")]
    backend: String,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Event {
    magic: u32,
    version: u16,
    kind: u16,
    size: u32,
    flags: u32,
    cpu_seq: u64,
    domain_id: u64,
    caller_cgroup_id: u64,
    process_start_boottime_ns: u64,
    thread_start_boottime_ns: u64,
    start_ns: u64,
    end_ns: u64,
    syscall_start_ns: u64,
    syscall_end_ns: u64,
    mount_id: u64,
    inode: u64,
    file_size: i64,
    offset: i64,
    requested: u64,
    result: i64,
    syscall_result: i64,
    fault_address: u64,
    pgoff: u64,
    device: u32,
    generation: u32,
    tgid: u32,
    tid: u32,
    cpu: u32,
    syscall_nr: u32,
    fault_flags: u32,
    vm_fault_result: u32,
}
#[repr(C)]
struct Config {
    count: u32,
    enabled: u32,
    emit_events: u32,
    reserved: u32,
}
#[repr(C)]
struct Domain {
    cgroup_id: u64,
    level: u32,
    reserved: u32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Totals {
    attempted: u64,
    emitted: u64,
    ring_drops: u64,
}

fn ns(clock: libc::clockid_t) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
fn native_arch(arch: &str) -> Result<()> {
    if arch != "x86_64" || !cfg!(target_endian = "little") {
        bail!("file-access collector requires little-endian native x86-64");
    }
    Ok(())
}
fn domains(paths: &[PathBuf]) -> Result<Vec<(File, Value, Domain)>> {
    if paths.is_empty() || paths.len() > 16 {
        bail!("one to 16 cgroups required");
    }
    for (i, path) in paths.iter().enumerate() {
        for other in &paths[i + 1..] {
            if path.starts_with(other) || other.starts_with(path) {
                bail!("overlapping cgroup domains");
            }
        }
    }
    let mut out = Vec::new();
    for path in paths {
        if !path.is_absolute() || fs::canonicalize(path)? != *path {
            bail!("require absolute canonical cgroup path");
        }
        let rel = path.strip_prefix("/sys/fs/cgroup")?;
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            bail!("invalid cgroup path");
        }
        let level = rel.components().count();
        if level == 0 || level > 31 || !path.join("cgroup.controllers").is_file() {
            bail!("require non-root cgroup-v2 domain at depth <=31");
        }
        let file = File::open(path)?;
        let stat = file.metadata()?;
        out.push((
            file,
            json!({"path":path,"inode":stat.ino(),"device":stat.dev(),"level":level}),
            Domain {
                cgroup_id: stat.ino(),
                level: level as u32,
                reserved: 0,
            },
        ));
    }
    Ok(out)
}
fn rc(value: i32, action: &str) -> Result<()> {
    if value < 0 {
        bail!("{action}: {}", io::Error::last_os_error());
    }
    Ok(())
}
fn pointer_bad<T>(value: *mut T) -> bool {
    value.is_null() || ((value as isize) < 0 && (value as isize) > -4096)
}
fn map(object: *mut bpf::bpf_object, name: &str, key: u32, value: u32) -> Result<i32> {
    let name = CString::new(name)?;
    let map = unsafe { bpf::bpf_object__find_map_by_name(object, name.as_ptr()) };
    if map.is_null() {
        bail!("missing map {}", name.to_string_lossy());
    }
    if unsafe { bpf::bpf_map__key_size(map) } != key
        || unsafe { bpf::bpf_map__value_size(map) } != value
    {
        bail!("map {} ABI mismatch", name.to_string_lossy());
    }
    let fd = unsafe { bpf::bpf_map__fd(map) };
    if fd < 0 {
        bail!("map not loaded");
    }
    Ok(fd)
}
fn update<T>(fd: i32, index: u32, value: &T) -> Result<()> {
    rc(
        unsafe {
            bpf::bpf_map_update_elem(
                fd,
                (&index as *const u32).cast(),
                (value as *const T).cast(),
                bpf::BPF_ANY as u64,
            )
        },
        "update map",
    )
}
fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

const TRACE_GROUP: &str = "allox_file_access";
const KRET_MAXACTIVE: u32 = 4096;
const TRACE_LIMIT: u64 = 4 * 1024 * 1024;
fn read_trace(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(TRACE_LIMIT + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > TRACE_LIMIT {
        bail!("tracefs text exceeds 4 MiB");
    }
    Ok(text)
}
fn trace_command(root: &Path, text: &str) -> Result<()> {
    OpenOptions::new()
        .append(true)
        .open(root.join("kprobe_events"))?
        .write_all(text.as_bytes())?;
    Ok(())
}
fn trace_profile(text: &str, name: &str) -> Result<[u64; 2]> {
    let rows = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|row| row.first().map_or(false, |value| *value == name))
        .collect::<Vec<_>>();
    if rows.len() != 1 || rows[0].len() != 3 {
        bail!("missing or ambiguous owned kprobe profile");
    }
    Ok([rows[0][1].parse()?, rows[0][2].parse()?])
}
struct TraceEvent {
    root: PathBuf,
    name: String,
    program: String,
    anchor: String,
    is_return: bool,
    definition: Option<String>,
    identity: Option<(u64, u64, u64)>,
    initial: Option<[u64; 2]>,
}
impl TraceEvent {
    fn identity(&self) -> Result<(u64, u64, u64)> {
        let path = self.root.join("events").join(TRACE_GROUP).join(&self.name);
        let meta = fs::metadata(&path)?;
        let id = read_trace(&path.join("id"))?.trim().parse()?;
        Ok((meta.dev(), meta.ino(), id))
    }
    fn definition(&self) -> Result<String> {
        let token = format!("{TRACE_GROUP}/{}", self.name);
        let text = read_trace(&self.root.join("kprobe_events"))?;
        let lines = text
            .lines()
            .filter(|line| {
                line.split_whitespace().next().map_or(false, |head| {
                    head.split_once(':').map_or(false, |(_, id)| id == token)
                })
            })
            .collect::<Vec<_>>();
        if lines.len() != 1 {
            bail!("owned trace definition missing or ambiguous");
        }
        let parts = lines[0].split_whitespace().collect::<Vec<_>>();
        let prefix = if self.is_return {
            format!("r{KRET_MAXACTIVE}")
        } else {
            "p".into()
        };
        if parts.len() != 2
            || parts[0] != format!("{prefix}:{token}")
            || !(parts[1] == self.anchor || parts[1] == format!("{}+0", self.anchor))
        {
            bail!("owned trace definition anchor/maxactive changed");
        }
        Ok(lines[0].trim().to_owned())
    }
    fn profile(&self) -> Result<[u64; 2]> {
        trace_profile(&read_trace(&self.root.join("kprobe_profile"))?, &self.name)
    }
    fn verify_identity(&self) -> Result<()> {
        if self.definition.as_ref() != Some(&self.definition()?)
            || self.identity != Some(self.identity()?)
        {
            bail!("owned trace event identity changed");
        }
        Ok(())
    }
    fn evidence(&self) -> (Value, bool) {
        let start = ns(libc::CLOCK_MONOTONIC);
        let observed = (|| -> Result<[u64; 2]> {
            self.verify_identity()?;
            let current = self.profile()?;
            let initial = self.initial.context("missing initial profile")?;
            if current[0] < initial[0] || current[1] < initial[1] {
                bail!("trace counters rolled back");
            }
            Ok(current)
        })();
        let (current, error) = match observed {
            Ok(value) => (Some(value), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let misses_delta = current.zip(self.initial).map(|(c, i)| c[1] - i[1]);
        (
            json!({"program_name":self.program,"name":self.name,"group":TRACE_GROUP,
            "anchor":self.anchor,"is_return":self.is_return,"maxactive":if self.is_return {Some(KRET_MAXACTIVE)} else {None},
            "tracefs_root":self.root,"definition":self.definition,
            "device":self.identity.map(|v|v.0),"directory_inode":self.identity.map(|v|v.1),"event_id":self.identity.map(|v|v.2),
            "initial_hits":self.initial.map(|v|v[0]),"initial_misses":self.initial.map(|v|v[1]),
            "hits":current.map(|v|v[0]),"misses":current.map(|v|v[1]),"misses_delta":misses_delta,
            "profile_status":if error.is_none() {"OBSERVED"} else {"UNKNOWN"},
            "identity_status":if error.is_none() {"MATCH"} else {"UNKNOWN"},"error":error,
            "collection_start_ns":start,"collection_end_ns":ns(libc::CLOCK_MONOTONIC),
            "scope":"GLOBAL_HOOK_NOT_AGENT_ATTRIBUTED; missed probes conservatively invalidate selected history"}),
            misses_delta != Some(0),
        )
    }
    fn remove(&self) -> Result<()> {
        self.verify_identity()?;
        trace_command(&self.root, &format!("-:{TRACE_GROUP}/{}\n", self.name))
    }
}

struct KernelBtf(*mut bpf::btf);
impl Drop for KernelBtf {
    fn drop(&mut self) {
        unsafe { bpf::btf__free(self.0) };
    }
}
fn btf_type(btf: *const bpf::btf, mut id: u32) -> Result<*const bpf::btf_type> {
    for _ in 0..16 {
        let ty = unsafe { bpf::btf__type_by_id(btf, id) };
        if ty.is_null() {
            bail!("BTF references missing type");
        }
        if [8, 9, 10, 11, 18].contains(&unsafe { ((*ty).info >> 24) & 31 }) {
            id = unsafe { (*ty).__bindgen_anon_1.type_ };
        } else {
            return Ok(ty);
        }
    }
    bail!("BTF modifier chain exceeds bound")
}
fn btf_name(btf: *const bpf::btf, offset: u32) -> Result<String> {
    let p = unsafe { bpf::btf__name_by_offset(btf, offset) };
    if p.is_null() {
        bail!("invalid BTF name offset");
    }
    Ok(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}
fn btf_integer(btf: *const bpf::btf, id: u32, bytes: u32, signed: bool) -> Result<()> {
    let ty = btf_type(btf, id)?;
    if unsafe { ((*ty).info >> 24) & 31 } != bpf::BTF_KIND_INT
        || unsafe { (*ty).__bindgen_anon_1.size } != bytes
    {
        bail!("hook integer ABI kind/width differs");
    }
    let encoding = unsafe { *ty.add(1).cast::<u32>() };
    if ((encoding >> 24) & 1 != 0) != signed {
        bail!("hook integer signedness differs");
    }
    Ok(())
}
fn validate_kprobe_abi() -> Result<Value> {
    let raw = unsafe { bpf::btf__load_vmlinux_btf() };
    if pointer_bad(raw) {
        bail!("kprobe backend requires kernel BTF");
    }
    let btf = KernelBtf(raw);
    let mut anchors = Vec::new();
    for (name, argc, ret_bytes, first_struct) in [
        ("vfs_read", 4usize, 8u32, "file"),
        ("vfs_readv", 5, 8, "file"),
        ("iterate_dir", 2, 4, "file"),
        ("security_file_open", 1, 4, "file"),
        ("filemap_fault", 1, 4, "vm_fault"),
        ("handle_mm_fault", 4, 4, "vm_area_struct"),
    ] {
        let cname = CString::new(name)?;
        let id = unsafe { bpf::btf__find_by_name_kind(raw, cname.as_ptr(), bpf::BTF_KIND_FUNC) };
        if id <= 0 {
            bail!("required kprobe BTF function {name} missing");
        }
        let func = btf_type(raw, id as u32)?;
        let proto = btf_type(raw, unsafe { (*func).__bindgen_anon_1.type_ })?;
        if unsafe { ((*proto).info >> 24) & 31 } != bpf::BTF_KIND_FUNC_PROTO
            || unsafe { (*proto).info & 65535 } as usize != argc
        {
            bail!("{name} parameter ABI differs");
        }
        let ret = btf_type(raw, unsafe { (*proto).__bindgen_anon_1.type_ })?;
        if unsafe { ((*ret).info >> 24) & 31 } != bpf::BTF_KIND_INT
            || unsafe { (*ret).__bindgen_anon_1.size } != ret_bytes
        {
            bail!("{name} return ABI differs");
        }
        let signed_return = name != "filemap_fault" && name != "handle_mm_fault";
        btf_integer(
            raw,
            unsafe { (*proto).__bindgen_anon_1.type_ },
            ret_bytes,
            signed_return,
        )?;
        let params =
            unsafe { std::slice::from_raw_parts(proto.add(1).cast::<bpf::btf_param>(), argc) };
        let pointer = btf_type(raw, params[0].type_)?;
        if unsafe { ((*pointer).info >> 24) & 31 } != bpf::BTF_KIND_PTR {
            bail!("{name} first argument must be pointer");
        }
        let target = btf_type(raw, unsafe { (*pointer).__bindgen_anon_1.type_ })?;
        if unsafe { ((*target).info >> 24) & 31 } != bpf::BTF_KIND_STRUCT
            || btf_name(raw, unsafe { (*target).name_off })? != first_struct
        {
            bail!("{name} first argument target differs");
        }
        if name == "vfs_read" || name == "vfs_readv" {
            btf_integer(raw, params[2].type_, 8, false)?;
            let pos = btf_type(raw, params[3].type_)?;
            if unsafe { ((*pos).info >> 24) & 31 } != bpf::BTF_KIND_PTR {
                bail!("VFS offset argument must be pointer");
            }
            btf_integer(raw, unsafe { (*pos).__bindgen_anon_1.type_ }, 8, true)?;
        }
        if name == "handle_mm_fault" {
            btf_integer(raw, params[1].type_, 8, false)?;
            btf_integer(raw, params[2].type_, 4, false)?;
        }
        anchors.push(
            json!({"name":name,"btf_function_id":id,"parameter_count":argc,"return_bytes":ret_bytes,
            "return_signed":signed_return,"first_argument_struct":first_struct}),
        );
    }
    let cname = CString::new("pt_regs")?;
    let id = unsafe { bpf::btf__find_by_name_kind(raw, cname.as_ptr(), bpf::BTF_KIND_STRUCT) };
    if id <= 0 {
        bail!("missing native pt_regs BTF");
    }
    let regs = btf_type(btf.0, id as u32)?;
    let count = unsafe { (*regs).info & 65535 } as usize;
    if count > 256 {
        bail!("excessive pt_regs fields");
    }
    let members =
        unsafe { std::slice::from_raw_parts(regs.add(1).cast::<bpf::btf_member>(), count) };
    for name in ["di", "si", "dx", "cx", "ax"] {
        let field = members
            .iter()
            .find(|m| btf_name(raw, m.name_off).map_or(false, |n| n == name))
            .context("missing pt_regs register")?;
        let ty = btf_type(raw, field.type_)?;
        if unsafe { ((*ty).info >> 24) & 31 } != bpf::BTF_KIND_INT
            || unsafe { (*ty).__bindgen_anon_1.size } != 8
        {
            bail!("pt_regs register must be native u64");
        }
    }
    Ok(
        json!({"status":"VALIDATED","architecture":"x86_64","anchors":anchors,
        "registers":["di","si","dx","cx","ax"],"kretprobe_maxactive":KRET_MAXACTIVE}),
    )
}

struct Sink {
    writer: BufWriter<File>,
    cap: u64,
    bytes: u64,
    records: u64,
    parser_errors: u64,
    cap_discarded: u64,
    write_errors: u64,
    last_seq: Vec<u64>,
    sequence_errors: u64,
    error: Option<String>,
}
impl Sink {
    fn new(path: &Path, cap: u64, cpus: usize) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::with_capacity(
                8 * 1024 * 1024,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)?,
            ),
            cap,
            bytes: 0,
            records: 0,
            parser_errors: 0,
            cap_discarded: 0,
            write_errors: 0,
            last_seq: vec![0; cpus],
            sequence_errors: 0,
            error: None,
        })
    }
    fn receive(&mut self, bytes: &[u8]) {
        if bytes.len() != EVENT_BYTES {
            self.parser_errors += 1;
            return;
        }
        let event = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<Event>()) };
        if validate(&event, self.last_seq.len()).is_err() {
            self.parser_errors += 1;
            return;
        }
        let previous = &mut self.last_seq[event.cpu as usize];
        // Nested contexts may reserve/submit in a different sequence order.
        // The offline verifier checks uniqueness and final counter ranges.
        *previous = (*previous).max(event.cpu_seq);
        if self.bytes + EVENT_BYTES as u64 > self.cap {
            self.cap_discarded += 1;
            return;
        }
        if self.error.is_some() {
            self.write_errors += 1;
            return;
        }
        if let Err(error) = self.writer.write_all(bytes) {
            self.write_errors += 1;
            self.error = Some(error.to_string());
            return;
        }
        self.bytes += EVENT_BYTES as u64;
        self.records += 1;
    }
    fn finish(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(())
    }
    fn digest_after_flush(&self) -> Result<String> {
        // Deliberately outside the workload recording window. Reuse the held
        // inode rather than trusting that the output pathname was unchanged.
        if !self.writer.buffer().is_empty() {
            bail!("event file must be flushed before hashing");
        }
        let original = self.writer.get_ref();
        let before = original.metadata()?;
        let identity = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        let mut reader = original.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = vec![0u8; 8 * 1024 * 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            bytes += count as u64;
        }
        let after = original.metadata()?;
        if identity(&before) != identity(&after) || bytes != after.len() || bytes != self.bytes {
            bail!("persisted event file changed or has a partial/unaccounted write");
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}
fn validate_ring_budget(bytes: u32) -> Result<()> {
    if !(16 * 1024 * 1024..=512 * 1024 * 1024).contains(&bytes) || !bytes.is_power_of_two() {
        bail!("ring-bytes must be a power of two between 16777216 and 536870912");
    }
    Ok(())
}
fn validate(event: &Event, cpus: usize) -> Result<()> {
    if event.magic != MAGIC
        || event.version != 1
        || event.size as usize != EVENT_BYTES
        || !(1..=6).contains(&event.kind)
        || event.cpu as usize >= cpus
        || event.cpu_seq == 0
        || event.flags & !(1 | 2 | 4 | 8 | 32 | 64 | 128 | 256 | 512) != 0
        || event.end_ns < event.start_ns
        || event.start_ns == 0
        || event.domain_id == 0
        || event.tgid == 0
        || event.tid == 0
    {
        bail!("invalid file-access event");
    }
    if event.flags & 1 != 0 && (event.mount_id == 0 || event.inode == 0) {
        bail!("object marked resolved without identity");
    }
    if event.flags & 512 != 0 && (event.kind != 6 || event.flags & 1 != 0) {
        bail!("NO_FILE_VMA classification is only a resolved null-file MM VMA");
    }
    if event.kind == 5 || event.kind == 6 {
        if event.flags & 64 == 0 || event.flags & 8 != 0 || event.syscall_nr != u32::MAX {
            bail!("invalid fault contract");
        }
    } else if event.flags & 8 == 0
        || event.syscall_start_ns == 0
        || event.syscall_end_ns < event.end_ns
        || event.start_ns < event.syscall_start_ns
    {
        bail!("invalid syscall correlation");
    }
    Ok(())
}
unsafe extern "C" fn receive(
    context: *mut libc::c_void,
    data: *mut libc::c_void,
    size: u64,
) -> i32 {
    let sink = &mut *(context as *mut Sink);
    if data.is_null() || size > EVENT_BYTES as u64 {
        sink.parser_errors += 1;
        return 0;
    }
    sink.receive(std::slice::from_raw_parts(data as *const u8, size as usize));
    0
}

struct Collector {
    object: *mut bpf::bpf_object,
    links: Vec<*mut bpf::bpf_link>,
    ring: *mut bpf::ring_buffer,
    config_fd: i32,
    calls_fd: i32,
    pending_fd: i32,
    faults_fd: i32,
    mm_faults_fd: i32,
    health_fd: i32,
    totals_fd: i32,
    cpus: usize,
    roots: Vec<(File, Value, Domain)>,
    emit_events: bool,
    backend: String,
    trace_events: Vec<TraceEvent>,
    hook_abi: Value,
    online_cpus: String,
}
impl Collector {
    fn open(args: &Args) -> Result<(Self, String)> {
        native_arch(std::env::consts::ARCH)?;
        if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
            bail!("file-access pgoff ABI requires x86-64 base page size 4096");
        }
        let hook_abi = if args.backend == "kprobe-tracefs" {
            validate_kprobe_abi()?
        } else {
            json!({"status":"FENTRY_BTF_PROTOTYPE_VERIFIED_BY_KERNEL_LOADER"})
        };
        let roots = domains(&args.cgroup)?;
        let bytes = fs::read(&args.bpf_object)?;
        if bytes.len() > 2 * 1024 * 1024 {
            bail!("BPF object exceeds 2 MiB");
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if digest != args.bpf_sha256.to_ascii_lowercase() {
            bail!("BPF digest mismatch");
        }
        let name = CString::new("file_access")?;
        let opts = bpf::bpf_object_open_opts {
            sz: std::mem::size_of::<bpf::bpf_object_open_opts>() as u64,
            object_name: name.as_ptr(),
            ..unsafe { std::mem::zeroed() }
        };
        let object =
            unsafe { bpf::bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len() as u64, &opts) };
        if pointer_bad(object) {
            bail!("open file-access BPF object");
        }
        let mut this = Self {
            object,
            links: Vec::new(),
            ring: ptr::null_mut(),
            config_fd: -1,
            calls_fd: -1,
            pending_fd: -1,
            faults_fd: -1,
            mm_faults_fd: -1,
            health_fd: -1,
            totals_fd: -1,
            cpus: 0,
            roots,
            emit_events: args.mode == "events",
            backend: args.backend.clone(),
            trace_events: Vec::new(),
            hook_abi,
            online_cpus: fs::read_to_string("/sys/devices/system/cpu/online")?
                .trim()
                .to_owned(),
        };
        let ring_name = CString::new("fa_events")?;
        let ring_map = unsafe { bpf::bpf_object__find_map_by_name(object, ring_name.as_ptr()) };
        if ring_map.is_null() {
            bail!("missing fa_events ring");
        }
        rc(
            unsafe { bpf::bpf_map__set_max_entries(ring_map, args.ring_bytes) },
            "set explicit ring budget",
        )?;
        rc(
            unsafe { bpf::bpf_object__load(object) },
            "load required file access BTF hooks",
        )?;
        if unsafe { bpf::bpf_map__max_entries(ring_map) } != args.ring_bytes {
            bail!("loaded ring allocation differs from requested budget");
        }
        this.config_fd = map(object, "fa_config", 4, 16)?;
        this.calls_fd = map(object, "fa_calls", 8, EVENT_BYTES as u32)?;
        this.pending_fd = map(object, "fa_pending", 8, 200)?;
        this.faults_fd = map(object, "fa_faults", 8, 200)?;
        this.mm_faults_fd = map(object, "fa_mm_faults", 8, 200)?;
        this.health_fd = map(object, "fa_health", 4, 8)?;
        this.totals_fd = map(object, "fa_totals", 4, 24)?;
        let domain_fd = map(object, "fa_domains", 4, 16)?;
        let count = unsafe { bpf::libbpf_num_possible_cpus() };
        if count <= 0 {
            bail!("cannot count possible CPUs");
        }
        this.cpus = count as usize;
        for (i, (_, _, root)) in this.roots.iter().enumerate() {
            update(domain_fd, i as u32, root)?;
        }
        this.configure(false)?;
        let mut program = ptr::null_mut();
        let mut names = Vec::new();
        loop {
            program = unsafe { bpf::bpf_object__next_program(object, program) };
            if program.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr(bpf::bpf_program__name(program)) }
                .to_string_lossy()
                .into_owned();
            let section =
                unsafe { CStr::from_ptr(bpf::bpf_program__section_name(program)) }.to_str()?;
            let is_tracepoint = section.starts_with("tracepoint/");
            if !is_tracepoint && this.backend == "kprobe-tracefs" {
                let (is_return, anchor) = if let Some(anchor) = section.strip_prefix("kretprobe/") {
                    (true, anchor)
                } else if let Some(anchor) = section.strip_prefix("kprobe/") {
                    (false, anchor)
                } else {
                    bail!("kprobe-tracefs backend requires kprobe object sections");
                };
                this.attach_trace(program, &name, anchor, is_return)?;
            } else {
                if !(is_tracepoint
                    || section.starts_with("fentry/")
                    || section.starts_with("fexit/"))
                {
                    bail!("fentry backend requires fentry/fexit object sections");
                }
                let link = unsafe { bpf::bpf_program__attach(program) };
                if pointer_bad(link) {
                    bail!("attach required hook {name}");
                }
                this.links.push(link);
            }
            names.push(name);
        }
        names.sort();
        let mut required = REQUIRED_PROGRAMS.to_vec();
        required.sort_unstable();
        if names != required {
            bail!("BPF program set differs from required ABI");
        }
        Ok((this, digest))
    }
    fn attach_trace(
        &mut self,
        program: *mut bpf::bpf_program,
        program_name: &str,
        anchor: &str,
        is_return: bool,
    ) -> Result<()> {
        let root = [
            Path::new("/sys/kernel/tracing"),
            Path::new("/sys/kernel/debug/tracing"),
        ]
        .into_iter()
        .find(|root| root.join("kprobe_events").is_file())
        .context("kprobe-tracefs requires mounted writable tracefs and readable kprobe_profile")?;
        let root = fs::canonicalize(root)?;
        let uuid = fs::read_to_string("/proc/sys/kernel/random/uuid")?
            .trim()
            .replace('-', "");
        if uuid.len() != 32 || !uuid.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid UUID");
        }
        let name = format!("alloxfa_{uuid}_{program_name}");
        if root.join("events").join(TRACE_GROUP).join(&name).exists() {
            bail!("owned event already exists");
        }
        let prefix = if is_return {
            format!("r{KRET_MAXACTIVE}")
        } else {
            "p".to_owned()
        };
        trace_command(&root, &format!("{prefix}:{TRACE_GROUP}/{name} {anchor}\n"))?;
        self.trace_events.push(TraceEvent {
            root,
            name,
            program: program_name.to_owned(),
            anchor: anchor.to_owned(),
            is_return,
            definition: None,
            identity: None,
            initial: None,
        });
        let event = self.trace_events.last_mut().unwrap();
        event.definition = Some(event.definition()?);
        event.identity = Some(event.identity()?);
        event.initial = Some(event.profile()?);
        let cpu = self
            .online_cpus
            .split(',')
            .next()
            .and_then(|v| v.split('-').next())
            .context("no online CPU")?
            .parse::<i32>()?;
        let attr = bpf::perf_event_attr {
            type_: bpf::PERF_TYPE_TRACEPOINT,
            size: std::mem::size_of::<bpf::perf_event_attr>() as u32,
            config: event.identity.unwrap().2,
            ..unsafe { std::mem::zeroed() }
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr,
                -1,
                cpu,
                -1,
                bpf::PERF_FLAG_FD_CLOEXEC,
            )
        } as i32;
        if fd < 0 {
            bail!(
                "open owned trace perf event: {}",
                io::Error::last_os_error()
            );
        }
        // Trace-kprobe's global prog_array runs on all CPUs. Attach once,
        // not once per CPU; no perf sample ring or payload is requested.
        let link = unsafe { bpf::bpf_program__attach_perf_event(program, fd) };
        if pointer_bad(link) {
            unsafe { libc::close(fd) };
            bail!("attach owned trace hook {program_name}");
        }
        self.links.push(link);
        Ok(())
    }
    fn trace_receipts(&self) -> (Vec<Value>, bool) {
        let rows = self
            .trace_events
            .iter()
            .map(TraceEvent::evidence)
            .collect::<Vec<_>>();
        (
            rows.iter().map(|(row, _)| row.clone()).collect(),
            rows.iter().any(|(_, bad)| *bad),
        )
    }
    fn cleanup_trace(&mut self) -> Value {
        let owned = self.trace_events.len();
        let mut errors = Vec::new();
        let mut retained = Vec::new();
        for event in self.trace_events.drain(..).rev() {
            if let Err(error) = event.remove() {
                errors.push(json!({"name":event.name,"error":error.to_string()}));
                retained.push(event);
            }
        }
        self.trace_events = retained;
        json!({"status":if errors.is_empty(){"COMPLETE"}else{"INCOMPLETE"},"owned_events":owned,
            "remaining_owned_events":self.trace_events.len(),"errors":errors,
            "order":"disable owned perf handlers; collect terminal profiles; verify exact definitions/inode/event_id; delete only owned UUID events"})
    }
    fn configure(&self, enabled: bool) -> Result<()> {
        update(
            self.config_fd,
            0,
            &Config {
                count: self.roots.len() as u32,
                enabled: enabled as u32,
                emit_events: self.emit_events as u32,
                reserved: 0,
            },
        )
    }
    fn start_ring(&mut self, sink: &mut Sink) -> Result<()> {
        let fd = map(self.object, "fa_events", 0, 0)?;
        self.ring = unsafe {
            bpf::ring_buffer__new(fd, Some(receive), (sink as *mut Sink).cast(), ptr::null())
        };
        if pointer_bad(self.ring) {
            bail!("create event ring consumer");
        }
        Ok(())
    }
    fn poll(&self, millis: i32) -> Result<i32> {
        let code = unsafe { bpf::ring_buffer__poll(self.ring, millis) };
        if code < 0 && code != -libc::EINTR {
            bail!("poll ring: {}", io::Error::from_raw_os_error(-code));
        }
        Ok(code)
    }
    fn detach(&mut self) -> Result<()> {
        self.configure(false)?;
        for link in self.links.drain(..).rev() {
            unsafe { bpf::bpf_link__destroy(link) };
        }
        Ok(())
    }
    fn active(&self, fd: i32) -> Result<usize> {
        let mut prev: Option<u64> = None;
        let mut count = 0;
        loop {
            let mut next = 0u64;
            let code = unsafe {
                bpf::bpf_map_get_next_key(
                    fd,
                    prev.as_ref()
                        .map_or(ptr::null(), |v| (v as *const u64).cast()),
                    (&mut next as *mut u64).cast(),
                )
            };
            if code != 0 {
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    bail!("enumerate pending map");
                }
                return Ok(count);
            }
            count += 1;
            if count > THREAD_LIMIT {
                bail!("pending-map enumeration bound");
            }
            prev = Some(next);
        }
    }
    fn health(&self) -> Result<(Value, bool)> {
        let mut health = serde_json::Map::new();
        let mut incomplete = false;
        for (index, name) in HEALTH.iter().enumerate() {
            let mut values = vec![0u64; self.cpus];
            let key = index as u32;
            rc(
                unsafe {
                    bpf::bpf_map_lookup_elem(
                        self.health_fd,
                        (&key as *const u32).cast(),
                        values.as_mut_ptr().cast(),
                    )
                },
                "read health",
            )?;
            let total: u64 = values.into_iter().sum();
            if total != 0 && *name != "nested_hooks" {
                incomplete = true;
            }
            health.insert((*name).into(), json!(total));
        }
        Ok((Value::Object(health), incomplete))
    }
    fn totals(&self) -> Result<Vec<Totals>> {
        let mut values = vec![Totals::default(); self.cpus];
        let zero = 0u32;
        rc(
            unsafe {
                bpf::bpf_map_lookup_elem(
                    self.totals_fd,
                    (&zero as *const u32).cast(),
                    values.as_mut_ptr().cast(),
                )
            },
            "read per-CPU totals",
        )?;
        Ok(values)
    }
    fn programs(&self) -> Result<(Vec<Value>, bool)> {
        let mut rows = Vec::new();
        let mut program = ptr::null_mut();
        let mut incomplete = false;
        loop {
            program = unsafe { bpf::bpf_object__next_program(self.object, program) };
            if program.is_null() {
                break;
            }
            let mut info: bpf::bpf_prog_info = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of::<bpf::bpf_prog_info>() as u32;
            rc(
                unsafe {
                    bpf::bpf_obj_get_info_by_fd(
                        bpf::bpf_program__fd(program),
                        (&mut info as *mut bpf::bpf_prog_info).cast(),
                        &mut size,
                    )
                },
                "read hook health",
            )?;
            let misses = info.recursion_misses;
            incomplete |= misses != 0;
            rows.push(json!({"name": unsafe { CStr::from_ptr(bpf::bpf_program__name(program)) }.to_string_lossy(),
                "id":info.id,"recursion_misses":misses}));
        }
        Ok((rows, incomplete))
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        for link in self.links.drain(..).rev() {
            unsafe { bpf::bpf_link__destroy(link) };
        }
        // Never remove an event whose exact identity/definition changed.
        let _ = self.cleanup_trace();
        if !pointer_bad(self.ring) {
            unsafe { bpf::ring_buffer__free(self.ring) };
        }
        if !pointer_bad(self.object) {
            unsafe { bpf::bpf_object__close(self.object) };
        }
    }
}
fn run(args: Args) -> Result<()> {
    validate_ring_budget(args.ring_bytes)?;
    if args.max_seconds == 0 || args.max_seconds > 3600 {
        bail!("max-seconds must be 1..3600");
    }
    if args.max_bytes < EVENT_BYTES as u64 || args.max_bytes > 64 * 1024 * 1024 * 1024 {
        bail!("max-bytes must be 192..68719476736");
    }
    if args.mode != "events" && args.mode != "counters" {
        bail!("mode must be events or counters");
    }
    if args.backend != "fentry" && args.backend != "kprobe-tracefs" {
        bail!("backend must be fentry or kprobe-tracefs");
    }
    if args.run_id.is_empty() || args.run_id.len() > 256 {
        bail!("invalid run-id");
    }
    let (mut collector, digest) = Collector::open(&args)?;
    fs::create_dir(&args.output_dir).context("output directory must not exist")?;
    let mut sink = Box::new(Sink::new(
        &args.output_dir.join("events.bin"),
        args.max_bytes,
        collector.cpus,
    )?);
    collector.start_ring(&mut sink)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let start = ns(libc::CLOCK_MONOTONIC);
    let binary = fs::read(std::env::current_exe()?)?;
    let meta = json!({"schema_version":1,"run_id":args.run_id,"boot_id":boot,
        "start_monotonic_ns":start,"start_boottime_ns":ns(libc::CLOCK_BOOTTIME),
        "domains":collector.roots.iter().map(|(_, id, _)| id).collect::<Vec<_>>(),
        "bpf_sha256":digest,"binary_sha256":format!("{:x}",Sha256::digest(binary)),
        "bpf_source_sha256":format!("{:x}",Sha256::digest(include_bytes!("../../../../bpf/file_access.bpf.c"))),
        "header_sha256":format!("{:x}",Sha256::digest(include_bytes!("../../../../bpf/file_access.h"))),
        "record_bytes":EVENT_BYTES,"event_magic":MAGIC,"event_abi_version":1,"endian":"little",
        "mode":args.mode,"max_bytes":args.max_bytes,"ring_bytes":args.ring_bytes,
        "event_hashing":"AFTER_DISABLE_DETACH_DRAIN_FLUSH_FSYNC_USING_HELD_INODE_NOT_PER_EVENT_HOT_PATH",
        "hash_scope":"DETACHED_DRAINED_FSYNCED_FD_PASS",
        "backend":args.backend,"hook_abi":collector.hook_abi,
        "kretprobe_maxactive":if args.backend=="kprobe-tracefs"{Some(KRET_MAXACTIVE)}else{None},
        "kprobe_events":collector.trace_events.iter().map(|event|event.evidence().0).collect::<Vec<_>>(),
        "online_cpus":collector.online_cpus,
        "possible_cpus":collector.cpus,"cpu_seq_contract":"ONE_BASED_ATTEMPT_BEFORE_RESERVATION_PER_CPU",
        "native_syscall_abi":"X86_64_EXCLUDING_TS_COMPAT_AND_X32",
        "page_size":4096,"page_shift":12,
        "vm_fault_flags_contract":{"major":4,"retry":1024,"error_mask":2163},
        "required_programs":REQUIRED_PROGRAMS,
        "start_boundary_scope":"PRE_ENABLE_LOWER_BOUND_REQUIRES_WORKLOAD_READY_GATE",
        "limits":["Opt-in diagnostic side channel, not audit evidence or a security verdict",
          "read/pread64/readv/preadv/preadv2 outermost synchronous VFS paths only; requested readv bytes UNKNOWN",
          "Successful open identity from security_file_open, syscall return determines success",
          "handle_mm_fault attempts classify file-backed, NO_FILE_VMA or unresolved; RETRY/ERROR are not successful unique faults",
          "NO_FILE_VMA flag512 means vm_file was read successfully as NULL; it does not prove vma_is_anonymous or ordinary heap/stack",
          "filemap_fault is a nested refill subpath; never add its attempts to handle_mm_fault or process page-fault totals",
          "Buffered read cache misses are not filemap_fault or necessarily major page faults",
          "No read-buffer contents, paths, io_uring, splice/sendfile, delegated or asynchronous read attribution",
          "VFS duration and syscall duration are distinct; successful read bytes are not physical disk bytes",
          "Selected syscalls failing before VFS are retained without an object; their start/end denote SYSCALL, not VFS",
          "Identity metadata is not an inode-reuse-proof version; frozen-scope path inventory is external",
          "Hook recursion misses and all loss/cap/pending/error counters are retained as INCOMPLETE"]});
    write_new(&args.output_dir.join("meta.json"), &meta)?;
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::signal(signal, stop as usize) } == libc::SIG_ERR {
            bail!("signal handler");
        }
    }
    collector.configure(true)?;
    let mut ready = meta.clone();
    ready["type"] = json!("READY");
    println!("{}", serde_json::to_string(&ready)?);
    io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    while !STOP.load(Ordering::SeqCst) && Instant::now() < deadline {
        collector.poll(20)?;
    }
    let timed_out = !STOP.load(Ordering::SeqCst);
    collector.detach()?;
    while collector.poll(0)? > 0 {}
    let end = ns(libc::CLOCK_MONOTONIC);
    let flush_error = sink.finish().err().map(|error| error.to_string());
    let (events_digest, hash_error) = match sink.digest_after_flush() {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let (health, kernel_incomplete) = collector.health()?;
    let (programs, recursion_incomplete) = collector.programs()?;
    let (trace_receipts, trace_incomplete) = collector.trace_receipts();
    let trace_cleanup = collector.cleanup_trace();
    let current_cpus = fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .map(|v| v.trim().to_owned());
    let cpu_incomplete = current_cpus.as_ref() != Some(&collector.online_cpus);
    let totals = collector.totals()?;
    let pending_syscalls = collector.active(collector.calls_fd)?;
    let pending_vfs_calls = collector.active(collector.pending_fd)?;
    let pending_fault_calls = collector.active(collector.faults_fd)?;
    let pending_mm_fault_calls = collector.active(collector.mm_faults_fd)?;
    let emitted: u64 = totals.iter().map(|v| v.emitted).sum();
    let incomplete = timed_out
        || kernel_incomplete
        || recursion_incomplete
        || trace_incomplete
        || trace_cleanup["status"] != "COMPLETE"
        || cpu_incomplete
        || pending_syscalls != 0
        || pending_vfs_calls != 0
        || pending_fault_calls != 0
        || pending_mm_fault_calls != 0
        || sink.parser_errors != 0
        || sink.sequence_errors != 0
        || sink.cap_discarded != 0
        || sink.write_errors != 0
        || flush_error.is_some()
        || hash_error.is_some()
        || sink.records != emitted;
    let mut result = meta;
    result["end_monotonic_ns"] = json!(end);
    result["observation_health"] = json!(if incomplete {
        "INCOMPLETE"
    } else {
        "COMPLETE_FOR_SELECTED_HOOKS"
    });
    result["timed_out"] = json!(timed_out);
    result["health"] = health;
    result["programs"] = json!(programs);
    result["kprobe_event_health"] = json!(trace_receipts);
    result["tracefs_cleanup"] = trace_cleanup;
    result["online_cpu_identity"] = json!({"initial":collector.online_cpus,"current":current_cpus,
        "status":if cpu_incomplete{"CHANGED_OR_UNKNOWN"}else{"STABLE"}});
    result["cpus"] = json!(totals
        .iter()
        .enumerate()
        .map(|(cpu, v)| json!({"cpu":cpu,
        "attempted":v.attempted,"emitted":v.emitted,"ring_drops":v.ring_drops}))
        .collect::<Vec<_>>());
    result["pending_syscalls"] = json!(pending_syscalls);
    result["pending_vfs_calls"] = json!(pending_vfs_calls);
    result["pending_fault_calls"] = json!(pending_fault_calls);
    result["pending_mm_fault_calls"] = json!(pending_mm_fault_calls);
    result["persisted_records"] = json!(sink.records);
    result["bytes"] = json!(sink.bytes);
    result["events_sha256"] = json!(events_digest);
    result["hash_error"] = json!(hash_error);
    result["parser_errors"] = json!(sink.parser_errors);
    result["sequence_errors"] = json!(sink.sequence_errors);
    result["cap_discarded"] = json!(sink.cap_discarded);
    result["write_errors"] = json!(sink.write_errors);
    result["write_error"] = json!(sink.error);
    result["flush_error"] = json!(flush_error);
    write_new(&args.output_dir.join("final.json"), &result)?;
    Ok(())
}
fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abi() {
        assert_eq!(std::mem::size_of::<Event>(), EVENT_BYTES);
        assert_eq!(std::mem::size_of::<Domain>(), 16);
        assert_eq!(std::mem::size_of::<Config>(), 16);
        assert_eq!(std::mem::size_of::<Totals>(), 24);
        let event = Event::default();
        let base = &event as *const _ as usize;
        assert_eq!(&event.cpu_seq as *const _ as usize - base, 16);
        assert_eq!(&event.start_ns as *const _ as usize - base, 56);
        assert_eq!(&event.mount_id as *const _ as usize - base, 88);
        assert_eq!(&event.result as *const _ as usize - base, 128);
        assert_eq!(&event.device as *const _ as usize - base, 160);
        assert_eq!(&event.vm_fault_result as *const _ as usize - base, 188);
    }
    fn event() -> Event {
        Event {
            magic: MAGIC,
            version: 1,
            kind: 1,
            size: EVENT_BYTES as u32,
            flags: 1 | 8 | 128,
            cpu_seq: 1,
            domain_id: 1,
            tgid: 2,
            tid: 2,
            start_ns: 10,
            end_ns: 20,
            syscall_start_ns: 5,
            syscall_end_ns: 25,
            mount_id: 1,
            inode: 2,
            ..Event::default()
        }
    }
    #[test]
    fn validation() {
        let mut e = event();
        assert!(validate(&e, 2).is_ok());
        e.end_ns = 9;
        assert!(validate(&e, 2).is_err());
        e = event();
        e.flags |= 16;
        assert!(validate(&e, 2).is_err());
        e = event();
        e.cpu_seq = 0;
        assert!(validate(&e, 2).is_err());
        e = event();
        e.inode = 0;
        assert!(validate(&e, 2).is_err());
        e = event();
        e.cpu = 2;
        assert!(validate(&e, 2).is_err());
    }
    #[test]
    fn fault_attempt_not_syscall() {
        let mut e = event();
        e.kind = 5;
        e.syscall_nr = u32::MAX;
        e.flags = 1 | 32 | 64 | 128;
        assert!(validate(&e, 2).is_ok());
        e.flags |= 8;
        assert!(validate(&e, 2).is_err());
    }
    #[test]
    fn no_file_vma_is_explicit_not_missing_object() {
        let mut e = event();
        e.kind = 6;
        e.syscall_nr = u32::MAX;
        e.flags = 32 | 64 | 512;
        e.inode = 0;
        e.mount_id = 0;
        assert!(validate(&e, 2).is_ok());
        e.flags |= 1;
        assert!(validate(&e, 2).is_err());
        e.flags = 32 | 64 | 512;
        e.kind = 5;
        assert!(validate(&e, 2).is_err());
    }
    struct TempFile(PathBuf);
    impl TempFile {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "allox-file-access-test-{}-{}",
                std::process::id(),
                ns(libc::CLOCK_MONOTONIC)
            )))
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn encoded(e: &Event) -> &[u8] {
        // ABI has no padding: each byte belongs to an initialized field.
        unsafe { std::slice::from_raw_parts((e as *const Event).cast(), EVENT_BYTES) }
    }
    #[test]
    fn byte_cap_never_writes_partial_records() {
        let file = TempFile::new();
        let mut sink = Sink::new(&file.0, EVENT_BYTES as u64, 2).unwrap();
        let mut e = event();
        sink.receive(encoded(&e));
        e.cpu_seq = 2;
        sink.receive(encoded(&e));
        sink.finish().unwrap();
        assert_eq!(sink.records, 1);
        assert_eq!(sink.bytes, EVENT_BYTES as u64);
        assert_eq!(sink.cap_discarded, 1);
        assert_eq!(fs::metadata(&file.0).unwrap().len(), EVENT_BYTES as u64);
        assert_eq!(fs::read(&file.0).unwrap(), encoded(&event()));
        assert_eq!(
            sink.digest_after_flush().unwrap(),
            format!("{:x}", Sha256::digest(encoded(&event())))
        );
    }
    #[test]
    fn malformed_payload_is_not_persisted() {
        let file = TempFile::new();
        let mut sink = Sink::new(&file.0, 1024, 2).unwrap();
        sink.receive(&[0; 191]);
        let mut e = event();
        e.magic = 0;
        sink.receive(encoded(&e));
        sink.finish().unwrap();
        assert_eq!(sink.parser_errors, 2);
        assert_eq!(sink.records, 0);
        assert_eq!(fs::metadata(&file.0).unwrap().len(), 0);
    }
    #[test]
    fn cpu_sequence_reordering_is_not_silently_treated_as_loss() {
        let file = TempFile::new();
        let mut sink = Sink::new(&file.0, 1024, 2).unwrap();
        let mut e = event();
        e.cpu_seq = 2;
        sink.receive(encoded(&e));
        e.cpu_seq = 1;
        sink.receive(encoded(&e));
        sink.finish().unwrap();
        assert_eq!(sink.records, 2);
        assert_eq!(sink.sequence_errors, 0);
        assert_eq!(sink.last_seq[0], 2);
    }
    #[test]
    fn trace_profile_rejects_missing_duplicate_and_malformed_rows() {
        assert_eq!(
            trace_profile("target 12 3\nother 1 0\n", "target").unwrap(),
            [12, 3]
        );
        for text in [
            "other 1 0\n",
            "target 1 0\ntarget 2 0\n",
            "target 1\n",
            "target nope 0\n",
        ] {
            assert!(trace_profile(text, "target").is_err());
        }
    }
    #[test]
    fn ring_budget_is_explicit_bounded_power_of_two() {
        for mib in [16, 32, 64, 128, 256, 512] {
            assert!(validate_ring_budget(mib * 1024 * 1024).is_ok());
        }
        for bytes in [0, 1, 8 * 1024 * 1024, 24 * 1024 * 1024, 1024 * 1024 * 1024] {
            assert!(validate_ring_budget(bytes).is_err());
        }
    }
    #[test]
    fn post_flush_hash_rejects_partial_or_unaccounted_file() {
        let file = TempFile::new();
        let mut sink = Sink::new(&file.0, 1024, 2).unwrap();
        sink.receive(encoded(&event()));
        assert!(sink.digest_after_flush().is_err());
        sink.finish().unwrap();
        assert!(sink.digest_after_flush().is_ok());
        OpenOptions::new()
            .append(true)
            .open(&file.0)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(sink.digest_after_flush().is_err());
    }
    #[test]
    fn post_flush_hash_uses_held_inode_not_replaced_pathname() {
        let file = TempFile::new();
        let moved = TempFile::new();
        let mut sink = Sink::new(&file.0, 1024, 2).unwrap();
        sink.receive(encoded(&event()));
        sink.finish().unwrap();
        fs::rename(file.0.as_path(), moved.0.as_path()).unwrap();
        fs::write(&file.0, b"replacement pathname").unwrap();
        assert_eq!(
            sink.digest_after_flush().unwrap(),
            format!("{:x}", Sha256::digest(encoded(&event())))
        );
    }
    struct TempTrace {
        root: PathBuf,
    }
    impl TempTrace {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "allox-file-access-trace-test-{}-{}",
                std::process::id(),
                ns(libc::CLOCK_MONOTONIC)
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(root.join("events").join(TRACE_GROUP).join("owned")).unwrap();
            fs::write(
                root.join("events").join(TRACE_GROUP).join("owned/id"),
                "17\n",
            )
            .unwrap();
            fs::write(
                root.join("kprobe_events"),
                format!("r4096:{TRACE_GROUP}/owned vfs_read\n"),
            )
            .unwrap();
            fs::write(root.join("kprobe_profile"), "owned 12 0\n").unwrap();
            Self { root }
        }
        fn event(&self) -> TraceEvent {
            let mut event = TraceEvent {
                root: self.root.clone(),
                name: "owned".into(),
                program: "fa_read_exit".into(),
                anchor: "vfs_read".into(),
                is_return: true,
                definition: None,
                identity: None,
                initial: Some([10, 0]),
            };
            event.definition = Some(event.definition().unwrap());
            event.identity = Some(event.identity().unwrap());
            event
        }
    }
    impl Drop for TempTrace {
        fn drop(&mut self) {
            // Exact private directory created by this fixture, never a user path.
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn owned_trace_receipt_keeps_misses_and_counter_reset_unknown() {
        let tree = TempTrace::new();
        let event = tree.event();
        let (row, bad) = event.evidence();
        assert!(!bad);
        assert_eq!(row["profile_status"], "OBSERVED");
        assert_eq!(row["misses_delta"], 0);
        fs::write(tree.root.join("kprobe_profile"), "owned 20 1\n").unwrap();
        let (row, bad) = event.evidence();
        assert!(bad);
        assert_eq!(row["misses_delta"], 1);
        fs::write(tree.root.join("kprobe_profile"), "owned 9 0\n").unwrap();
        let (row, bad) = event.evidence();
        assert!(bad);
        assert_eq!(row["profile_status"], "UNKNOWN");
        assert!(row["misses_delta"].is_null());
    }
    #[test]
    fn changed_maxactive_or_identity_refuses_owned_cleanup() {
        let tree = TempTrace::new();
        let mut event = tree.event();
        let changed = format!("r1024:{TRACE_GROUP}/owned vfs_read\n");
        fs::write(tree.root.join("kprobe_events"), &changed).unwrap();
        assert!(event.remove().is_err());
        assert_eq!(
            fs::read_to_string(tree.root.join("kprobe_events")).unwrap(),
            changed
        );
        fs::write(
            tree.root.join("kprobe_events"),
            event.definition.as_ref().unwrap(),
        )
        .unwrap();
        let (dev, inode, id) = event.identity.unwrap();
        event.identity = Some((dev, inode + 1, id));
        assert!(event.remove().is_err());
        assert!(event.evidence().1);
    }
    #[test]
    fn native_only() {
        assert!(native_arch("x86_64").is_ok());
        assert!(native_arch("aarch64").is_err());
        assert!(native_arch("x86").is_err());
    }
}
