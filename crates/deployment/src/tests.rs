// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::discover::{discover_with_roots, DiscoveryRoots};
use crate::revalidate::validate_against_roots;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    roots: DiscoveryRoots,
    executable_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "bpf-observer-deployment-test-{}-{sequence}",
            std::process::id()
        ));
        let procfs = root.join("proc");
        let cgroupfs = root.join("cgroup");
        let sysfs = root.join("sys");
        let executable_dir = root.join("bin");
        fs::create_dir_all(procfs.join("sys/kernel/random")).unwrap();
        fs::create_dir_all(&cgroupfs).unwrap();
        fs::create_dir_all(sysfs.join("class/net")).unwrap();
        fs::create_dir_all(&executable_dir).unwrap();
        fs::write(
            procfs.join("sys/kernel/random/boot_id"),
            b"01234567-89ab-cdef-0123-456789abcdef\n",
        )
        .unwrap();
        Self {
            root,
            roots: DiscoveryRoots {
                procfs,
                cgroupfs,
                sysfs,
                source_trust: DiscoverySourceTrust::FixtureUntrusted,
            },
            executable_dir,
        }
    }

    fn executable(&self, name: &str) -> PathBuf {
        let path = self.executable_dir.join(name);
        fs::write(&path, b"fixture executable\n").unwrap();
        path
    }

    fn add_cgroup(&self, path: &str, pids: &[u32]) {
        let directory = self
            .roots
            .cgroupfs
            .join(path.strip_prefix('/').unwrap_or(path));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("cgroup.events"), b"populated 1\n").unwrap();
        let members = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(directory.join("cgroup.procs"), format!("{members}\n")).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn add_process(
        &self,
        pid: u32,
        executable: &Path,
        cgroup: &str,
        comm: &str,
        argv: &[&str],
        namespace_pids: &[u32],
        mnt_ns: u64,
        pid_ns: u64,
        net_ns: u64,
    ) {
        let directory = self.roots.procfs.join(pid.to_string());
        fs::create_dir_all(directory.join("ns")).unwrap();
        let mut tail = vec!["S".to_owned()];
        tail.extend((0..18).map(|_| "0".to_owned()));
        tail.push((10_000u64 + u64::from(pid)).to_string());
        fs::write(
            directory.join("stat"),
            format!("{pid} ({comm}) {}\n", tail.join(" ")),
        )
        .unwrap();
        fs::write(directory.join("comm"), format!("{comm}\n")).unwrap();
        let mut cmdline = argv.join("\0").into_bytes();
        cmdline.push(0);
        fs::write(directory.join("cmdline"), cmdline).unwrap();
        fs::write(directory.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
        fs::write(
            directory.join("status"),
            format!(
                "Name:\t{comm}\nNSpid:\t{}\n",
                namespace_pids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("\t")
            ),
        )
        .unwrap();
        symlink(executable, directory.join("exe")).unwrap();
        symlink(format!("mnt:[{mnt_ns}]"), directory.join("ns/mnt")).unwrap();
        symlink(format!("pid:[{pid_ns}]"), directory.join("ns/pid")).unwrap();
        symlink(format!("net:[{net_ns}]"), directory.join("ns/net")).unwrap();
        symlink(
            format!("uts:[{}]", mnt_ns + 10_000),
            directory.join("ns/uts"),
        )
        .unwrap();
        symlink(
            format!("ipc:[{}]", mnt_ns + 20_000),
            directory.join("ns/ipc"),
        )
        .unwrap();
    }

    fn add_observer_netns(&self, net_ns: u64) {
        let directory = self.roots.procfs.join("self/ns");
        fs::create_dir_all(&directory).unwrap();
        symlink(format!("net:[{net_ns}]"), directory.join("net")).unwrap();
    }

    fn add_tap(&self, name: &str, ifindex: u32) {
        let directory = self.roots.sysfs.join("class/net").join(name);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("ifindex"), format!("{ifindex}\n")).unwrap();
        fs::write(directory.join("tun_flags"), b"0x1002\n").unwrap();
    }

    fn add_tun_fd(&self, pid: u32, descriptor: u32, interface: &str) {
        let process = self.roots.procfs.join(pid.to_string());
        fs::create_dir_all(process.join("fd")).unwrap();
        fs::create_dir_all(process.join("fdinfo")).unwrap();
        symlink(
            &self.executable_dir,
            process.join("fd").join(descriptor.to_string()),
        )
        .unwrap();
        fs::write(
            process.join("fdinfo").join(descriptor.to_string()),
            format!("pos:\t0\nflags:\t02\niff:\t{interface}\n"),
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn request_validation_rejects_ambiguous_identifiers_and_paths() {
    let short_id = DeploymentRequest::Docker(DockerRequest::new("abcd", Some(42)));
    assert!(short_id.validate().is_err());

    let mut direct = DirectRequest::new(42);
    direct.expected_cgroup_path = Some("/agent//child".to_owned());
    assert!(DeploymentRequest::Direct(direct).validate().is_err());

    let mut kata = KataHostRequest::new("kata-sandbox", 42);
    kata.expected_hypervisor_pid = Some(42);
    assert!(DeploymentRequest::KataHost(kata).validate().is_err());
}

#[test]
fn direct_closure_allows_descendant_churn_but_detects_residual_processes() {
    let fixture = Fixture::new();
    let executable = fixture.executable("agent");
    fixture.add_cgroup("/agent", &[101]);
    fixture.add_cgroup("/agent/worker", &[102]);
    fixture.add_process(
        101,
        &executable,
        "/agent",
        "agent",
        &["agent"],
        &[101],
        1001,
        2001,
        3001,
    );
    fixture.add_process(
        102,
        &executable,
        "/agent/worker",
        "worker",
        &["agent", "worker"],
        &[102],
        1001,
        2001,
        3001,
    );
    let mut request = DirectRequest::new(101);
    request.require_dedicated_cgroup = false;
    request.expected_cgroup_path = Some("/agent".to_owned());
    let manifest = discover_with_roots(&DeploymentRequest::Direct(request), &fixture.roots)
        .expect("discover direct fixture");

    assert_eq!(manifest.processes.len(), 2);
    assert_eq!(manifest.registration_cgroup_ids().len(), 2);
    assert_eq!(manifest.registration_root_cgroup_ids().len(), 1);
    assert_eq!(
        manifest.coverage.descendant_observation_requirement,
        DescendantObservationRequirement::CgroupV2AncestorMatchRequired
    );
    assert!(
        validate_against_roots(&manifest, RevalidationPhase::Ready, &fixture.roots)
            .unwrap()
            .is_stable()
    );

    fixture.add_cgroup("/agent/new-after-ready", &[]);
    let closure =
        validate_against_roots(&manifest, RevalidationPhase::Closure, &fixture.roots).unwrap();
    assert!(closure.is_stable());
    let ready_changed =
        validate_against_roots(&manifest, RevalidationPhase::Ready, &fixture.roots).unwrap();
    assert!(!ready_changed.is_stable());
    assert!(ready_changed
        .mismatches
        .iter()
        .any(|mismatch| matches!(mismatch, ValidationMismatch::CgroupSetChanged { .. })));

    fixture.add_cgroup("/agent/new-after-ready", &[103]);
    fixture.add_process(
        103,
        &executable,
        "/agent/new-after-ready",
        "residual",
        &["agent", "residual"],
        &[103],
        1001,
        2001,
        3001,
    );
    let residual =
        validate_against_roots(&manifest, RevalidationPhase::Closure, &fixture.roots).unwrap();
    assert!(!residual.is_stable());
    assert!(residual
        .mismatches
        .iter()
        .any(|mismatch| matches!(mismatch, ValidationMismatch::ProcessSetChanged { added, .. } if added == &vec![103])));
}

#[test]
fn docker_requires_the_full_container_identity_and_inner_pid_one() {
    let fixture = Fixture::new();
    let executable = fixture.executable("container-init");
    let container_id = "a1".repeat(32);
    let cgroup = format!("/system.slice/docker-{container_id}.scope");
    fixture.add_cgroup(&cgroup, &[201, 202]);
    fixture.add_process(
        201,
        &executable,
        &cgroup,
        "init",
        &["init"],
        &[201, 1],
        1101,
        2101,
        3101,
    );
    fixture.add_process(
        202,
        &executable,
        &cgroup,
        "worker",
        &["worker"],
        &[202, 2],
        1101,
        2101,
        3101,
    );
    let manifest = discover_with_roots(
        &DeploymentRequest::Docker(DockerRequest::new(&container_id, Some(201))),
        &fixture.roots,
    )
    .expect("discover Docker fixture");

    assert_eq!(manifest.subject_id, container_id);
    assert_eq!(manifest.processes.len(), 2);
    assert_eq!(
        manifest
            .processes
            .iter()
            .filter(|process| process.role == ProcessRole::DockerInit)
            .count(),
        1
    );
    let wrong = format!("{}{}", &manifest.subject_id[..62], "ff");
    assert!(discover_with_roots(
        &DeploymentRequest::Docker(DockerRequest::new(wrong, Some(201))),
        &fixture.roots,
    )
    .is_err());
}

#[test]
fn kata_observes_shim_and_qemu_in_separate_host_cgroups_without_entering_guest() {
    let fixture = Fixture::new();
    let shim = fixture.executable("containerd-shim-kata-v2");
    let qemu = fixture.executable("qemu-system-x86_64");
    let sandbox_id = "kata-sandbox-01234567";
    fixture.add_cgroup("/kata/shim", &[301]);
    fixture.add_cgroup("/kata/qemu", &[302]);
    fixture.add_process(
        301,
        &shim,
        "/kata/shim",
        "kata-shim",
        &["containerd-shim-kata-v2", "-id", sandbox_id],
        &[301],
        1201,
        2201,
        3201,
    );
    fixture.add_process(
        302,
        &qemu,
        "/kata/qemu",
        "qemu",
        &["qemu-system-x86_64", "-name", sandbox_id],
        &[302],
        1202,
        2202,
        3202,
    );
    fixture.add_observer_netns(3200);
    let mut request = KataHostRequest::new(sandbox_id, 301);
    request.expected_hypervisor_pid = Some(302);
    let manifest = discover_with_roots(&DeploymentRequest::KataHost(request), &fixture.roots)
        .expect("discover Kata host fixture");

    assert_eq!(manifest.registration_root_cgroup_ids().len(), 2);
    assert!(manifest
        .processes
        .iter()
        .any(|process| process.role == ProcessRole::KataHypervisor));
    assert!(!manifest.coverage.kata_guest_entered);
    assert!(
        manifest
            .coverage
            .kata_host_backends_discovered_from_qemu_argv
    );
}

#[test]
fn kata_resolves_qemu_fd_and_fds_only_from_the_owner_fdinfo() {
    let fixture = Fixture::new();
    let shim = fixture.executable("containerd-shim-kata-v2");
    let qemu = fixture.executable("qemu-system-x86_64");
    let sandbox_id = "kata-fd-sandbox-01234567";
    fixture.add_cgroup("/kata-fd", &[401, 402]);
    fixture.add_process(
        401,
        &shim,
        "/kata-fd",
        "kata-shim",
        &["containerd-shim-kata-v2", sandbox_id],
        &[401],
        1401,
        2401,
        3401,
    );
    fixture.add_process(
        402,
        &qemu,
        "/kata-fd",
        "qemu",
        &[
            "qemu-system-x86_64",
            sandbox_id,
            "-netdev",
            "tap,id=n0,fd=9",
            "-netdev",
            "tap,id=n1,fds=10:11",
        ],
        &[402],
        1401,
        2401,
        3401,
    );
    fixture.add_observer_netns(3401);
    fixture.add_tap("tapfd0", 71);
    fixture.add_tap("tapfds0", 72);
    fixture.add_tun_fd(402, 9, "tapfd0");
    fixture.add_tun_fd(402, 10, "tapfds0");
    fixture.add_tun_fd(402, 11, "tapfds0");

    let mut request = KataHostRequest::new(sandbox_id, 401);
    request.expected_hypervisor_pid = Some(402);
    let manifest = discover_with_roots(&DeploymentRequest::KataHost(request), &fixture.roots)
        .expect("resolve QEMU fd/fds TAP fixture");
    assert!(manifest.coverage.kata_tap_fdinfo_evidence_present);
    let taps = manifest
        .kata_host_resources
        .iter()
        .filter(|resource| resource.kind == KataResourceKind::TapInterface)
        .collect::<Vec<_>>();
    assert_eq!(taps.len(), 2);
    assert!(taps.iter().any(|resource| {
        resource.network_binding == Some(KataNetworkBinding::QemuFd)
            && resource.network_file_descriptors == vec![9]
            && resource.interface_name.as_deref() == Some("tapfd0")
    }));
    assert!(taps.iter().any(|resource| {
        resource.network_binding == Some(KataNetworkBinding::QemuFds)
            && resource.network_file_descriptors == vec![10, 11]
            && resource.interface_name.as_deref() == Some("tapfds0")
    }));
    assert!(
        validate_against_roots(&manifest, RevalidationPhase::Ready, &fixture.roots)
            .unwrap()
            .is_stable()
    );

    fs::write(
        fixture.roots.procfs.join("402/fdinfo/11"),
        b"pos:\t0\nflags:\t02\niff:\ttapfd0\n",
    )
    .unwrap();
    let changed =
        validate_against_roots(&manifest, RevalidationPhase::Ready, &fixture.roots).unwrap();
    assert!(changed.mismatches.iter().any(|mismatch| matches!(
        mismatch,
        ValidationMismatch::NetworkBackendDescriptorChanged { descriptor: 11, .. }
    )));
}

#[test]
fn qemu_tap_descriptor_parser_rejects_noncanonical_duplicate_and_out_of_bound_values() {
    use crate::discover::{parse_qemu_descriptor, parse_qemu_descriptor_set};

    assert_eq!(parse_qemu_descriptor(b"9", 32).unwrap(), 9);
    assert!(parse_qemu_descriptor(b"09", 32).is_err());
    assert!(parse_qemu_descriptor(b"-1", 32).is_err());
    assert!(parse_qemu_descriptor(b"32", 32).is_err());
    assert_eq!(parse_qemu_descriptor_set(b"9:10", 32).unwrap(), vec![9, 10]);
    assert!(parse_qemu_descriptor_set(b"9:9", 32).is_err());
    assert!(parse_qemu_descriptor_set(b"9:", 32).is_err());
}
