"""Exercise native owned-hook parsers/ABI checks with synthetic files only.

The tiny harness includes the exact collector implementation. It never loads
BPF, creates real tracefs events, changes preemption, or inspects Host cgroups.
Fake kprobe_events is an ordinary temporary file: an accepted remove command
is not represented as proof that a real kernel event was removed.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
ARCHIVE = Path(os.environ.get("LIBBPF_ARCHIVE", str(PROJECT /
    ".output/cargo-target/release/build/libbpf-sys-6600eb2a870d407c/out/libbpf.a")))


HARNESS = r'''
#include <errno.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>
static int fixture_reject_large_reads;
static size_t fixture_largest_read;
static ssize_t fixture_read(int fd,void *buffer,size_t size)
{
    if(size>fixture_largest_read)fixture_largest_read=size;
    if(fixture_reject_large_reads&&size>4096){errno=ENOMEM;return -1;}
    return syscall(SYS_read,fd,buffer,size);
}
#define read fixture_read
#define main timeline_collector_main
#include SOURCE_FILE
#undef main
#undef read

static struct btf *fixture_btf(const char *defect)
{
    struct btf *b=btf__new_empty();if(libbpf_get_error(b))return NULL;
    int u64=btf__add_int(b,"unsigned long",8,0),s64=btf__add_int(b,"long",8,BTF_INT_SIGNED);
    int s32=btf__add_int(b,"int",4,BTF_INT_SIGNED),ch=btf__add_int(b,"char",1,BTF_INT_SIGNED);
    int file=btf__add_struct(b,!strcmp(defect,"file")?"not_file":"file",8);
    int iovec=btf__add_struct(b,"iovec",16);
    int fp=btf__add_ptr(b,file),cp=btf__add_ptr(b,ch),vp=btf__add_ptr(b,iovec);
    int pos=btf__add_ptr(b,!strcmp(defect,"offset")?u64:s64);
    btf__add_struct(b,"pt_regs",48);
    const char *regs[]={"di","si","dx","cx","ax","orig_ax"};
    for(int i=0;i<6;i++)btf__add_field(b,((!strcmp(defect,"register-name")&&i==4)||(!strcmp(defect,"orig-name")&&i==5))?"other":regs[i],
        ((!strcmp(defect,"register-width")&&i==4)||(!strcmp(defect,"orig-width")&&i==5))?s32:u64,i*64,0);
    for(int i=0;i<2;i++){
        int proto=btf__add_func_proto(b,!strcmp(defect,"return")?u64:s64);
        btf__add_func_param(b,"file",fp);btf__add_func_param(b,"buffer",i?vp:cp);
        btf__add_func_param(b,"count",!strcmp(defect,"count")?s64:u64);
        if(strcmp(defect,"arity"))btf__add_func_param(b,"pos",pos);
        if(i)btf__add_func_param(b,"flags",!strcmp(defect,"flags")?u64:s32);
        btf__add_func(b,i?"vfs_readv":"vfs_read",BTF_FUNC_GLOBAL,proto);
    }
    int boolean=btf__add_int(b,"_Bool",1,BTF_INT_BOOL);
    if(strcmp(defect,"seccomp-missing")){
        int proto=btf__add_func_proto(b,!strcmp(defect,"seccomp-return")?s32:boolean);
        btf__add_func_param(b,"this_syscall",!strcmp(defect,"seccomp-number")?u64:s32);
        if(strcmp(defect,"seccomp-arity"))btf__add_func_param(b,"recheck_after_trace",!strcmp(defect,"seccomp-bool")?s32:boolean);
        btf__add_func(b,"__seccomp_filter",BTF_FUNC_STATIC,proto);
    }
    return b;
}
int main(int argc,char **argv)
{
    if(argc==3&&!strcmp(argv[1],"bounded-read")){
        fixture_reject_large_reads=1;fixture_largest_read=0;char *text=NULL;
        int valid=!trace_text(argv[2],&text);
        printf("{\"valid\":%s,\"largest_read\":%zu,\"bytes\":%zu,\"synthetic_only\":true}\n",
            valid?"true":"false",fixture_largest_read,text?strlen(text):0);free(text);return 0;
    }
    if(argc==3&&!strcmp(argv[1],"btf")){
        struct btf *b=fixture_btf(argv[2]);struct owned_traces traces={};
        int valid=b&&!validate_btf_types(b,&traces);if(b)btf__free(b);
        printf("{\"valid\":%s,\"synthetic_only\":true}\n",valid?"true":"false");return 0;
    }
    if(argc==4&&!strcmp(argv[1],"profile")){
        char *text=NULL;uint64_t hits=0,misses=0;
        int valid=!trace_text(argv[2],&text)&&!profile_text(text,argv[3],&hits,&misses);
        free(text);printf("{\"valid\":%s,\"hits\":%llu,\"misses\":%llu}\n",valid?"true":"false",(unsigned long long)hits,(unsigned long long)misses);return 0;
    }
    if(argc==6&&!strcmp(argv[1],"receipt")){
        struct owned_traces traces={};strcpy(traces.root,argv[2]);lstat(traces.root,&traces.root_identity);
        traces.count=1;struct owned_hook *h=&traces.hooks[0];
        strcpy(h->name,"owned_test");strcpy(h->program,"et_read_end");strcpy(h->anchor,"vfs_read");h->is_return=1;h->created=1;
        struct stat st;
        if(hook_identity(&traces,h,&st,&h->event_id,h->definition))return 2;
        h->device=st.st_dev;h->inode=st.st_ino;h->anchored=1;h->initial_valid=1;
        h->initial_hits=strtoull(argv[4],NULL,10);h->initial_misses=strtoull(argv[5],NULL,10);
        if(!strcmp(argv[3],"event-id"))h->event_id++;
        if(!strcmp(argv[3],"inode"))h->inode++;
        if(!strcmp(argv[3],"definition"))strcat(h->definition," ");
        char output[PATH_MAX];path_join(output,sizeof(output),traces.root,"result");mkdir(output,0700);
        finish_traces(&traces,output);
        printf("{\"errors\":%llu,\"misses\":%llu,\"cleanup_errors\":%llu,\"removed_command_accepted\":%s,\"synthetic_only\":true}\n",
            (unsigned long long)traces.errors,(unsigned long long)traces.misses,(unsigned long long)traces.cleanup_errors,h->removed?"true":"false");return 0;
    }
    return 2;
}
'''


class NativeKprobeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE.is_file() or not shutil.which(os.environ.get("CC", "cc")):
            raise unittest.SkipTest("native contract harness requires existing libbpf archive and C compiler")
        cls.temp = tempfile.TemporaryDirectory(prefix="timeline-kprobe-contract-")
        root = Path(cls.temp.name)
        source, cls.harness = root / "test.c", root / "test"
        source.write_text(HARNESS.replace("SOURCE_FILE", json.dumps(str(HERE / "collect.c"))))
        cmd = [os.environ.get("CC", "cc"), "-O1", "-g", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
               "-I" + str(ARCHIVE.parent / "include"), "-I" + str(PROJECT.parents[2] / "tools/include/uapi"),
               "-I" + str(PROJECT / "bpf"), str(source), str(ARCHIVE), "-lelf", "-lz", "-o", str(cls.harness)]
        process = subprocess.run(cmd, capture_output=True, text=True)
        if process.returncode:
            cls.temp.cleanup()
            raise AssertionError("native contract harness did not compile: " + process.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, *args):
        process = subprocess.run([str(self.harness), *map(str, args)], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_btf_exact_native_vfs_and_register_abi(self):
        self.assertTrue(self.invoke("btf", "valid")["valid"])
        for defect in ("file", "return", "count", "offset", "flags", "arity", "register-name", "register-width", "orig-name", "orig-width",
                       "seccomp-missing", "seccomp-return", "seccomp-number", "seccomp-bool", "seccomp-arity"):
            with self.subTest(defect=defect):
                self.assertFalse(self.invoke("btf", defect)["valid"])

    def test_text_total_limit_does_not_become_a_huge_sysctl_read(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "sysctl-fixture"
            path.write_bytes(b"a" * 17001)
            result = self.invoke("bounded-read", path)
            self.assertTrue(result["valid"])
            self.assertEqual(result["bytes"], 17001)
            self.assertLessEqual(result["largest_read"], 4096)

    def test_profile_requires_one_exact_bounded_unsigned_record(self):
        for text, valid in (("other 8 7\nowned 12 0\n", True), ("owned 12 1\n", True),
                            ("owned 12 0\nowned 12 0\n", False), ("other 12 0\n", False),
                            ("owned -1 0\n", False), ("owned 1 -1\n", False),
                            ("owned 1 0 extra\n", False), ("owned 18446744073709551616 0\n", False),
                            ("owned 1\n", False), ("owned 1 0\0hidden", False)):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "profile"
                path.write_bytes(text.encode())
                self.assertEqual(self.invoke("profile", path, "owned")["valid"], valid)

    def fixture(self, root, profile="owned_test 20 0\n", definition=None):
        root = Path(root)
        event = root / "events/allox_execution_timeline/owned_test"
        event.mkdir(parents=True)
        (event / "id").write_text("123\n")
        command = definition or "r4096:allox_execution_timeline/owned_test vfs_read\n"
        (root / "kprobe_events").write_text(command)
        (root / "kprobe_profile").write_text(profile)
        return root

    def test_global_missed_probe_is_never_exempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(tmp, "owned_test 20 3\n")
            result = self.invoke("receipt", root, "valid", 1, 0)
            self.assertEqual(result["errors"], 0)
            self.assertEqual(result["misses"], 3)
            receipt = json.loads((root / "result/kprobe-hooks.json").read_text())
            self.assertEqual(receipt["misses_delta"], 3)
            self.assertTrue(receipt["hooks"][0]["final_valid"])
            self.assertLessEqual(receipt["hooks"][0]["final_begin_ns"], receipt["hooks"][0]["final_end_ns"])

    def test_profile_rollback_missing_or_parse_failure_cannot_pass(self):
        for profile, initial in (("owned_test 9 0\n", (10, 0)), ("owned_test 20 0\n", (1, 1)),
                                 ("another 20 0\n", (1, 0)), ("owned_test 20 bad\n", (1, 0))):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp, profile)
                result = self.invoke("receipt", root, "valid", *initial)
                self.assertGreater(result["errors"], 0)
                receipt = json.loads((root / "result/kprobe-hooks.json").read_text())
                self.assertFalse(receipt["hooks"][0]["final_valid"])

    def test_changed_event_identity_or_definition_refuses_removal(self):
        for defect in ("event-id", "inode", "definition"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as tmp:
                root = self.fixture(tmp)
                original = (root / "kprobe_events").read_bytes()
                result = self.invoke("receipt", root, defect, 1, 0)
                self.assertGreater(result["errors"], 0)
                self.assertEqual(result["cleanup_errors"], 1)
                self.assertFalse(result["removed_command_accepted"])
                self.assertEqual((root / "kprobe_events").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
