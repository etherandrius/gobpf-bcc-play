package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct val_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char host[80];
    u64 ts;
} __attribute__((packed));

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char host[80];
} __attribute__((packed));

BPF_HASH(start, u32, struct val_t);
BPF_PERF_OUTPUT(events);
int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read_user(&val.host, sizeof(val.host),
                       (void *)PT_REGS_PARM1(ctx));
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        start.update(&pid, &val);
    }
    return 0;
}

int do_return(struct pt_regs *ctx) {
    struct val_t *valp;
    struct data_t data = {};
    u64 delta;
    u32 pid = bpf_get_current_pid_tgid();
    u64 tsp = bpf_ktime_get_ns();
    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_kernel(&data.host, sizeof(data.host), (void *)valp->host);
    data.pid = valp->pid;
    data.delta = tsp - valp->ts;
    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&pid);
    return 0;
}
`

type dnsEvent struct {
	Pid   uint32
	Delta uint64
	Comm  [16]byte
	Host  [80]byte
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer func() {
		_ = m.Close
	}()

	doEntry, err := m.LoadUprobe("do_entry")
	if err != nil {
		panic(err)
	}

	doReturn, err := m.LoadUprobe("do_return")
	if err != nil {
		panic(err)
	}

	if err := m.AttachUprobe("c", "getaddrinfo", doEntry, -1); err != nil {
		panic(err)
	}
	if err := m.AttachUprobe("c", "gethostbyname", doEntry, -1); err != nil {
		panic(err)
	}
	if err := m.AttachUprobe("c", "gethostbyname2", doEntry, -1); err != nil {
		panic(err)
	}

	if err := m.AttachUretprobe("c", "getaddrinfo", doReturn, -1); err != nil {
		panic(err)
	}
	if err := m.AttachUretprobe("c", "gethostbyname", doReturn, -1); err != nil {
		panic(err)
	}
	if err := m.AttachUretprobe("c", "gethostbyname2", doReturn, -1); err != nil {
		panic(err)
	}

	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		panic(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		var event dnsEvent
		for {
			data := <-channel
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
				fmt.Println(err)
				continue
			}

			host := string(event.Host[:bytes.IndexByte(event.Host[:], 0)])
			comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])
			fmt.Printf("pid:%v, command:%s, LATms:%10.2f, Host:%s\n", event.Pid, comm, (float64(event.Delta) / 1000000), host)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
