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

struct readline_event_t {
		u32 pid;
		u64 cgid;
        char str[80];
} __attribute__((packed));

BPF_PERF_OUTPUT(readline_events);

int get_return_value(struct pt_regs *ctx) {
	struct readline_event_t event = {};
    u32 pid;
    u64 cgid;

    if (!PT_REGS_RC(ctx))
        return 0;

    pid = bpf_get_current_pid_tgid();
	event.pid = pid;

	cgid = bpf_get_current_cgroup_id();
	event.cgid = cgid;

    bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
    readline_events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
`

type readlineEvent struct {
	Pid  uint32
	CgID uint64
	Str  [80]byte
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer func() {
		_ = m.Close
	}()

	readlineUretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		panic(err)
	}

	if err := m.AttachUretprobe("/bin/bash", "readline", readlineUretprobe, -1); err != nil {
		panic(err)
	}

	table := bpf.NewTable(m.TableId("readline_events"), m)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		panic(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		var event readlineEvent
		for {
			data := <-channel
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
				fmt.Println(err)
				continue
			}
			comm := string(event.Str[:bytes.IndexByte(event.Str[:], 0)])
			fmt.Printf("pid:%v, cgid:%v, command:%s\n", event.Pid, event.CgID, string(comm))
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
