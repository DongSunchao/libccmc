# libccmc

Migrate an ESTABLISHED TCP socket to another host.

Uses `TCP_REPAIR` to dump socket state (seq numbers, timestamp offset, MSS, window scale — about 80 bytes) on the source, ships it to the target, and re-opens the socket there in ESTABLISHED state. The client sees a brief stall, not a reset.

![Demo](video/zeno_migration_demo.gif)

[Write-up with more context on Dev.to](https://dev.to/sunchao_dong/i-froze-a-tcp-connection-for-10-minutes-and-migrated-it-to-another-server-31i8)

```
Source host                         Target host
────────────────                    ────────────────
ccmc_tiocoutq_poll(fd)
ccmc_freeze_and_extract(fd, &st) -->  (send st over any channel)
close(fd)                               new_fd = ccmc_socket_restore(&st)
                                        // new_fd is a live ESTABLISHED socket
```

Why not CRIU: CRIU checkpoints the whole process. I only want the socket — the process on the target is a different binary.

## Limitations

- Requires `CAP_NET_ADMIN` on both ends
- No TLS session migration — that's an application-layer problem
- VIP / IP drift is your responsibility; see `examples/gateway.c` for one approach
- Tested on 5.15 and 6.1; not tested with MPTCP
- SACK scoreboard is not preserved on restore — minor retransmit possible after migration
- In-flight send queue: `TIOCOUTQ` tells you how many bytes are unacked, but if you freeze before it drains you may lose them. `ccmc_tiocoutq_poll()` spins until the queue is empty, but the timeout is your call.

## Known edge cases

- **Timestamp offset**: not a simple copy. `ccmc_socket_restore` computes `tsoffset = tsval_at_freeze - tcp_time_stamp_raw(target)` so PAWS doesn't reject the first post-migration segment. This works, but assumes both machines have monotonic `tcp_time_stamp` (true on every kernel I've tested).
- **Window scale / SACK permitted**: these are negotiated during SYN and can only be set via `TCP_REPAIR_OPTIONS`, not through `TCP_INFO`. The library captures them from `getsockopt(TCP_REPAIR_WINDOW)`.
- **rcv_nxt vs copied_seq**: if the application has read data that the kernel hasn't ACKed yet, restoring with the wrong `rcv_nxt` can make the peer see a seq regression. In practice `ccmc_freeze_and_extract` grabs `rcv_nxt` from repair mode which reflects the kernel's view, not the app's — so this is safe as long as you don't have unread data sitting in the receive buffer at freeze time.

## Build

```bash
make                # shared + static library
make examples       # sse_server, gateway
make ebpf           # optional: XDP + TC programs (requires clang + libbpf)

sudo bash tests/test_tcp_repair.sh   # core validation
sudo bash tests/test_sse.sh          # E2E SSE migration across 2 hops
```

## Usage

```c
#include <ccmc.h>

// source side
struct ccmc_state st;
ccmc_tiocoutq_poll(fd, 2000);          // wait for send queue to drain
ccmc_freeze_and_extract(fd, &st, sizeof(st));
close(fd);                             // kernel discards silently, no RST

// ... send &st to target however you want (80 bytes) ...

// target side
int new_fd = ccmc_socket_restore(&st, sizeof(st));
// new_fd is ESTABLISHED and writable
```

```bash
gcc -O2 -I./include myapp.c -L./build -lccmc -o myapp
```

Python bindings are in `python/` — they work but are experimental, not battle-tested.

The eBPF programs in `ebpf/` implement a zero-window hold that keeps the client in persist-timer mode during migration. They do the job, but this is my first real XDP/TC project — feedback and PRs from experienced eBPF developers are welcome.

## License

`src/` `include/` `examples/` `tests/` `python/` — Apache-2.0
`ebpf/` — GPL-2.0-only

See [LICENSE](LICENSE) and [LICENSE-APACHE](LICENSE-APACHE).

## Author

Sunchao Dong — 2026
