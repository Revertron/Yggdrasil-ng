# TUN Segmentation Offload (GSO)

`if_gso = true` asks the kernel for `IFF_VNET_HDR` on the TUN interface, so
segmented buffers cross the device in one read or write instead of one syscall
per MTU-sized packet. Off by default. Linux only — the knob is accepted and
ignored everywhere else.

```toml
if_gso = true
```

## When to enable it

**The predicate is many small packets arriving back to back — not a small MTU.**

GSO coalesces packets that are _already queued_ when the I/O loop looks. It
never waits for a partner to show up, so it helps exactly when traffic is dense
and segmented, and does nothing otherwise.

| Traffic shape                    | Effect                      | Why                                                                                                |
| -------------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------- |
| Small segments, back to back     | **Large win**               | 16–20× coalescing; this is the case it exists for                                                  |
| Bulk TCP at `if_mtu = 65535`     | **No-op**                   | TCP derives its MSS from the MTU, so segments already arrive at ~64 KB — there is nothing to merge |
| Sparse small packets (idle gaps) | **No-op, ~6% CPU overhead** | No partner is ever queued; the loop correctly refuses to add latency waiting for one               |

Enable it when:

- **You peer with 1500-byte-MTU meshes.** Any peer behind a 1500-byte path
  negotiates a small MSS _regardless of your local MTU_, so a node at the
  default `if_mtu = 65535` still sees small segments and still benefits. This is
  the common interop case.
- **You forward traffic** — CKR/VPN exit nodes, site-to-site tunnels, routers.
- **CPU is your bottleneck**, not bandwidth. The efficiency gain is larger and
  far more reliable than the throughput gain.

Leave it off when:

- Your workload is bulk transfer between nodes that both run the default MTU.
  There is nothing to coalesce and you pay the machinery for nothing.
- You are latency-sensitive at the millisecond level (see the cost below).

## Measured effect

Two nodes over 1 GbE, one router hop, `if_mtu = 1500`, single TCP stream,
10 repetitions per arm, both hosts idle.

|                          | gso=off            | gso=on         | delta      |
| ------------------------ | ------------------ | -------------- | ---------- |
| throughput               | 590.7 ±48.5 Mbit/s | **698.7 ±8.4** | **+18.3%** |
| CPU-s per Gbit, sender   | 1.335              | **0.909**      | **−32%**   |
| CPU-s per Gbit, receiver | 2.970              | **2.294**      | **−23%**   |
| avg TUN packet           | 1500 B             | 29912 B        | 20×        |
| TUN writes per 30 s      | 1,550,709          | 87,777         | **−94%**   |

Reverse direction: +5.5% throughput, −40% CPU per gigabit on both nodes.

Two things worth noting beyond the averages:

- **Consistency improves sharply.** Run-to-run stdev was 6× tighter with GSO
  (8.4 vs 48.5 Mbit/s), and the only throughput collapse across the whole set
  was in the _baseline_ arm.
- **Throughput gains need headroom to be visible.** At `if_mtu = 65535` on this
  1 GbE link the tunnel already reached 99% of raw line rate with GSO off, so
  no throughput difference was measurable at the default MTU on this hardware.
  The CPU savings are still real there whenever segments are small.

## What it costs

- **Latency.** Loaded RTT went from 1.03 ms to 1.68 ms at a 1500-byte MTU, with
  a worse tail. Expected for batching, and the reason the write loop never waits
  for a batch to fill.
- **Memory.** Roughly 427 KiB for the read batch at `if_mtu = 65535` (less at
  smaller MTUs) plus the write batch, per interface.
- **Sensitivity to host load.** Batch fill depends on packets already being
  queued when the loop polls, so a busy host depresses GSO specifically in a way
  it does not depress the one-syscall-per-packet path. If you benchmark this,
  benchmark on an idle host — measuring under load can invert the result.

## Verifying it is active

The kernel can refuse the offload mask (old kernels, restricted containers).
`yggdrasil` asks for what was actually granted rather than assuming, and logs it
at device creation:

```text
INFO yggdrasil::tun: TUN device 'ygg0' created with address ... and MTU 1500 (GSO enabled)
```

If the request did not take, you get the fallback warning and plain packet mode:

```text
WARN yggdrasil::tun: if_gso is set but the kernel refused TUN offload; continuing without GSO
```

In a container this usually means the runtime restricts `/dev/net/tun` ioctls;
see [CONTAINER.md](CONTAINER.md) for the capabilities the interface needs.

## Behaviour under errors

An offloaded read hands back a whole kernel aggregate, which can be rejected as
a unit — a peer with a below-standard MSS can split one into more segments than
the batch has slots, for instance. Such a read drops that aggregate and the loop
continues; failures are counted and reported at most once every 5 seconds:

```text
WARN yggdrasil::tun: TUN read error, 1 aggregate(s) dropped since last report: too many GSO segments
```

Occasional lines here are graceful degradation, not an outage. A _sustained_
stream of them means something is wrong with the peer or the device and is worth
investigating.
