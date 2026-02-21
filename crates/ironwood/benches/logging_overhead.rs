use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

// Simulate hot-path operations with different logging levels
fn simulate_packet_routing_with_logging(iterations: u32) {
    for i in 0..iterations {
        let packet_id = i;
        let dest = [0u8; 8];

        // This simulates the logging in router.rs handle_traffic
        tracing::debug!("Route traffic {:?}, for: {}", i, hex::encode(&dest[..8]));

        // Simulate actual work
        black_box(packet_id.wrapping_add(1));
    }
}

fn simulate_packet_routing_no_logging(iterations: u32) {
    for i in 0..iterations {
        let packet_id = i;
        // Simulate actual work
        black_box(packet_id.wrapping_add(1));
    }
}

fn benchmark_logging_overhead(c: &mut Criterion) {
    // Initialize tracing with INFO level (debug messages disabled)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_writer(|| std::io::sink()) // Discard all output
        .try_init();

    let mut group = c.benchmark_group("packet_routing");

    for count in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("with_debug_logging", count),
            count,
            |b, &count| b.iter(|| simulate_packet_routing_with_logging(count))
        );

        group.bench_with_input(
            BenchmarkId::new("no_logging", count),
            count,
            |b, &count| b.iter(|| simulate_packet_routing_no_logging(count))
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_logging_overhead);
criterion_main!(benches);
