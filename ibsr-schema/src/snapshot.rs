//! Snapshot and BucketEntry types for IBSR.

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;

/// Current schema version.
/// Version 1: Added multi-port support (dst_port -> dst_ports)
/// Version 2: Added handshake_ack field for accurate SYN-flood detection
/// Version 3: Added per-port granularity (dst_port field in BucketEntry)
/// Version 4: Added aggregation field, changed key_value to src_ip string format
/// Version 5: Added interval_sec, run_id, counter_mode, base_ts_unix_sec for offline reporting
/// Version 6: Added optional resp_aggregates field for ShadowPayload mode (per-window
///            response-amplification aggregates: req_bytes_max, resp_bytes_max,
///            amp_ratio_{mean,median,max}). Field semantics match
///            nr-substrate's nr_training/features/responses.py exactly.
/// Version 7: Extended ResponseAggregates with response timing
///            (duration_ns_{mean,max}), HTTP status fractions
///            (status_{2xx,4xx,5xx}_frac), JSON-RPC error metadata
///            (rpc_error_distinct_codes, rpc_error_frac), and derived
///            byte means (req_bytes_mean, resp_bytes_mean). Adds an
///            optional HostTelemetry block (`host`) sourced from
///            `/proc/<pid>` for collectors configured with a target PID.
///            All new fields are Option-typed with skip_serializing_if so
///            v7 readers parse v6 snapshots cleanly and v6 readers ignore
///            the new keys.
pub const SCHEMA_VERSION: u32 = 7;

/// Schema versions this reader understands. v5 lacks resp_aggregates (StrictCounter
/// mode); v6 may carry resp_aggregates (ShadowPayload mode); v7 adds optional
/// timing/status/error/mean fields on resp_aggregates.
pub const SUPPORTED_VERSIONS: &[u32] = &[5, 6, 7];

/// Per-window response-amplification aggregates. Only emitted by ShadowPayload-mode
/// collectors (`ibsr collect-payload`); absent on StrictCounter (`ibsr collect`)
/// snapshots.
///
/// Semantics match `nr_training/features/responses.py` exactly so the Phase 1
/// close-gate criterion (numerical identity, per-feature `PHASE_1_TOLERANCE`) is
/// achievable when this collector is fed the same traffic the offline extractor
/// reads from `responses.parquet`. The extractor on the offline side computes
/// from per-RPC `request_size_bytes` / `response_size_bytes` columns; here we
/// compute from per-RPC pairs reassembled by the userspace TC handler.
///
/// Aggregates are over the snapshot window — same window length as the
/// surrounding snapshot's `interval_sec`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseAggregates {
    /// Number of complete request:response pairs observed in this window.
    pub count: u64,

    /// Sum of all response bytes across all pairs in window.
    pub resp_bytes_total: u64,

    /// Maximum request size in bytes (None if count == 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_bytes_max: Option<u64>,

    /// Maximum response size in bytes (None if count == 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp_bytes_max: Option<u64>,

    /// Mean amplification ratio (response/request). Per offline semantics:
    /// only pairs with request_bytes > 0 are included in the ratio set.
    /// None if no eligible pair existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amp_ratio_mean: Option<f64>,

    /// Median amplification ratio.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amp_ratio_median: Option<f64>,

    /// Maximum amplification ratio.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amp_ratio_max: Option<f64>,

    /// Distinct dst_port cardinality observed across all packets in
    /// the window, capped at 5 to match offline `summarise_pcap`'s
    /// `top_n=5` semantic. Tracked by the userspace handler from
    /// every TC payload event's flow tuple. Omitted on pre-v0.2
    /// snapshots that did not yet emit this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_dst_ports: Option<u32>,

    /// Distinct src_port cardinality observed across all packets in
    /// the window, capped at 5 to match offline semantics. Same
    /// userspace-handler tracking path as `unique_dst_ports`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_src_ports: Option<u32>,

    /// Mean response duration (ns), computed per-pair as
    /// `resp_completed_ns - req_started_ns` and averaged over pairs with
    /// a non-zero duration. None if no eligible pair existed. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ns_mean: Option<u64>,

    /// Maximum response duration (ns) observed in window. None if count == 0
    /// or no pair carried timing metadata. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ns_max: Option<u64>,

    /// Fraction of responses with HTTP status 2xx, in [0, 1]. Denominator
    /// is the count of responses with a parseable HTTP status line; non-HTTP
    /// responses are excluded. None if no response carried a parseable
    /// status. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_2xx_frac: Option<f64>,

    /// Fraction of responses with HTTP status 4xx, in [0, 1]. Same
    /// denominator semantics as `status_2xx_frac`. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_4xx_frac: Option<f64>,

    /// Fraction of responses with HTTP status 5xx, in [0, 1]. Same
    /// denominator semantics as `status_2xx_frac`. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_5xx_frac: Option<f64>,

    /// Cardinality of distinct JSON-RPC `error.code` values observed in the
    /// window, capped at 5 to match offline `summarise_responses` semantics.
    /// None if no JSON-RPC error envelope was parsed. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_error_distinct_codes: Option<u32>,

    /// Fraction of responses with a non-null JSON-RPC `error` field, in
    /// [0, 1]. Denominator is `count` (all pairs in window). None if no
    /// response was parseable as JSON-RPC. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_error_frac: Option<f64>,

    /// Mean request size in bytes, derived as `sum(req_bytes) / count`.
    /// None if count == 0. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_bytes_mean: Option<f64>,

    /// Mean response size in bytes, derived as `sum(resp_bytes) / count`.
    /// None if count == 0. v7+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp_bytes_mean: Option<f64>,
}

/// HTTP status-code counters for a window. Inputs to
/// `ResponseAggregates::from_triples_and_metadata`.
///
/// `n_with_parsed_status` is the denominator used for `status_*_frac`: it is
/// the count of responses where a `HTTP/x.y CCC ...` status line was parsed.
/// Non-HTTP responses (raw JSON, non-conformant, mid-stream truncation) do
/// not contribute to either numerator or denominator. When
/// `n_with_parsed_status == 0`, all three status fractions emit as `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatusCounts {
    pub n_2xx: u64,
    pub n_4xx: u64,
    pub n_5xx: u64,
    pub n_with_parsed_status: u64,
}

/// JSON-RPC error metadata for a window. Inputs to
/// `ResponseAggregates::from_triples_and_metadata`.
///
/// `error_codes` is the full sequence of `error.code` values observed across
/// responses (duplicates allowed; the constructor computes distinct cardinality
/// and caps at 5 to match offline `summarise_responses` semantics).
/// `error_count` is the count of responses with a non-null `error` field.
/// `n_with_parsed_envelope` is the count of responses where JSON-RPC envelope
/// parsing succeeded (whether or not `error` was present); when 0, both
/// `rpc_error_distinct_codes` and `rpc_error_frac` emit as `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RpcMetadata {
    pub error_codes: Vec<i32>,
    pub error_count: u64,
    pub n_with_parsed_envelope: u64,
}

impl ResponseAggregates {
    /// Compute per-window aggregates from a slice of (request_bytes, response_bytes)
    /// pairs. Mirrors the aggregation logic in
    /// `nr_training/features/responses.py` exactly:
    ///
    /// - `req_bytes_max` / `resp_bytes_max`: max over all pairs.
    /// - `amp_ratio_*`: ratios are computed per-pair, but only over pairs where
    ///   request > 0; if no pair qualifies, all amp_ratio_* are None.
    /// - `resp_bytes_total`: sum of all response_bytes.
    ///
    /// Thin wrapper over `from_triples_and_metadata` with no timing or
    /// status/error metadata. Preserved as the offline-extractor parity
    /// constructor (matches `responses.py` byte-aggregate contract); new
    /// call-sites should prefer `from_triples_and_metadata` so the v7
    /// timing / status / RPC-error fields flow through.
    #[deprecated(
        since = "0.2.0",
        note = "Use `from_triples_and_metadata` for v7 timing/status/error fields. \
                `from_pairs` is preserved for the offline-extractor parity contract only."
    )]
    pub fn from_pairs(pairs: &[(u64, u64)]) -> Self {
        let triples: Vec<(u64, u64, Option<u64>)> =
            pairs.iter().map(|(q, r)| (*q, *r, None)).collect();
        Self::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        )
    }

    /// Compute per-window aggregates from per-pair (request_bytes, response_bytes,
    /// duration_ns) triples plus optional HTTP status / JSON-RPC error metadata.
    ///
    /// Field semantics (v7+):
    /// - `count`, `resp_bytes_total`, `req_bytes_max`, `resp_bytes_max`,
    ///   `amp_ratio_*`: identical to `from_pairs` semantics, derived from the
    ///   first two elements of each triple.
    /// - `req_bytes_mean` / `resp_bytes_mean`: arithmetic mean over all triples;
    ///   `None` only if the triples slice is empty.
    /// - `duration_ns_mean`: arithmetic mean over triples whose `Some(d)` carry
    ///   `d > 0`; `None` if no such triple exists. 0-duration triples are
    ///   excluded from the mean to keep the metric meaningful for sub-µs RPCs.
    /// - `duration_ns_max`: max over triples carrying `Some(d)` (any value);
    ///   `None` if no triple carried timing.
    /// - `status_*_frac`: numerator from `status_counts.n_*xx`; denominator is
    ///   `status_counts.n_with_parsed_status`. All three emit `None` when the
    ///   denominator is 0 (non-HTTP windows or no status parsed).
    /// - `rpc_error_distinct_codes`: cardinality of distinct values in
    ///   `rpc_metadata.error_codes`, capped at 5 to match offline
    ///   `summarise_responses`. `None` when `n_with_parsed_envelope == 0`.
    /// - `rpc_error_frac`: `error_count / count`. `None` when
    ///   `n_with_parsed_envelope == 0`.
    pub fn from_triples_and_metadata(
        triples: &[(u64, u64, Option<u64>)],
        status_counts: StatusCounts,
        rpc_metadata: RpcMetadata,
    ) -> Self {
        if triples.is_empty() {
            return Self {
                count: 0,
                resp_bytes_total: 0,
                req_bytes_max: None,
                resp_bytes_max: None,
                amp_ratio_mean: None,
                amp_ratio_median: None,
                amp_ratio_max: None,
                unique_dst_ports: None,
                unique_src_ports: None,
                duration_ns_mean: None,
                duration_ns_max: None,
                status_2xx_frac: None,
                status_4xx_frac: None,
                status_5xx_frac: None,
                rpc_error_distinct_codes: None,
                rpc_error_frac: None,
                req_bytes_mean: None,
                resp_bytes_mean: None,
            };
        }

        let count = triples.len() as u64;
        let count_f = count as f64;

        let resp_bytes_total: u64 = triples.iter().map(|(_, r, _)| *r).sum();
        let req_bytes_total: u64 = triples.iter().map(|(q, _, _)| *q).sum();
        let req_bytes_max = triples.iter().map(|(q, _, _)| *q).max();
        let resp_bytes_max = triples.iter().map(|(_, r, _)| *r).max();

        let req_bytes_mean = Some(req_bytes_total as f64 / count_f);
        let resp_bytes_mean = Some(resp_bytes_total as f64 / count_f);

        let mut ratios: Vec<f64> = triples
            .iter()
            .filter(|(q, _, _)| *q > 0)
            .map(|(q, r, _)| (*r as f64) / (*q as f64))
            .collect();

        let (amp_mean, amp_median, amp_max) = if ratios.is_empty() {
            (None, None, None)
        } else {
            let mean = ratios.iter().sum::<f64>() / (ratios.len() as f64);
            ratios.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let median = if ratios.len() % 2 == 1 {
                ratios[ratios.len() / 2]
            } else {
                let lo = ratios[ratios.len() / 2 - 1];
                let hi = ratios[ratios.len() / 2];
                (lo + hi) / 2.0
            };
            let max = ratios.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            (Some(mean), Some(median), Some(max))
        };

        let durations_with_timing: Vec<u64> =
            triples.iter().filter_map(|(_, _, d)| *d).collect();
        let duration_ns_max = durations_with_timing.iter().copied().max();
        let nonzero_durations: Vec<u64> = durations_with_timing
            .iter()
            .copied()
            .filter(|d| *d > 0)
            .collect();
        let duration_ns_mean = if nonzero_durations.is_empty() {
            None
        } else {
            let sum: u64 = nonzero_durations.iter().sum();
            Some(sum / nonzero_durations.len() as u64)
        };

        let (status_2xx_frac, status_4xx_frac, status_5xx_frac) =
            if status_counts.n_with_parsed_status == 0 {
                (None, None, None)
            } else {
                let denom = status_counts.n_with_parsed_status as f64;
                (
                    Some(status_counts.n_2xx as f64 / denom),
                    Some(status_counts.n_4xx as f64 / denom),
                    Some(status_counts.n_5xx as f64 / denom),
                )
            };

        let (rpc_error_distinct_codes, rpc_error_frac) =
            if rpc_metadata.n_with_parsed_envelope == 0 {
                (None, None)
            } else {
                let distinct: HashSet<i32> =
                    rpc_metadata.error_codes.iter().copied().collect();
                let capped = distinct.len().min(5) as u32;
                (
                    Some(capped),
                    Some(rpc_metadata.error_count as f64 / count_f),
                )
            };

        Self {
            count,
            resp_bytes_total,
            req_bytes_max,
            resp_bytes_max,
            amp_ratio_mean: amp_mean,
            amp_ratio_median: amp_median,
            amp_ratio_max: amp_max,
            unique_dst_ports: None,
            unique_src_ports: None,
            duration_ns_mean,
            duration_ns_max,
            status_2xx_frac,
            status_4xx_frac,
            status_5xx_frac,
            rpc_error_distinct_codes,
            rpc_error_frac,
            req_bytes_mean,
            resp_bytes_mean,
        }
    }

    /// Builder: attach distinct dst_port + src_port cardinalities
    /// observed in the same window. Caps each at 5 to match offline
    /// `summarise_pcap`'s `top_n=5` semantic. Pass the full set of
    /// distinct ports observed; this method takes care of the cap.
    pub fn with_port_cardinalities(mut self, dst_ports: usize, src_ports: usize) -> Self {
        self.unique_dst_ports = Some(dst_ports.min(5) as u32);
        self.unique_src_ports = Some(src_ports.min(5) as u32);
        self
    }
}

/// Per-window host-process telemetry block. Optional addition to v7+
/// snapshots. Source: `/proc/<pid>/{stat,status,io,fd,net/tcp}` sampled
/// at the snapshot-emit thread's window-boundary cadence (window-start
/// baseline + window-close end-snapshot, deltas computed in userspace).
///
/// All fields are individually `Option`-typed: a collector that lacks
/// `/proc/<pid>/io` permission can still emit `cpu_*` and `rss_*`
/// without forcing the whole block to `None`. Operators with no
/// `--target-pid` configured emit `Snapshot.host: None` entirely (the
/// block doesn't appear in JSON at all).
///
/// Window-boundary semantics: `cpu_max` and `rss_max` collapse to the
/// end-of-window value in v7 (single-thread sampling). A future v8
/// could add a 1Hz mid-window sampler for true intra-window max.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostTelemetry {
    /// Mean process CPU% over window, as a fraction-of-one-core
    /// percentage (0.0 = idle, 100.0 = one full core). v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_mean: Option<f64>,

    /// Maximum process CPU% observed in window. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_max: Option<f64>,

    /// RSS memory delta over window in bytes (signed; positive = grew).
    /// Computed as `rss_at_window_close - rss_at_window_start`. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_delta: Option<i64>,

    /// RSS memory at window end, in bytes. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_max: Option<u64>,

    /// RSS slope in bytes-per-second (rss_delta / window_duration_secs).
    /// Captures slow-leak signatures that flip-flopping deltas can mask. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_slope_bps: Option<f64>,

    /// File-descriptor count delta over window (signed). v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_fds_delta: Option<i64>,

    /// Open TCP-connection count delta over window (signed). Sourced
    /// from `/proc/<pid>/net/tcp` ESTABLISHED-state lines. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_connections_delta: Option<i64>,

    /// Maximum open TCP-connection count observed during window. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_connections_max: Option<u32>,

    /// Disk-write byte delta over window. Sourced from
    /// `/proc/<pid>/io::write_bytes`. v7+.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_write_delta: Option<i64>,
}

/// Key type for bucket entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    SrcIp,
    SrcCidr24,
}

/// A single bucket entry representing counters for one source.
///
/// Note: Custom Serialize/Deserialize implementations emit `src_ip` as a
/// dotted-decimal string instead of `key_value` as u32, for human readability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketEntry {
    pub key_type: KeyType,
    /// The IP address as u32 (for internal use and sorting).
    /// Serialized as `src_ip` in dotted-decimal format.
    pub key_value: u32,
    /// Destination port this bucket tracks (for per-port granularity).
    pub dst_port: Option<u16>,
    pub syn: u32,
    pub ack: u32,
    /// ACKs that are part of handshake completion (ACK=1, SYN=0, RST=0, no payload).
    /// This is used for accurate SYN-flood detection, as established connection ACKs
    /// (with payload) should not count toward handshake success ratio.
    pub handshake_ack: u32,
    pub rst: u32,
    pub packets: u32,
    pub bytes: u64,
}

impl Serialize for BucketEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Count fields: key_type, src_ip, syn, ack, handshake_ack, rst, packets, bytes
        // + optionally dst_port
        let field_count = if self.dst_port.is_some() { 9 } else { 8 };
        let mut state = serializer.serialize_struct("BucketEntry", field_count)?;

        state.serialize_field("key_type", &self.key_type)?;
        state.serialize_field("src_ip", &ip_u32_to_string(self.key_value))?;

        if let Some(port) = self.dst_port {
            state.serialize_field("dst_port", &port)?;
        }

        state.serialize_field("syn", &self.syn)?;
        state.serialize_field("ack", &self.ack)?;
        state.serialize_field("handshake_ack", &self.handshake_ack)?;
        state.serialize_field("rst", &self.rst)?;
        state.serialize_field("packets", &self.packets)?;
        state.serialize_field("bytes", &self.bytes)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for BucketEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            KeyType,
            SrcIp,
            DstPort,
            Syn,
            Ack,
            HandshakeAck,
            Rst,
            Packets,
            Bytes,
        }

        struct BucketEntryVisitor;

        impl<'de> Visitor<'de> for BucketEntryVisitor {
            type Value = BucketEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct BucketEntry")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BucketEntry, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_type = None;
                let mut src_ip: Option<String> = None;
                let mut dst_port = None;
                let mut syn = None;
                let mut ack = None;
                let mut handshake_ack = None;
                let mut rst = None;
                let mut packets = None;
                let mut bytes = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::KeyType => {
                            if key_type.is_some() {
                                return Err(de::Error::duplicate_field("key_type"));
                            }
                            key_type = Some(map.next_value()?);
                        }
                        Field::SrcIp => {
                            if src_ip.is_some() {
                                return Err(de::Error::duplicate_field("src_ip"));
                            }
                            src_ip = Some(map.next_value()?);
                        }
                        Field::DstPort => {
                            if dst_port.is_some() {
                                return Err(de::Error::duplicate_field("dst_port"));
                            }
                            dst_port = Some(map.next_value()?);
                        }
                        Field::Syn => {
                            if syn.is_some() {
                                return Err(de::Error::duplicate_field("syn"));
                            }
                            syn = Some(map.next_value()?);
                        }
                        Field::Ack => {
                            if ack.is_some() {
                                return Err(de::Error::duplicate_field("ack"));
                            }
                            ack = Some(map.next_value()?);
                        }
                        Field::HandshakeAck => {
                            if handshake_ack.is_some() {
                                return Err(de::Error::duplicate_field("handshake_ack"));
                            }
                            handshake_ack = Some(map.next_value()?);
                        }
                        Field::Rst => {
                            if rst.is_some() {
                                return Err(de::Error::duplicate_field("rst"));
                            }
                            rst = Some(map.next_value()?);
                        }
                        Field::Packets => {
                            if packets.is_some() {
                                return Err(de::Error::duplicate_field("packets"));
                            }
                            packets = Some(map.next_value()?);
                        }
                        Field::Bytes => {
                            if bytes.is_some() {
                                return Err(de::Error::duplicate_field("bytes"));
                            }
                            bytes = Some(map.next_value()?);
                        }
                    }
                }

                let key_type = key_type.ok_or_else(|| de::Error::missing_field("key_type"))?;
                let src_ip_str = src_ip.ok_or_else(|| de::Error::missing_field("src_ip"))?;
                // Parse IP - u32::from(Ipv4Addr) uses MSB=first-octet representation
                let key_value = u32::from(
                    src_ip_str
                        .parse::<Ipv4Addr>()
                        .map_err(|_| de::Error::custom(format!("invalid IP address: {}", src_ip_str)))?,
                );
                let syn = syn.ok_or_else(|| de::Error::missing_field("syn"))?;
                let ack = ack.ok_or_else(|| de::Error::missing_field("ack"))?;
                let handshake_ack =
                    handshake_ack.ok_or_else(|| de::Error::missing_field("handshake_ack"))?;
                let rst = rst.ok_or_else(|| de::Error::missing_field("rst"))?;
                let packets = packets.ok_or_else(|| de::Error::missing_field("packets"))?;
                let bytes = bytes.ok_or_else(|| de::Error::missing_field("bytes"))?;

                Ok(BucketEntry {
                    key_type,
                    key_value,
                    dst_port,
                    syn,
                    ack,
                    handshake_ack,
                    rst,
                    packets,
                    bytes,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "key_type",
            "src_ip",
            "dst_port",
            "syn",
            "ack",
            "handshake_ack",
            "rst",
            "packets",
            "bytes",
        ];
        deserializer.deserialize_struct("BucketEntry", FIELDS, BucketEntryVisitor)
    }
}

/// A snapshot of counters at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    /// Describes how metrics are aggregated: "src_ip_dst_port" means per source IP per destination port.
    pub aggregation: String,
    pub ts_unix_sec: u64,
    /// Snapshot emission interval in seconds (e.g., 60 for one snapshot per minute).
    pub interval_sec: u32,
    /// Stable run identifier: Unix timestamp when the run started.
    /// Constant across all snapshots in a run.
    pub run_id: u64,
    /// Counter semantics: always "cumulative" (counters accumulate from run start).
    pub counter_mode: String,
    /// First snapshot timestamp of the run. Used with interval_sec for delta computation.
    pub base_ts_unix_sec: u64,
    /// Destination ports being monitored (sorted for deterministic output).
    pub dst_ports: Vec<u16>,
    pub buckets: Vec<BucketEntry>,
    /// Per-window response-amplification aggregates. Only present on v6
    /// snapshots emitted by ShadowPayload-mode collectors. Absent on v5
    /// (StrictCounter-mode) snapshots and on v6 ShadowPayload windows
    /// where no complete request:response pair was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_aggregates: Option<ResponseAggregates>,

    /// Per-window host-process telemetry. Optional v7+ addition. Present
    /// only when the collector has been configured with a target PID
    /// (e.g. `ibsr collect-payload --target-pid 1234`). Absent for
    /// untargeted runs and on snapshots from collectors without
    /// `/proc` access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostTelemetry>,
}

impl Snapshot {
    /// Create a new snapshot with the current schema version.
    ///
    /// # Arguments
    /// * `ts_unix_sec` - Unix timestamp of this snapshot
    /// * `dst_ports` - Destination ports being monitored
    /// * `buckets` - Bucket entries (will be sorted for determinism)
    /// * `interval_sec` - Snapshot emission interval in seconds
    /// * `run_id` - Stable run identifier (Unix timestamp when run started)
    /// * `base_ts_unix_sec` - First snapshot timestamp of the run
    pub fn new(
        ts_unix_sec: u64,
        dst_ports: &[u16],
        mut buckets: Vec<BucketEntry>,
        interval_sec: u32,
        run_id: u64,
        base_ts_unix_sec: u64,
    ) -> Self {
        // Sort buckets for deterministic ordering: by key_type, then key_value, then dst_port
        buckets.sort_by(|a, b| {
            a.key_type
                .cmp(&b.key_type)
                .then_with(|| a.key_value.cmp(&b.key_value))
                .then_with(|| a.dst_port.cmp(&b.dst_port))
        });

        // Sort ports for deterministic output
        let mut sorted_ports = dst_ports.to_vec();
        sorted_ports.sort_unstable();

        Self {
            version: SCHEMA_VERSION,
            aggregation: "src_ip_dst_port".to_string(),
            ts_unix_sec,
            interval_sec,
            run_id,
            counter_mode: "cumulative".to_string(),
            base_ts_unix_sec,
            dst_ports: sorted_ports,
            buckets,
            resp_aggregates: None,
            host: None,
        }
    }

    /// Builder: attach response-amplification aggregates (ShadowPayload mode).
    /// The snapshot remains v6; this is the form ShadowPayload-mode collectors
    /// emit when a window contains complete request:response pairs.
    pub fn with_resp_aggregates(mut self, agg: ResponseAggregates) -> Self {
        self.resp_aggregates = Some(agg);
        self
    }

    /// Builder: attach per-window host-process telemetry. v7+ addition;
    /// emitted by collectors configured with a target PID.
    pub fn with_host(mut self, host: HostTelemetry) -> Self {
        self.host = Some(host);
        self
    }

    /// Serialize snapshot to JSON string (single line for JSONL format).
    /// This cannot fail for our struct types.
    pub fn to_json(&self) -> String {
        // SAFETY: Our struct types are always serializable to JSON.
        // Snapshot contains only primitive types and Vec<BucketEntry>.
        serde_json::to_string(self).expect("Snapshot serialization cannot fail")
    }

    /// Deserialize snapshot from JSON string. Accepts any version listed in
    /// `SUPPORTED_VERSIONS` (currently v5 and v6). v5 lacks `resp_aggregates`
    /// (StrictCounter mode); v6 may carry `resp_aggregates` (ShadowPayload
    /// mode).
    pub fn from_json(json: &str) -> Result<Self, SnapshotError> {
        let snapshot: Snapshot = serde_json::from_str(json)?;
        if !SUPPORTED_VERSIONS.contains(&snapshot.version) {
            return Err(SnapshotError::VersionMismatch {
                expected: SCHEMA_VERSION,
                found: snapshot.version,
            });
        }
        Ok(snapshot)
    }
}

/// Errors that can occur when working with snapshots.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("schema version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },

    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),
}

/// Convert a u32 IP address to dotted-decimal string.
/// Uses MSB=first-octet representation (same as Ipv4Addr).
pub fn ip_u32_to_string(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

/// Parse a dotted-decimal IP string to u32.
/// Uses MSB=first-octet representation (same as Ipv4Addr).
pub fn string_to_ip_u32(s: &str) -> Result<u32, SnapshotError> {
    s.parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| SnapshotError::InvalidIpAddress(s.to_string()))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    // ===========================================
    // Test Category A — Schema / Encoding
    // ===========================================

    #[test]
    fn test_roundtrip_empty_snapshot() {
        let snapshot = Snapshot::new(1234567890, &[8899], vec![], 60, 1234567890, 1234567890);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_roundtrip_single_bucket() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001, // 10.0.0.1
            dst_port: Some(8899),
            syn: 100,
            ack: 200,
            handshake_ack: 95,
            rst: 5,
            packets: 305,
            bytes: 45000,
        };
        let snapshot = Snapshot::new(1234567890, &[8899], vec![bucket], 60, 1234567890, 1234567890);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_roundtrip_multiple_buckets() {
        let buckets = vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8000),
                syn: 10,
                ack: 20,
                handshake_ack: 10,
                rst: 1,
                packets: 31,
                bytes: 4500,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000002,
                dst_port: Some(8000),
                syn: 50,
                ack: 100,
                handshake_ack: 50,
                rst: 0,
                packets: 150,
                bytes: 22000,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000,
                dst_port: None,
                syn: 60,
                ack: 120,
                handshake_ack: 60,
                rst: 1,
                packets: 181,
                bytes: 26500,
            },
        ];
        let snapshot = Snapshot::new(1234567890, &[8000], buckets, 60, 1234567890, 1234567890);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_deterministic_bucket_ordering() {
        // Create buckets in random order
        let buckets_unordered = vec![
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000,
                dst_port: None,
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0B000001,
                dst_port: Some(8899),
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8899),
                syn: 3,
                ack: 3,
                handshake_ack: 3,
                rst: 0,
                packets: 6,
                bytes: 300,
            },
        ];

        let snapshot = Snapshot::new(1234567890, &[8899], buckets_unordered, 60, 1234567890, 1234567890);

        // Should be sorted: SrcIp entries first (by key_value), then SrcCidr24
        assert_eq!(snapshot.buckets.len(), 3);
        assert_eq!(snapshot.buckets[0].key_type, KeyType::SrcIp);
        assert_eq!(snapshot.buckets[0].key_value, 0x0A000001);
        assert_eq!(snapshot.buckets[1].key_type, KeyType::SrcIp);
        assert_eq!(snapshot.buckets[1].key_value, 0x0B000001);
        assert_eq!(snapshot.buckets[2].key_type, KeyType::SrcCidr24);
        assert_eq!(snapshot.buckets[2].key_value, 0x0A000000);
    }

    #[test]
    fn test_deterministic_ordering_produces_same_json() {
        let buckets1 = vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0B000001,
                dst_port: Some(8899),
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8899),
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
        ];

        let buckets2 = vec![
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0A000001,
                dst_port: Some(8899),
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
            BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: 0x0B000001,
                dst_port: Some(8899),
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
        ];

        let snapshot1 = Snapshot::new(1234567890, &[8899], buckets1, 60, 1234567890, 1234567890);
        let snapshot2 = Snapshot::new(1234567890, &[8899], buckets2, 60, 1234567890, 1234567890);

        let json1 = snapshot1.to_json();
        let json2 = snapshot2.to_json();

        assert_eq!(json1, json2);
    }

    #[test]
    fn test_sorting_within_same_key_type() {
        // Test that buckets with the same key_type are sorted by key_value
        // This exercises the then_with clause in the sort comparator
        let buckets = vec![
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0C000000, // 12.0.0.0/24
                dst_port: None,
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0A000000, // 10.0.0.0/24
                dst_port: None,
                syn: 2,
                ack: 2,
                handshake_ack: 2,
                rst: 0,
                packets: 4,
                bytes: 200,
            },
            BucketEntry {
                key_type: KeyType::SrcCidr24,
                key_value: 0x0B000000, // 11.0.0.0/24
                dst_port: None,
                syn: 3,
                ack: 3,
                handshake_ack: 3,
                rst: 0,
                packets: 6,
                bytes: 300,
            },
        ];

        let snapshot = Snapshot::new(1234567890, &[8899], buckets, 60, 1234567890, 1234567890);

        // Should be sorted by key_value within SrcCidr24
        assert_eq!(snapshot.buckets.len(), 3);
        assert_eq!(snapshot.buckets[0].key_value, 0x0A000000);
        assert_eq!(snapshot.buckets[1].key_value, 0x0B000000);
        assert_eq!(snapshot.buckets[2].key_value, 0x0C000000);
    }

    #[test]
    fn test_empty_snapshot_handling() {
        let snapshot = Snapshot::new(0, &[], vec![], 60, 0, 0);

        assert_eq!(snapshot.version, SCHEMA_VERSION);
        assert_eq!(snapshot.ts_unix_sec, 0);
        assert!(snapshot.dst_ports.is_empty());
        assert!(snapshot.buckets.is_empty());

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");
        assert_eq!(snapshot, restored);
    }

    #[test]
    fn test_large_values_u32_max() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: u32::MAX,
            dst_port: Some(u16::MAX),
            syn: u32::MAX,
            ack: u32::MAX,
            handshake_ack: u32::MAX,
            rst: u32::MAX,
            packets: u32::MAX,
            bytes: u64::MAX,
        };
        let snapshot = Snapshot::new(u64::MAX, &[u16::MAX], vec![bucket], u32::MAX, u64::MAX, u64::MAX);

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize");

        assert_eq!(snapshot, restored);
        assert_eq!(restored.buckets[0].syn, u32::MAX);
        assert_eq!(restored.buckets[0].bytes, u64::MAX);
        assert_eq!(restored.buckets[0].dst_port, Some(u16::MAX));
        assert_eq!(restored.ts_unix_sec, u64::MAX);
        assert_eq!(restored.dst_ports, vec![u16::MAX]);
        assert_eq!(restored.interval_sec, u32::MAX);
        assert_eq!(restored.run_id, u64::MAX);
        assert_eq!(restored.base_ts_unix_sec, u64::MAX);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        // Manually craft JSON with wrong version (not in SUPPORTED_VERSIONS)
        let bad_json = r#"{"version":999,"aggregation":"src_ip_dst_port","ts_unix_sec":1234567890,"interval_sec":60,"run_id":1234567890,"counter_mode":"cumulative","base_ts_unix_sec":1234567890,"dst_ports":[8899],"buckets":[]}"#;

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::VersionMismatch {
                expected: SCHEMA_VERSION,
                found: 999
            }
        ));
    }

    #[test]
    fn test_invalid_json_rejected() {
        let bad_json = "not valid json";

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SnapshotError::Json(_)));
    }

    #[test]
    fn test_missing_field_rejected() {
        // JSON missing required field
        let bad_json = r#"{"version":1,"ts_unix_sec":1234567890,"buckets":[]}"#;

        let result = Snapshot::from_json(bad_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_json_is_single_line() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(8899),
            syn: 100,
            ack: 200,
            handshake_ack: 95,
            rst: 5,
            packets: 305,
            bytes: 45000,
        };
        let snapshot = Snapshot::new(1234567890, &[8899], vec![bucket], 60, 1234567890, 1234567890);

        let json = snapshot.to_json();

        // JSONL format: no newlines in output
        assert!(!json.contains('\n'));
    }

    #[test]
    fn test_key_type_serialization() {
        let bucket_ip = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(80),
            syn: 1,
            ack: 1,
            handshake_ack: 1,
            rst: 0,
            packets: 2,
            bytes: 100,
        };
        let bucket_cidr = BucketEntry {
            key_type: KeyType::SrcCidr24,
            key_value: 0x0A000000,
            dst_port: None,
            syn: 1,
            ack: 1,
            handshake_ack: 1,
            rst: 0,
            packets: 2,
            bytes: 100,
        };

        let json_ip = serde_json::to_string(&bucket_ip).expect("serialize");
        let json_cidr = serde_json::to_string(&bucket_cidr).expect("serialize");

        assert!(json_ip.contains("\"src_ip\""));
        assert!(json_ip.contains("\"dst_port\":80"));
        assert!(json_cidr.contains("\"src_cidr24\""));
        // dst_port should be skipped when None
        assert!(!json_cidr.contains("dst_port"));
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, 7);
    }

    #[test]
    fn test_supported_versions_constant() {
        assert_eq!(SUPPORTED_VERSIONS, &[5, 6, 7]);
    }

    #[test]
    fn test_snapshot_new_sets_version() {
        let snapshot = Snapshot::new(1234567890, &[8899], vec![], 60, 1234567890, 1234567890);
        assert_eq!(snapshot.version, SCHEMA_VERSION);
    }

    // ===========================================
    // Test Category B — IP Conversion Utilities
    // ===========================================

    #[test]
    fn test_ip_u32_to_dotted_decimal() {
        // u32 values use MSB=first-octet representation (0x0A000001 = 10.0.0.1)
        assert_eq!(ip_u32_to_string(0x52_01_FE_7D), "82.1.254.125");
        assert_eq!(ip_u32_to_string(0x0A_00_00_01), "10.0.0.1");
        assert_eq!(ip_u32_to_string(0x0A_00_00_02), "10.0.0.2");
        assert_eq!(ip_u32_to_string(0xC0_A8_01_01), "192.168.1.1");

        // Edge cases
        assert_eq!(ip_u32_to_string(0), "0.0.0.0");
        assert_eq!(ip_u32_to_string(u32::MAX), "255.255.255.255");
    }

    #[test]
    fn test_dotted_decimal_to_ip_u32() {
        // string_to_ip_u32 returns MSB=first-octet representation
        assert_eq!(string_to_ip_u32("82.1.254.125").unwrap(), 0x52_01_FE_7D);
        assert_eq!(string_to_ip_u32("10.0.0.1").unwrap(), 0x0A_00_00_01);
        assert_eq!(string_to_ip_u32("192.168.1.1").unwrap(), 0xC0_A8_01_01);
        assert_eq!(string_to_ip_u32("0.0.0.0").unwrap(), 0);
        assert_eq!(string_to_ip_u32("255.255.255.255").unwrap(), u32::MAX);
    }

    #[test]
    fn test_ip_roundtrip_conversion() {
        // Roundtrip: string -> u32 (host order) -> string
        let test_ips = ["0.0.0.0", "10.0.0.1", "82.1.254.125", "192.168.1.1", "255.255.255.255"];
        for &ip_str in &test_ips {
            let host_order = string_to_ip_u32(ip_str).expect("parse");
            let back = ip_u32_to_string(host_order);
            assert_eq!(back, ip_str, "roundtrip failed for {}", ip_str);
        }
    }

    #[test]
    fn test_string_to_ip_invalid() {
        assert!(string_to_ip_u32("not an ip").is_err());
        assert!(string_to_ip_u32("256.0.0.1").is_err());
        assert!(string_to_ip_u32("").is_err());
        assert!(string_to_ip_u32("10.0.0").is_err());
    }

    // ===========================================
    // Test Category C — BucketEntry src_ip Serialization
    // ===========================================

    #[test]
    fn test_bucket_emits_src_ip_string_correctly() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001, // 10.0.0.1
            dst_port: Some(8080),
            syn: 100,
            ack: 90,
            handshake_ack: 90,
            rst: 5,
            packets: 200,
            bytes: 20000,
        };

        let json = serde_json::to_string(&bucket).expect("serialize");

        // JSON should contain "src_ip":"10.0.0.1" NOT "key_value":167772161
        assert!(json.contains(r#""src_ip":"10.0.0.1""#), "JSON should contain src_ip string: {}", json);
        assert!(!json.contains(r#""key_value""#), "JSON should NOT contain key_value: {}", json);
    }

    #[test]
    fn test_bucket_roundtrip_with_src_ip() {
        let original = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x5201FE7D, // 82.1.254.125
            dst_port: Some(22),
            syn: 50,
            ack: 45,
            handshake_ack: 40,
            rst: 2,
            packets: 100,
            bytes: 10000,
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let restored: BucketEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(original.key_value, restored.key_value);
        assert_eq!(original.key_type, restored.key_type);
        assert_eq!(original.dst_port, restored.dst_port);
        assert_eq!(original.syn, restored.syn);
        assert_eq!(original.ack, restored.ack);
        assert_eq!(original.handshake_ack, restored.handshake_ack);
        assert_eq!(original.rst, restored.rst);
        assert_eq!(original.packets, restored.packets);
        assert_eq!(original.bytes, restored.bytes);
    }

    #[test]
    fn test_bucket_roundtrip_edge_cases() {
        // Test with various IP addresses
        let ips = [0u32, 167772161, 1375862397, 3232235777, u32::MAX];

        for ip in ips {
            let original = BucketEntry {
                key_type: KeyType::SrcIp,
                key_value: ip,
                dst_port: Some(80),
                syn: 1,
                ack: 1,
                handshake_ack: 1,
                rst: 0,
                packets: 2,
                bytes: 100,
            };

            let json = serde_json::to_string(&original).expect("serialize");
            let restored: BucketEntry = serde_json::from_str(&json).expect("deserialize");

            assert_eq!(original.key_value, restored.key_value,
                "roundtrip failed for IP {}: {}", ip, json);
        }
    }

    // ===========================================
    // Test Category D — Aggregation Field
    // ===========================================

    #[test]
    fn test_snapshot_includes_aggregation_header() {
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000);
        let json = snapshot.to_json();

        // Verify aggregation field is present and has correct value
        assert!(json.contains(r#""aggregation":"src_ip_dst_port""#),
            "JSON should contain aggregation field: {}", json);

        // Verify roundtrip preserves aggregation
        let restored = Snapshot::from_json(&json).expect("deserialize");
        assert_eq!(restored.aggregation, "src_ip_dst_port");
    }

    #[test]
    fn test_snapshot_aggregation_in_output() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000002, // 10.0.0.2
            dst_port: Some(8080),
            syn: 100,
            ack: 90,
            handshake_ack: 90,
            rst: 5,
            packets: 200,
            bytes: 20000,
        };
        let snapshot = Snapshot::new(1000, &[8080], vec![bucket], 60, 1000, 1000);
        let json = snapshot.to_json();

        // Check the expected output format
        assert!(json.contains(r#""aggregation":"src_ip_dst_port""#));
        assert!(json.contains(r#""src_ip":"10.0.0.2""#));
    }

    // ===========================================
    // Test Category E — Byte-Order Verification Tests
    // These tests verify our MSB-first convention is correctly maintained.
    // If bytes were accidentally swapped, these tests would fail.
    // ===========================================

    #[test]
    fn test_ip_byte_representation_is_msb_first() {
        // Verify our convention: 0x0A000001 means 10.0.0.1
        // MSB-first means first octet (10) is in the most significant byte
        let ip: u32 = 0x0A000001;

        // Byte representation should be [10, 0, 0, 1] in big-endian
        assert_eq!(
            ip.to_be_bytes(),
            [10, 0, 0, 1],
            "IP 0x0A000001 should have bytes [10, 0, 0, 1] in big-endian"
        );

        // Ipv4Addr::from() should interpret as 10.0.0.1
        assert_eq!(
            Ipv4Addr::from(ip).to_string(),
            "10.0.0.1",
            "Ipv4Addr::from(0x0A000001) must produce 10.0.0.1"
        );
    }

    #[test]
    fn test_ip_from_string_produces_correct_u32() {
        // Parsing "10.0.0.1" must produce 0x0A000001
        let addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let ip_u32 = u32::from(addr);

        assert_eq!(
            ip_u32, 0x0A000001,
            "Parsing '10.0.0.1' must produce 0x0A000001, got {:#X}",
            ip_u32
        );
        assert_eq!(ip_u32.to_be_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn test_swapped_ip_produces_wrong_string() {
        // If someone accidentally byte-swaps, they get wrong output
        // This test documents what WRONG looks like
        let swapped: u32 = 0x0100000A; // Wrong: bytes reversed

        // This would produce "1.0.0.10" - WRONG!
        assert_eq!(
            Ipv4Addr::from(swapped).to_string(),
            "1.0.0.10",
            "Swapped IP should produce wrong string (this test documents the bug)"
        );

        // Verify it's NOT the correct IP
        assert_ne!(Ipv4Addr::from(swapped).to_string(), "10.0.0.1");
    }

    #[test]
    fn test_bucket_key_value_to_display_roundtrip() {
        // Test the FULL pipeline: key_value → JSON → parse → display
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001, // Must display as "10.0.0.1"
            dst_port: Some(8080),
            syn: 100,
            ack: 90,
            handshake_ack: 90,
            rst: 5,
            packets: 200,
            bytes: 20000,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&bucket).unwrap();

        // JSON must contain "10.0.0.1", NOT "1.0.0.10"
        assert!(
            json.contains(r#""src_ip":"10.0.0.1""#),
            "JSON must contain '10.0.0.1', got: {}",
            json
        );
        assert!(
            !json.contains("1.0.0.10"),
            "JSON must NOT contain swapped IP '1.0.0.10'"
        );

        // Parse back and verify key_value
        let parsed: BucketEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.key_value, 0x0A000001,
            "Parsed key_value must be 0x0A000001"
        );
    }

    // ===========================================
    // Test Category F — Schema v5 Fields
    // These tests verify the new v5 schema fields:
    // - interval_sec: snapshot emission interval
    // - run_id: stable run identifier (start timestamp)
    // - counter_mode: always "cumulative"
    // - base_ts_unix_sec: first snapshot timestamp of run
    // ===========================================

    #[test]
    fn test_v5_compat_still_supported() {
        // v5 snapshots from existing StrictCounter-mode collectors must still
        // round-trip through the reader after the v6 bump.
        assert!(SUPPORTED_VERSIONS.contains(&5));
        assert!(SUPPORTED_VERSIONS.contains(&6));
    }

    #[test]
    fn test_v5_new_fields_present() {
        let snapshot = Snapshot::new(
            1704067200,      // ts_unix_sec
            &[8080],         // dst_ports
            vec![],          // buckets
            60,              // interval_sec
            1704067200,      // run_id
            1704067200,      // base_ts_unix_sec
        );

        assert_eq!(snapshot.interval_sec, 60);
        assert_eq!(snapshot.run_id, 1704067200);
        assert_eq!(snapshot.counter_mode, "cumulative");
        assert_eq!(snapshot.base_ts_unix_sec, 1704067200);
    }

    #[test]
    fn test_v5_serialization_includes_new_fields() {
        let snapshot = Snapshot::new(1704067200, &[8080], vec![], 60, 1704067200, 1704067200);
        let json = snapshot.to_json();

        assert!(json.contains(r#""interval_sec":60"#), "JSON missing interval_sec: {}", json);
        assert!(json.contains(r#""run_id":1704067200"#), "JSON missing run_id: {}", json);
        assert!(json.contains(r#""counter_mode":"cumulative""#), "JSON missing counter_mode: {}", json);
        assert!(json.contains(r#""base_ts_unix_sec":1704067200"#), "JSON missing base_ts_unix_sec: {}", json);
    }

    #[test]
    fn test_v5_roundtrip() {
        let bucket = BucketEntry {
            key_type: KeyType::SrcIp,
            key_value: 0x0A000001,
            dst_port: Some(8080),
            syn: 100,
            ack: 90,
            handshake_ack: 85,
            rst: 5,
            packets: 200,
            bytes: 20000,
        };
        let snapshot = Snapshot::new(
            1704067260,      // ts_unix_sec (60s after base)
            &[8080],
            vec![bucket],
            60,              // interval_sec
            1704067200,      // run_id
            1704067200,      // base_ts_unix_sec
        );

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("deserialize current snapshot");

        // After v6 bump, Snapshot::new emits version=SCHEMA_VERSION (6). v5
        // back-compat is exercised in test_v5_snapshot_round_trips_through_v6_reader.
        assert_eq!(restored.version, SCHEMA_VERSION);
        assert_eq!(restored.interval_sec, 60);
        assert_eq!(restored.run_id, 1704067200);
        assert_eq!(restored.counter_mode, "cumulative");
        assert_eq!(restored.base_ts_unix_sec, 1704067200);
        assert_eq!(restored.ts_unix_sec, 1704067260);
        assert_eq!(restored.buckets.len(), 1);
    }

    #[test]
    fn test_v5_run_id_constant_across_snapshots() {
        // Multiple snapshots in same run should have same run_id
        let run_id = 1704067200u64;
        let base_ts = 1704067200u64;

        let snap1 = Snapshot::new(1704067200, &[8080], vec![], 60, run_id, base_ts);
        let snap2 = Snapshot::new(1704067260, &[8080], vec![], 60, run_id, base_ts);
        let snap3 = Snapshot::new(1704067320, &[8080], vec![], 60, run_id, base_ts);

        assert_eq!(snap1.run_id, run_id);
        assert_eq!(snap2.run_id, run_id);
        assert_eq!(snap3.run_id, run_id);
        assert_eq!(snap1.base_ts_unix_sec, base_ts);
        assert_eq!(snap2.base_ts_unix_sec, base_ts);
        assert_eq!(snap3.base_ts_unix_sec, base_ts);
    }

    #[test]
    fn test_v4_json_rejected() {
        // v4 is below SUPPORTED_VERSIONS — must still be rejected.
        // (We include v5 fields so serde can parse the body; version check then fails.)
        let v4_json = r#"{"version":4,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let result = Snapshot::from_json(v4_json);

        assert!(result.is_err(), "v4 JSON should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, SnapshotError::VersionMismatch { expected: SCHEMA_VERSION, found: 4 }),
            "Expected version mismatch error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_v5_missing_new_fields_rejected() {
        // v5 without v5 required fields should fail to parse (serde missing-field).
        // This documents that v5 is not just "any schema with version=5" but the
        // canonical v5 shape with interval_sec/run_id/counter_mode/base_ts_unix_sec.
        let incomplete_v5 = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let result = Snapshot::from_json(incomplete_v5);

        assert!(result.is_err(), "v5 JSON missing required fields should be rejected");
    }

    // ===========================================
    // Test Category G — Schema v6 Fields (resp_aggregates, ShadowPayload mode)
    // ===========================================

    #[test]
    fn test_v5_snapshot_round_trips_through_v6_reader() {
        // A v5 snapshot (no resp_aggregates field) should still parse cleanly
        // through the v6-aware reader. ShadowPayload mode is opt-in; existing
        // StrictCounter-mode collectors continue to emit v5 (or v6 with no
        // aggregates) and must remain readable.
        let v5_json = r#"{"version":5,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let restored = Snapshot::from_json(v5_json).expect("v5 should round-trip");
        assert_eq!(restored.version, 5);
        assert!(restored.resp_aggregates.is_none());
    }

    #[test]
    fn test_v6_snapshot_round_trips_through_v7_reader() {
        // After the v6→v7 bump, a v6 snapshot (no v7-only fields) must still
        // parse cleanly through the v7-aware reader. Forward-compat invariant:
        // existing ShadowPayload-mode collectors emitting v6 must remain
        // readable. Regression-pin against accidentally dropping v6 from
        // SUPPORTED_VERSIONS during the bump.
        let v6_json = r#"{"version":6,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;

        let restored = Snapshot::from_json(v6_json).expect("v6 should round-trip under v7 reader");
        assert_eq!(restored.version, 6);
        assert!(restored.resp_aggregates.is_none());
    }

    #[test]
    fn test_v7_snapshot_with_aggregates_round_trips() {
        // Inputs picked to produce exact-decimal means so the JSON round-trip
        // is bit-stable (f64 → JSON → f64 drifts the last bit on repeating
        // decimals). Sum(req)=300, sum(resp)=600, count=2 → means 150.0/300.0.
        let agg = ResponseAggregates::from_pairs(&[(100, 200), (200, 400)]);
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000)
            .with_resp_aggregates(agg.clone());

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("v7 should round-trip");

        assert_eq!(restored.version, 7);
        assert_eq!(restored.resp_aggregates, Some(agg));
    }

    #[test]
    fn test_v7_snapshot_without_aggregates_omits_field() {
        // v7 with no aggregates: JSON should not contain a `resp_aggregates`
        // key at all (skip_serializing_if=Option::is_none). Stays compact for
        // StrictCounter-mode-equivalent windows.
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000);
        let json = snapshot.to_json();
        assert!(!json.contains("resp_aggregates"), "JSON should omit resp_aggregates: {}", json);
    }

    #[test]
    fn test_v7_resp_aggregates_omits_metadata_dependent_fields_when_none() {
        // The v7-only fields that depend on extra metadata (timing, HTTP
        // status, JSON-RPC error parsing) must not appear in the JSON when
        // their inputs were absent. Pre-v7 readers see a v7 snapshot with
        // no v7-only keys and parse it as v6-shaped.
        //
        // Note: req_bytes_mean / resp_bytes_mean are derivable from byte
        // pairs alone and ARE populated when count > 0, so they are not
        // listed here.
        let agg = ResponseAggregates::from_pairs(&[(100, 200)]);
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000)
            .with_resp_aggregates(agg);
        let json = snapshot.to_json();

        for absent_key in [
            "duration_ns_mean",
            "duration_ns_max",
            "status_2xx_frac",
            "status_4xx_frac",
            "status_5xx_frac",
            "rpc_error_distinct_codes",
            "rpc_error_frac",
        ] {
            assert!(
                !json.contains(absent_key),
                "v7 JSON should omit metadata-dependent field {} when no metadata supplied: {}",
                absent_key,
                json,
            );
        }
    }

    #[test]
    fn test_v7_resp_aggregates_includes_byte_means_when_count_positive() {
        // *_bytes_mean derive from byte pairs alone (no extra metadata) and
        // must be present in JSON when count > 0.
        let agg = ResponseAggregates::from_pairs(&[(100, 200)]);
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000)
            .with_resp_aggregates(agg);
        let json = snapshot.to_json();
        assert!(json.contains("req_bytes_mean"), "missing req_bytes_mean in: {}", json);
        assert!(json.contains("resp_bytes_mean"), "missing resp_bytes_mean in: {}", json);
    }

    #[test]
    fn test_resp_aggregates_empty_pairs_yields_zero_count() {
        let agg = ResponseAggregates::from_pairs(&[]);
        assert_eq!(agg.count, 0);
        assert_eq!(agg.resp_bytes_total, 0);
        assert_eq!(agg.req_bytes_max, None);
        assert_eq!(agg.resp_bytes_max, None);
        assert_eq!(agg.amp_ratio_mean, None);
        assert_eq!(agg.amp_ratio_median, None);
        assert_eq!(agg.amp_ratio_max, None);
    }

    #[test]
    fn test_resp_aggregates_basic_pair() {
        // Single pair (req=100, resp=300) → ratio = 3.0; max-byte = 100/300.
        let agg = ResponseAggregates::from_pairs(&[(100, 300)]);
        assert_eq!(agg.count, 1);
        assert_eq!(agg.resp_bytes_total, 300);
        assert_eq!(agg.req_bytes_max, Some(100));
        assert_eq!(agg.resp_bytes_max, Some(300));
        assert_eq!(agg.amp_ratio_mean, Some(3.0));
        assert_eq!(agg.amp_ratio_median, Some(3.0));
        assert_eq!(agg.amp_ratio_max, Some(3.0));
    }

    #[test]
    fn test_resp_aggregates_zero_request_excluded_from_ratios() {
        // req=0 pairs are excluded from ratio set per offline semantics
        // (responses.py:48 — `if r is None or q is None or q <= 0: continue`).
        // But max-byte / count / total still see them.
        let agg = ResponseAggregates::from_pairs(&[
            (0, 500),
            (100, 200),
            (200, 600),
        ]);
        assert_eq!(agg.count, 3);
        assert_eq!(agg.resp_bytes_total, 1300);
        assert_eq!(agg.req_bytes_max, Some(200));
        assert_eq!(agg.resp_bytes_max, Some(600));
        // ratios from the 2 non-zero-request pairs: 200/100 = 2.0, 600/200 = 3.0
        assert_eq!(agg.amp_ratio_mean, Some(2.5));
        assert_eq!(agg.amp_ratio_median, Some(2.5));
        assert_eq!(agg.amp_ratio_max, Some(3.0));
    }

    #[test]
    fn test_resp_aggregates_all_zero_requests_yields_no_ratios() {
        let agg = ResponseAggregates::from_pairs(&[(0, 100), (0, 200)]);
        assert_eq!(agg.count, 2);
        assert_eq!(agg.resp_bytes_total, 300);
        assert_eq!(agg.req_bytes_max, Some(0));
        assert_eq!(agg.resp_bytes_max, Some(200));
        assert_eq!(agg.amp_ratio_mean, None);
        assert_eq!(agg.amp_ratio_median, None);
        assert_eq!(agg.amp_ratio_max, None);
    }

    #[test]
    fn test_resp_aggregates_median_even_count() {
        // Even count → median is mean of two middle values after sorting.
        // ratios = [1.0, 2.0, 3.0, 4.0] → median = (2.0 + 3.0) / 2 = 2.5
        let agg = ResponseAggregates::from_pairs(&[
            (100, 100),
            (100, 200),
            (100, 300),
            (100, 400),
        ]);
        assert_eq!(agg.amp_ratio_median, Some(2.5));
    }

    #[test]
    fn test_resp_aggregates_median_odd_count() {
        // Odd count → median is exact middle after sorting.
        // ratios = [1.0, 2.0, 3.0] → median = 2.0
        let agg = ResponseAggregates::from_pairs(&[
            (100, 100),
            (100, 200),
            (100, 300),
        ]);
        assert_eq!(agg.amp_ratio_median, Some(2.0));
    }

    #[test]
    fn test_resp_aggregates_matches_offline_semantics_documentation() {
        // This test pins the contract with the offline extractor at
        // training/src/nr_training/features/responses.py:
        //
        // - req_bytes_max = max(non-null request_size_bytes)
        // - resp_bytes_max = max(non-null response_size_bytes)
        // - resp_bytes_total = sum(non-null response_size_bytes)
        // - amp_ratio_* = aggregates over per-pair ratios where request > 0
        //
        // If the offline semantics ever change, this test will catch the drift
        // at IBSR-side, before Phase 1 cross-validation surfaces it as a
        // numerical-identity failure.
        let agg = ResponseAggregates::from_pairs(&[
            (100, 200),  // ratio = 2.0
            (50, 250),   // ratio = 5.0
            (200, 200),  // ratio = 1.0
        ]);
        assert_eq!(agg.req_bytes_max, Some(200));
        assert_eq!(agg.resp_bytes_max, Some(250));
        assert_eq!(agg.resp_bytes_total, 650);
        assert_eq!(agg.amp_ratio_max, Some(5.0));
        // mean of [2.0, 5.0, 1.0] = 8/3
        assert!(
            (agg.amp_ratio_mean.unwrap() - (8.0 / 3.0)).abs() < 1e-9,
            "amp_ratio_mean should be 8/3, got {:?}", agg.amp_ratio_mean,
        );
        // median of sorted [1.0, 2.0, 5.0] = 2.0
        assert_eq!(agg.amp_ratio_median, Some(2.0));
    }

    // ===========================================
    // Test Category H — Schema v7 Fields
    // (timing, HTTP status, JSON-RPC error, derived means)
    // via from_triples_and_metadata
    // ===========================================

    #[test]
    fn test_from_triples_empty_yields_all_none() {
        let agg = ResponseAggregates::from_triples_and_metadata(
            &[],
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        assert_eq!(agg.count, 0);
        assert_eq!(agg.resp_bytes_total, 0);
        assert_eq!(agg.req_bytes_max, None);
        assert_eq!(agg.resp_bytes_max, None);
        assert_eq!(agg.amp_ratio_mean, None);
        assert_eq!(agg.amp_ratio_median, None);
        assert_eq!(agg.amp_ratio_max, None);
        assert_eq!(agg.duration_ns_mean, None);
        assert_eq!(agg.duration_ns_max, None);
        assert_eq!(agg.status_2xx_frac, None);
        assert_eq!(agg.status_4xx_frac, None);
        assert_eq!(agg.status_5xx_frac, None);
        assert_eq!(agg.rpc_error_distinct_codes, None);
        assert_eq!(agg.rpc_error_frac, None);
        assert_eq!(agg.req_bytes_mean, None);
        assert_eq!(agg.resp_bytes_mean, None);
    }

    #[test]
    fn test_from_triples_no_metadata_matches_from_pairs_for_byte_aggregates() {
        // Pairs converted to triples with no duration and empty metadata
        // should produce the same byte/ratio aggregates as from_pairs.
        let pairs = [(100, 200), (50, 250), (200, 200)];
        let triples: Vec<(u64, u64, Option<u64>)> =
            pairs.iter().map(|(q, r)| (*q, *r, None)).collect();

        let agg_pairs = ResponseAggregates::from_pairs(&pairs);
        let agg_triples = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );

        assert_eq!(agg_pairs.count, agg_triples.count);
        assert_eq!(agg_pairs.resp_bytes_total, agg_triples.resp_bytes_total);
        assert_eq!(agg_pairs.req_bytes_max, agg_triples.req_bytes_max);
        assert_eq!(agg_pairs.resp_bytes_max, agg_triples.resp_bytes_max);
        assert_eq!(agg_pairs.amp_ratio_mean, agg_triples.amp_ratio_mean);
        assert_eq!(agg_pairs.amp_ratio_median, agg_triples.amp_ratio_median);
        assert_eq!(agg_pairs.amp_ratio_max, agg_triples.amp_ratio_max);
    }

    #[test]
    fn test_from_triples_populates_byte_means_when_count_positive() {
        // *_bytes_mean is derivable from triples alone (no extra metadata).
        // Plan: req_bytes_mean = sum(req)/count, resp_bytes_mean = sum(resp)/count.
        let triples = [(100, 200, None), (50, 250, None), (200, 600, None)];
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        // sum(req) = 350, count = 3 → mean = 350/3
        assert!(
            (agg.req_bytes_mean.unwrap() - (350.0 / 3.0)).abs() < 1e-9,
            "req_bytes_mean = 350/3, got {:?}", agg.req_bytes_mean,
        );
        // sum(resp) = 1050, count = 3 → mean = 350.0
        assert_eq!(agg.resp_bytes_mean, Some(350.0));
    }

    #[test]
    fn test_from_triples_duration_only_counts_some_values() {
        // Mixed: 2 with timing, 1 without. Mean averages over Some values
        // with d > 0; max takes the largest Some.
        let triples = [
            (100, 200, Some(1_000_000)),
            (100, 200, Some(3_000_000)),
            (100, 200, None), // no timing — excluded from both mean and max
        ];
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        // mean over [1_000_000, 3_000_000] = 2_000_000 ns
        assert_eq!(agg.duration_ns_mean, Some(2_000_000));
        assert_eq!(agg.duration_ns_max, Some(3_000_000));
    }

    #[test]
    fn test_from_triples_duration_excludes_zero_from_mean() {
        // Plan: "averaged over pairs with non-zero duration". 0-duration
        // pairs ARE included in the max but NOT in the mean.
        let triples = [
            (100, 200, Some(0)),
            (100, 200, Some(2_000_000)),
        ];
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        // mean over [2_000_000] only (0 excluded) = 2_000_000
        assert_eq!(agg.duration_ns_mean, Some(2_000_000));
        // max over [0, 2_000_000] = 2_000_000
        assert_eq!(agg.duration_ns_max, Some(2_000_000));
    }

    #[test]
    fn test_from_triples_duration_all_none_yields_none() {
        let triples = [(100, 200, None), (50, 250, None)];
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        assert_eq!(agg.duration_ns_mean, None);
        assert_eq!(agg.duration_ns_max, None);
    }

    #[test]
    fn test_from_triples_status_fractions_with_parsed_denominator() {
        // 4 responses, denominator (n_with_parsed_status) = 4: 2x 2xx, 1x 4xx, 1x 5xx
        let triples = [(100, 200, None); 4];
        let status = StatusCounts {
            n_2xx: 2,
            n_4xx: 1,
            n_5xx: 1,
            n_with_parsed_status: 4,
        };
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            status,
            RpcMetadata::default(),
        );
        assert_eq!(agg.status_2xx_frac, Some(0.5));
        assert_eq!(agg.status_4xx_frac, Some(0.25));
        assert_eq!(agg.status_5xx_frac, Some(0.25));
    }

    #[test]
    fn test_from_triples_status_fractions_skip_unparsed_responses() {
        // 4 pairs but only 2 had parseable status lines (others were non-HTTP).
        // Denominator is 2, not 4.
        let triples = [(100, 200, None); 4];
        let status = StatusCounts {
            n_2xx: 1,
            n_4xx: 0,
            n_5xx: 1,
            n_with_parsed_status: 2,
        };
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            status,
            RpcMetadata::default(),
        );
        assert_eq!(agg.status_2xx_frac, Some(0.5));
        assert_eq!(agg.status_4xx_frac, Some(0.0));
        assert_eq!(agg.status_5xx_frac, Some(0.5));
    }

    #[test]
    fn test_from_triples_status_none_when_no_parsed() {
        // No HTTP status lines parsed → all status_*_frac stay None.
        let triples = [(100, 200, None); 3];
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        assert_eq!(agg.status_2xx_frac, None);
        assert_eq!(agg.status_4xx_frac, None);
        assert_eq!(agg.status_5xx_frac, None);
    }

    #[test]
    fn test_from_triples_rpc_error_distinct_and_frac() {
        // 10 pairs, 4 error responses, 3 distinct error codes.
        let triples = [(100, 200, None); 10];
        let rpc = RpcMetadata {
            error_codes: vec![-32602, -32602, -32601, -32700],
            error_count: 4,
            n_with_parsed_envelope: 10,
        };
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            rpc,
        );
        // distinct {-32602, -32601, -32700} = 3
        assert_eq!(agg.rpc_error_distinct_codes, Some(3));
        // frac = 4/10 = 0.4
        assert_eq!(agg.rpc_error_frac, Some(0.4));
    }

    #[test]
    fn test_from_triples_rpc_error_caps_distinct_at_five() {
        // 10 distinct error codes → capped at 5.
        let triples = [(100, 200, None); 20];
        let rpc = RpcMetadata {
            error_codes: (0..10).collect(),
            error_count: 10,
            n_with_parsed_envelope: 20,
        };
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            rpc,
        );
        assert_eq!(agg.rpc_error_distinct_codes, Some(5));
    }

    #[test]
    fn test_from_triples_rpc_none_when_no_envelope_parsed() {
        let triples = [(100, 200, None); 5];
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            RpcMetadata::default(),
        );
        assert_eq!(agg.rpc_error_distinct_codes, None);
        assert_eq!(agg.rpc_error_frac, None);
    }

    #[test]
    fn test_from_triples_rpc_zero_errors_with_envelopes_parsed() {
        // All 5 responses parsed cleanly as JSON-RPC, none had error fields.
        let triples = [(100, 200, None); 5];
        let rpc = RpcMetadata {
            error_codes: vec![],
            error_count: 0,
            n_with_parsed_envelope: 5,
        };
        let agg = ResponseAggregates::from_triples_and_metadata(
            &triples,
            StatusCounts::default(),
            rpc,
        );
        // No distinct codes observed → still Some(0) because envelopes WERE parsed.
        assert_eq!(agg.rpc_error_distinct_codes, Some(0));
        assert_eq!(agg.rpc_error_frac, Some(0.0));
    }

    // ===========================================
    // Test Category I — v7 HostTelemetry block
    // (closes B.1 of PLAN-PRODUCTION-FEATURE-SURFACE)
    // ===========================================

    #[test]
    fn test_v7_snapshot_with_host_block_round_trips() {
        // Populate every host telemetry field with a clean-decimal value so
        // JSON round-trip is bit-stable. Verify equality through the
        // serialise/deserialise path.
        let host = HostTelemetry {
            cpu_mean: Some(25.5),
            cpu_max: Some(87.0),
            rss_delta: Some(-65536),
            rss_max: Some(2_147_483_648),
            rss_slope_bps: Some(1024.5),
            num_fds_delta: Some(4),
            num_connections_delta: Some(-2),
            num_connections_max: Some(128),
            io_write_delta: Some(4096),
        };
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000)
            .with_host(host.clone());

        let json = snapshot.to_json();
        let restored = Snapshot::from_json(&json).expect("v7 with host should round-trip");

        assert_eq!(restored.version, 7);
        assert_eq!(restored.host, Some(host));
    }

    #[test]
    fn test_v7_snapshot_without_host_block_omits_field() {
        // No `with_host` → JSON must not contain "host" key
        // (skip_serializing_if=Option::is_none).
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000);
        let json = snapshot.to_json();
        assert!(
            !json.contains("\"host\""),
            "JSON should omit host field: {}",
            json,
        );
    }

    #[test]
    fn test_host_telemetry_omits_none_fields_individually() {
        // A partially-populated HostTelemetry must omit the None-valued
        // fields from JSON. Operators that have no /proc/<pid>/io access
        // (e.g. unprivileged collector) emit cpu/rss but skip io_write_delta.
        let host = HostTelemetry {
            cpu_mean: Some(50.0),
            cpu_max: Some(75.0),
            rss_max: Some(1024),
            ..Default::default()
        };
        let snapshot = Snapshot::new(1000, &[8080], vec![], 60, 1000, 1000)
            .with_host(host);
        let json = snapshot.to_json();
        // Present fields appear
        assert!(json.contains("cpu_mean"), "expected cpu_mean in JSON: {}", json);
        assert!(json.contains("cpu_max"), "expected cpu_max in JSON: {}", json);
        assert!(json.contains("rss_max"), "expected rss_max in JSON: {}", json);
        // Absent (None) fields do not
        for absent in [
            "rss_delta",
            "rss_slope_bps",
            "num_fds_delta",
            "num_connections_delta",
            "num_connections_max",
            "io_write_delta",
        ] {
            assert!(
                !json.contains(absent),
                "expected {} omitted from JSON: {}",
                absent,
                json,
            );
        }
    }

    #[test]
    fn test_v6_snapshot_no_host_field_parses_under_v7() {
        // A literal v6 JSON (pre-host era) must still parse cleanly under
        // the v7-aware reader and surface `host: None`. Forward-compat
        // regression-pin — the Phase B schema addition is purely additive
        // and must not break existing readers.
        let v6_json = r#"{"version":6,"aggregation":"src_ip_dst_port","ts_unix_sec":1000,"interval_sec":60,"run_id":1000,"counter_mode":"cumulative","base_ts_unix_sec":1000,"dst_ports":[8080],"buckets":[]}"#;
        let restored = Snapshot::from_json(v6_json)
            .expect("v6 should parse under v7-with-host reader");
        assert_eq!(restored.version, 6);
        assert!(restored.host.is_none());
        assert!(restored.resp_aggregates.is_none());
    }
}
