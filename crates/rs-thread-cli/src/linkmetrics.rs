//! `linkmetrics request|config|probe` (OT `cli_link_metrics.cpp`): the Link
//! Metrics Initiator of Thread 1.2.

use core::fmt::Write;

use rs_thread_instance::{Event, InstanceCrypto};
use rs_thread_mle::link_metrics::{EnhAckFlags, Metrics, MetricsValues, SeriesFlags};
use rs_thread_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, ln, out, parse_ip6, parse_u8};

/// The synchronous commands waiting for their answer.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    query: bool,
    series: bool,
    enh_ack: bool,
}

/// OT `ParseLinkMetricsFlags`.
fn parse_metrics(s: &str) -> Result<Metrics, E> {
    if s.is_empty() {
        return Err(E::INVALID_ARGS);
    }
    let mut m = Metrics::NONE;
    for c in s.chars() {
        match c {
            'p' => m.pdu_count = true,
            'q' => m.lqi = true,
            'm' => m.link_margin = true,
            'r' => m.rssi = true,
            _ => return Err(E::INVALID_ARGS),
        }
    }
    Ok(m)
}

/// OT `LinkMetricsStatusToStr`.
fn status_name(status: u8) -> &'static str {
    match status {
        0 => "Success",
        1 => "Cannot support new series",
        2 => "Series ID already registered",
        3 => "Series ID not recognized",
        4 => "No matching series ID",
        254 => "Other error",
        _ => "Unknown error",
    }
}

fn print_values<W: Write>(o: &mut W, v: &MetricsValues) {
    const AVG: &str = "(Exponential Moving Average)";
    if v.metrics.pdu_count {
        ln!(o, " - PDU Counter: {} (Count/Summation)", v.pdu_count);
    }
    if v.metrics.lqi {
        ln!(o, " - LQI: {} {}", v.lqi, AVG);
    }
    if v.metrics.link_margin {
        ln!(o, " - Margin: {} (dB) {}", v.link_margin, AVG);
    }
    if v.metrics.rssi {
        ln!(o, " - RSSI: {} (dBm) {}", v.rssi, AVG);
    }
}

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn linkmetrics(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "request" => self.lm_request(a),
            "config" => self.lm_config(a),
            "probe" => {
                let dst = parse_ip6(a.get(2))?;
                let series = parse_u8(a.get(3))?;
                let len = parse_u8(a.get(4))?;
                self.i
                    .link_metrics_probe(&dst, series, len, self.now)
                    .map_err(E::from)
            }
            "query" => {
                ln!(
                    self.o,
                    "The command \"linkmetrics query\" has been replaced by the command \"linkmetrics request\"."
                );
                Err(E::INVALID_COMMAND)
            }
            "mgmt" => {
                ln!(
                    self.o,
                    "The command \"linkmetrics mgmt\" has been replaced by the command \"linkmetrics config\"."
                );
                Err(E::INVALID_COMMAND)
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }

    /// `linkmetricsmgr enable|disable|show` (OT `cli.cpp`).
    pub(crate) fn linkmetricsmgr(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "enable" => self.i.link_metrics_manager_set_enabled(true, self.now),
            "disable" => self.i.link_metrics_manager_set_enabled(false, self.now),
            "show" => {
                for n in self.i.neighbor_table() {
                    if let Ok((margin, rssi)) = self.i.link_metrics_manager_values(&n.ext) {
                        out!(self.o, "ExtAddr:");
                        crate::util::hex(self.o, &n.ext.0);
                        ln!(self.o, ", LinkMargin:{margin}, Rssi:{rssi}");
                    }
                }
            }
            "" => {
                let on = self.i.is_link_metrics_manager_enabled();
                ln!(self.o, "{}", if on { "Enabled" } else { "Disabled" });
            }
            _ => return Err(E::INVALID_COMMAND),
        }
        Ok(())
    }

    fn lm_request(&mut self, a: &Args<'_>) -> R {
        let (sync, k) = if a.get(2) == "async" {
            (false, 3)
        } else {
            (true, 2)
        };
        let dst = parse_ip6(a.get(k))?;
        let (series, metrics) = match a.get(k + 1) {
            "single" => (0, Some(parse_metrics(a.get(k + 2))?)),
            "forward" => (parse_u8(a.get(k + 2))?, None),
            _ => return Err(E::INVALID_ARGS),
        };
        self.i
            .link_metrics_query(&dst, series, metrics.as_ref(), self.now)?;
        if sync {
            self.st.linkmetrics.query = true;
            return Err(E::PENDING);
        }
        Ok(())
    }

    fn lm_config(&mut self, a: &Args<'_>) -> R {
        let (sync, k) = if a.get(2) == "async" {
            (false, 3)
        } else {
            (true, 2)
        };
        let dst = parse_ip6(a.get(k))?;
        match a.get(k + 1) {
            "forward" => {
                let series = parse_u8(a.get(k + 2))?;
                let flags = a.get(k + 3);
                if flags.is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let mut sf = SeriesFlags::default();
                let mut clear = false;
                for (i, c) in flags.chars().enumerate() {
                    match c {
                        'l' => sf.link_probe = true,
                        'd' => sf.mac_data = true,
                        'r' => sf.mac_data_request = true,
                        'a' => sf.mac_ack = true,
                        'X' => {
                            if i != 0 || flags.len() != 1 || !a.get(k + 4).is_empty() {
                                return Err(E::INVALID_ARGS);
                            }
                            clear = true;
                        }
                        _ => return Err(E::INVALID_ARGS),
                    }
                }
                let metrics = if clear {
                    None
                } else {
                    let m = parse_metrics(a.get(k + 4))?;
                    if !a.get(k + 5).is_empty() {
                        return Err(E::INVALID_ARGS);
                    }
                    Some(m)
                };
                self.i.link_metrics_forward_series(
                    &dst,
                    series,
                    &sf,
                    metrics.as_ref(),
                    self.now,
                )?;
                if sync {
                    self.st.linkmetrics.series = true;
                    return Err(E::PENDING);
                }
                Ok(())
            }
            "enhanced-ack" => {
                let (flags, metrics) = match a.get(k + 2) {
                    "clear" => (EnhAckFlags::Clear, None),
                    "register" => {
                        let mut m = parse_metrics(a.get(k + 3))?;
                        // Reference device: reserved Type/Average Enum.
                        m.reserved = a.get(k + 4) == "r";
                        (EnhAckFlags::Register, Some(m))
                    }
                    _ => return Err(E::INVALID_ARGS),
                };
                self.i
                    .link_metrics_enh_ack(&dst, flags, metrics.as_ref(), self.now)?;
                if sync {
                    self.st.linkmetrics.enh_ack = true;
                    return Err(E::PENDING);
                }
                Ok(())
            }
            _ => Err(E::INVALID_ARGS),
        }
    }

    pub(crate) fn linkmetrics_event(&mut self, ev: &Event) {
        match ev {
            Event::LinkMetricsReport {
                from,
                values,
                status,
            } => {
                out!(self.o, "Received Link Metrics Report from: ");
                ln!(self.o, "{}", Ip6(*from));
                match values {
                    Some(v) => print_values(self.o, v),
                    None => ln!(
                        self.o,
                        "Link Metrics Report, status: {}",
                        status_name(*status)
                    ),
                }
                if core::mem::take(&mut self.st.linkmetrics.query) {
                    ln!(self.o, "Done");
                }
            }
            Event::LinkMetricsManagement { from, status } => {
                out!(self.o, "Received Link Metrics Management Response from: ");
                ln!(self.o, "{}", Ip6(*from));
                ln!(self.o, "Status: {}", status_name(*status));
                let p = &mut self.st.linkmetrics;
                if core::mem::take(&mut p.series) || core::mem::take(&mut p.enh_ack) {
                    ln!(self.o, "Done");
                }
            }
            Event::EnhAckLinkMetrics {
                rloc16,
                ext,
                lqi,
                link_margin,
                rssi,
            } => {
                out!(
                    self.o,
                    "Received Link Metrics data in Enh Ack from neighbor, short address:0x{:02x} , extended address:",
                    rloc16.0
                );
                for b in ext.0 {
                    out!(self.o, "{:02x}", b);
                }
                ln!(self.o);
                let v = MetricsValues {
                    metrics: Metrics {
                        pdu_count: false,
                        lqi: lqi.is_some(),
                        link_margin: link_margin.is_some(),
                        rssi: rssi.is_some(),
                        reserved: false,
                    },
                    pdu_count: 0,
                    lqi: lqi.unwrap_or(0),
                    link_margin: link_margin.unwrap_or(0),
                    rssi: rssi.unwrap_or(0),
                };
                print_values(self.o, &v);
            }
            _ => {}
        }
    }
}
