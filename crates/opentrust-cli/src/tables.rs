//! `child`, `router`, `neighbor` and `counters`.

use core::fmt::Write;

use opentrust_instance::InstanceCrypto;
#[cfg(feature = "ftd")]
use opentrust_instance::RouteInfo;
#[cfg(feature = "ftd")]
use opentrust_mle::Role;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
#[cfg(feature = "ftd")]
use crate::util::parse_u16;
use crate::util::{Args, E, R, hex, ln, out, table_header};

/// Thread version reported for neighbors (Thread 1.4).
const NEIGHBOR_VERSION: u8 = 5;

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn child(&mut self, a: &Args<'_>) -> R {
        let table = match a.get(1) {
            "table" => true,
            "list" => false,
            _ => return Err(E::INVALID_COMMAND),
        };
        if table {
            table_header(
                self.o,
                &[
                    "ID",
                    "RLOC16",
                    "Timeout",
                    "Age",
                    "LQ In",
                    "C_VN",
                    "R",
                    "D",
                    "N",
                    "Ver",
                    "CSL",
                    "QMsgCnt",
                    "Suprvsn",
                    "Extended MAC",
                ],
                &[5, 8, 12, 12, 7, 6, 1, 1, 1, 3, 3, 7, 7, 18],
            );
        }
        for c in self.i.child_table() {
            if table {
                out!(self.o, "| {:3} ", c.rloc16.0 & 0x1ff);
                out!(self.o, "| 0x{:04x} ", c.rloc16.0);
                out!(self.o, "| {:10} ", c.timeout_secs);
                // Age, LQ In and QMsgCnt are not tracked per child by the
                // instance API.
                out!(self.o, "| {:10} ", 0);
                out!(self.o, "| {:5} ", 0);
                out!(self.o, "| {:4} ", c.network_data_version);
                out!(self.o, "|{:1}", u8::from(c.rx_on_when_idle));
                out!(self.o, "|{:1}", u8::from(c.full_thread_device));
                out!(self.o, "|{:1}", u8::from(c.full_thread_device));
                out!(self.o, "|{:3}", NEIGHBOR_VERSION);
                out!(self.o, "| {:1} ", u8::from(c.csl_synchronized));
                out!(self.o, "| {:5} ", 0);
                out!(self.o, "| {:5} ", c.supervision_interval);
                out!(self.o, "| ");
                hex(self.o, &c.ext.0);
                ln!(self.o, " |");
            } else {
                out!(self.o, "{} ", c.rloc16.0 & 0x1ff);
            }
        }
        if !table {
            ln!(self.o);
        }
        Ok(())
    }

    #[cfg(feature = "ftd")]
    pub(crate) fn router(&mut self, a: &Args<'_>) -> R {
        let table = match a.get(1) {
            "table" => true,
            "list" => false,
            "" => return Err(E::INVALID_COMMAND),
            id => return self.router_info(id),
        };
        if table {
            table_header(
                self.o,
                &[
                    "ID",
                    "RLOC16",
                    "Next Hop",
                    "Path Cost",
                    "LQ In",
                    "LQ Out",
                    "Age",
                    "Extended MAC",
                    "Link",
                ],
                &[4, 8, 10, 11, 7, 8, 5, 18, 6],
            );
        }
        let mut rows = self.i.route_table();
        let me = self.i.rloc16();
        if matches!(self.i.role(), Role::Router | Role::Leader)
            && !rows.iter().any(|r| r.rloc16 == me)
        {
            // OT lists the device itself too.
            let _ = rows.push(RouteInfo {
                router_id: (me.0 >> 10) as u8,
                rloc16: me,
                next_hop: None,
                cost: 0,
                is_neighbor: false,
                ext: self.i.ext_address(),
                link_quality_in: 0,
                link_quality_out: 0,
                age_secs: 0,
            });
            rows.sort_unstable_by_key(|r| r.router_id);
        }
        for r in rows {
            if table {
                out!(self.o, "| {:2} ", r.router_id);
                out!(self.o, "| 0x{:04x} ", r.rloc16.0);
                out!(self.o, "| {:8} ", r.next_hop.unwrap_or(63));
                // OpenThread keeps the cost 0 while there is no next hop.
                out!(
                    self.o,
                    "| {:9} ",
                    if r.next_hop.is_some() { r.cost } else { 0 }
                );
                out!(self.o, "| {:5} ", r.link_quality_in);
                out!(self.o, "| {:6} ", r.link_quality_out);
                out!(self.o, "| {:3} ", r.age_secs);
                out!(self.o, "| ");
                hex(self.o, &r.ext.0);
                ln!(self.o, " | {:4} |", u8::from(r.is_neighbor));
            } else {
                out!(self.o, "{} ", r.router_id);
            }
        }
        if !table {
            ln!(self.o);
        }
        Ok(())
    }

    pub(crate) fn neighbor(&mut self, a: &Args<'_>) -> R {
        let table = match a.get(1) {
            "table" => true,
            "list" => false,
            _ => return Err(E::INVALID_COMMAND),
        };
        if table {
            table_header(
                self.o,
                &[
                    "Role",
                    "RLOC16",
                    "Age",
                    "Avg RSSI",
                    "Last RSSI",
                    "LQ In",
                    "R",
                    "D",
                    "N",
                    "Extended MAC",
                    "Version",
                ],
                &[6, 8, 5, 10, 11, 7, 1, 1, 1, 18, 9],
            );
        }
        for n in self.i.neighbor_table() {
            if table {
                out!(self.o, "| {:>3}  ", if n.is_child { 'C' } else { 'R' });
                out!(self.o, "| 0x{:04x} ", n.rloc16.0);
                // The age and the last RSSI are not tracked separately.
                out!(self.o, "| {:3} ", 0);
                out!(self.o, "| {:8} ", n.average_rssi);
                out!(self.o, "| {:9} ", n.average_rssi);
                out!(self.o, "| {:5} ", n.link_quality_in);
                out!(self.o, "|{:1}", u8::from(n.rx_on_when_idle));
                out!(self.o, "|{:1}", u8::from(n.full_thread_device));
                out!(self.o, "|{:1}", u8::from(n.full_thread_device));
                out!(self.o, "| ");
                hex(self.o, &n.ext.0);
                ln!(self.o, " | {:7} |", NEIGHBOR_VERSION);
            } else {
                out!(self.o, "0x{:04x} ", n.rloc16.0);
            }
        }
        if !table {
            ln!(self.o);
        }
        Ok(())
    }

    /// `router <id>`: the entry of a router (a Router ID or an RLOC16).
    #[cfg(feature = "ftd")]
    fn router_info(&mut self, id: &str) -> R {
        let id = parse_u16(id)?;
        let id = if id > 62 { id >> 10 } else { id };
        let me = self.i.rloc16();
        let mut found = self
            .i
            .route_table()
            .into_iter()
            .find(|r| u16::from(r.router_id) == id);
        if found.is_none()
            && matches!(self.i.role(), Role::Router | Role::Leader)
            && me.0 >> 10 == id
        {
            found = Some(RouteInfo {
                router_id: id as u8,
                rloc16: me,
                next_hop: None,
                cost: 0,
                is_neighbor: false,
                ext: self.i.ext_address(),
                link_quality_in: 0,
                link_quality_out: 0,
                age_secs: 0,
            });
        }
        let Some(r) = found else {
            ln!(self.o, "Alloc: 0");
            return Ok(());
        };
        ln!(self.o, "Alloc: 1");
        ln!(self.o, "Router ID: {}", r.router_id);
        ln!(self.o, "Rloc: {:04x}", r.rloc16.0);
        ln!(
            self.o,
            "Next Hop: {:04x}",
            u16::from(r.next_hop.unwrap_or(63)) << 10
        );
        ln!(self.o, "Link: {}", u8::from(r.is_neighbor));
        if r.is_neighbor {
            out!(self.o, "Ext Addr: ");
            hex(self.o, &r.ext.0);
            ln!(self.o);
            ln!(
                self.o,
                "Cost: {}",
                if r.next_hop.is_some() { r.cost } else { 0 }
            );
            ln!(self.o, "Link Quality In: {}", r.link_quality_in);
            ln!(self.o, "Link Quality Out: {}", r.link_quality_out);
            ln!(self.o, "Age: {}", r.age_secs);
        }
        Ok(())
    }

    pub(crate) fn counters(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "" => {
                ln!(self.o, "mac");
                Ok(())
            }
            "mac" => {
                let c = *self.i.mac_counters();
                let o = &mut *self.o;
                ln!(o, "TxTotal: {}", c.tx_total);
                for (n, v) in [
                    ("TxUnicast", 0),
                    ("TxBroadcast", 0),
                    ("TxAckRequested", c.tx_ack_requested),
                    ("TxAcked", c.tx_acked),
                    ("TxNoAckRequested", 0),
                    ("TxData", c.tx_data),
                    ("TxDataPoll", c.tx_data_poll),
                    ("TxBeacon", c.tx_beacon),
                    ("TxBeaconRequest", c.tx_beacon_request),
                    ("TxOther", 0),
                    ("TxRetry", c.tx_retry),
                    ("TxErrCca", c.tx_err_cca),
                    ("TxErrBusyChannel", 0),
                    ("TxErrAbort", c.tx_err_abort),
                    ("TxDirectMaxRetryExpiry", c.tx_direct_max_retry_expiry),
                    ("TxIndirectMaxRetryExpiry", c.tx_indirect_max_retry_expiry),
                ] {
                    ln!(o, "    {n}: {v}");
                }
                ln!(o, "RxTotal: {}", c.rx_total);
                for (n, v) in [
                    ("RxUnicast", 0),
                    ("RxBroadcast", 0),
                    ("RxData", c.rx_data),
                    ("RxDataPoll", c.rx_data_poll),
                    ("RxBeacon", c.rx_beacon),
                    ("RxBeaconRequest", c.rx_beacon_request),
                    ("RxOther", c.rx_other),
                    ("RxAddressFiltered", 0),
                    ("RxDestAddrFiltered", c.rx_dest_addr_filtered),
                    ("RxDuplicated", 0),
                    ("RxErrNoFrame", c.rx_err_no_frame),
                    ("RxErrNoUnknownNeighbor", c.rx_err_unknown_neighbor),
                    ("RxErrInvalidSrcAddr", c.rx_err_invalid_src_addr),
                    ("RxErrSec", c.rx_err_sec),
                    ("RxErrFcs", 0),
                    ("RxErrOther", 0),
                ] {
                    ln!(o, "    {n}: {v}");
                }
                Ok(())
            }
            _ => Err(E::INVALID_COMMAND),
        }
    }
}
