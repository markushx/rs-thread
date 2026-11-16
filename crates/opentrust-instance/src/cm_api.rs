//! The public commissioning API of the [`Instance`]: Joiner (OT
//! `otJoiner*`), Commissioner (`otCommissioner*`) and Border Agent
//! (`otBorderAgent*`).

use opentrust_core::time::Instant;
use opentrust_core::{Error, Result};
use opentrust_meshcop::joiner::{JoinerConfig, JoinerState};
use opentrust_meshcop::steering::JoinerDiscerner;
use opentrust_mle::Role;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::cm_glue::link_io;
use crate::{Instance, InstanceCrypto};

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    // ------------------------------------------------------------ joiner

    /// Start joining (OT `otJoinerStart`): discover Joiner Routers on
    /// `scan_channels` (bit `n` = channel `n`, `0` = all page 0 channels),
    /// run EC-JPAKE with `pskd` through the best one, send JOIN_FIN with
    /// the Provisioning URL and vendor information of `cfg`, and wait for
    /// the Joiner Entrust (key ID mode 0 under the KEK of the session).
    ///
    /// On success ([`Event::JoinerResult`](crate::Event::JoinerResult)
    /// `Ok`) the network key, channel and PAN ID are the Active Dataset and
    /// Thread is started; the rest of the dataset comes from the parent.
    /// Needs an enabled interface and Thread stopped
    /// ([`Error::InvalidState`]); [`Error::Busy`] while joining,
    /// [`Error::InvalidArgs`] for an invalid PSKd or over-long strings.
    pub fn joiner_start(
        &mut self,
        pskd: &str,
        cfg: &JoinerConfig<'_>,
        scan_channels: u32,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        if !self.ip6_enabled || self.mle.role() != Role::Disabled {
            return Err(Error::InvalidState);
        }
        let eui64 = self.cm.eui64;
        let mut io = link_io!(self);
        self.cm.joiner.start(
            now,
            &mut self.core.rng,
            &mut io,
            &eui64,
            pskd,
            cfg,
            scan_channels,
        )?;
        self.apply_joiner_actions(now);
        self.poll(now);
        Ok(())
    }

    /// Abort joining (OT `otJoinerStop`); reported as
    /// [`Event::JoinerResult`](crate::Event::JoinerResult) with
    /// [`Error::Abort`].
    pub fn joiner_stop(&mut self, now: Instant) {
        self.core.now = now;
        let mut io = link_io!(self);
        self.cm.joiner.stop(&mut io);
        self.apply_joiner_actions(now);
    }

    /// The Joiner's state.
    pub fn joiner_state(&self) -> JoinerState {
        self.cm.joiner.state()
    }

    /// The Joiner ID (from the EUI-64 or the discerner; OT
    /// `otJoinerGetId`).
    pub fn joiner_id(&self) -> opentrust_core::types::ExtAddress {
        *self.cm.joiner.id()
    }

    /// Use a Joiner Discerner instead of the EUI-64 derived Joiner ID
    /// (`Some`), or go back to the EUI-64 (`None`); only while idle (OT
    /// `otJoinerSetDiscerner`).
    pub fn joiner_set_discerner(&mut self, d: Option<JoinerDiscerner>) -> Result<()> {
        match d {
            Some(d) => self.cm.joiner.set_discerner(&mut self.core.rng, d),
            None => self.cm.joiner.clear_discerner(),
        }
    }

    // ------------------------------------------------------------ commissioner

    /// Become the on-mesh Commissioner (OT `otCommissionerStart`):
    /// petition the Leader with Commissioner ID `id`; JOIN_FIN with a
    /// Provisioning URL other than `provisioning_url` is rejected. Progress
    /// is reported as [`Event::Commissioner`](crate::Event::Commissioner).
    /// [`Error::InvalidState`] unless attached, [`Error::Already`] if
    /// running.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_start(
        &mut self,
        id: &str,
        provisioning_url: Option<&str>,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        if !self.mle.role().is_attached() {
            return Err(Error::InvalidState);
        }
        self.cm.comm.set_id(id)?;
        self.cm
            .comm
            .set_provisioning_url(provisioning_url.unwrap_or(""))?;
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm.comm.start(now, &mut self.core.rng, &mut t)?;
        self.poll(now);
        Ok(())
    }

    /// Stop the Commissioner and resign at the Leader (OT
    /// `otCommissionerStop`).
    #[cfg(feature = "commissioner")]
    pub fn commissioner_stop(&mut self, now: Instant) {
        self.core.now = now;
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm.comm.stop(now, &mut t, true);
        self.poll(now);
    }

    /// The Commissioner's state.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_state(&self) -> opentrust_meshcop::commissioner::CommissionerState {
        self.cm.comm.state()
    }

    /// The Commissioner ID of the next petition (OT `otCommissionerGetId`).
    #[cfg(feature = "commissioner")]
    pub fn commissioner_id(&self) -> &str {
        self.cm.comm.id()
    }

    /// The Provisioning URL the Commissioner expects from Joiners (empty:
    /// none; OT `otCommissionerGetProvisioningUrl`).
    #[cfg(feature = "commissioner")]
    pub fn commissioner_provisioning_url(&self) -> &str {
        self.cm.comm.provisioning_url()
    }

    /// Set the Commissioner ID (OT `otCommissionerSetId`; only while
    /// disabled).
    #[cfg(feature = "commissioner")]
    pub fn commissioner_set_id(&mut self, id: &str) -> Result<()> {
        self.cm.comm.set_id(id)
    }

    /// Set the Provisioning URL (OT `otCommissionerSetProvisioningUrl`).
    #[cfg(feature = "commissioner")]
    pub fn commissioner_set_provisioning_url(&mut self, url: &str) -> Result<()> {
        self.cm.comm.set_provisioning_url(url)
    }

    /// MGMT_COMMISSIONER_GET for the TLV types `types` (empty: all; OT
    /// `otCommissionerSendMgmtGet`). Only while active.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_mgmt_get(&mut self, types: &[u8], now: Instant) -> Result<()> {
        self.core.now = now;
        if self.cm.comm.state() != opentrust_meshcop::commissioner::CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm.comm.send_commissioner_get(now, &mut t, types)?;
        self.poll(now);
        Ok(())
    }

    /// MGMT_COMMISSIONER_SET with the TLVs `tlvs` as they are (OT
    /// `otCommissionerSendMgmtSet` sends exactly the given dataset fields
    /// and TLVs). Only while active.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_mgmt_set(&mut self, tlvs: &[u8], now: Instant) -> Result<()> {
        self.core.now = now;
        if self.cm.comm.state() != opentrust_meshcop::commissioner::CommissionerState::Active {
            return Err(Error::InvalidState);
        }
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm
            .comm
            .send_mgmt(now, &mut t, opentrust_coap::uri::Uri::CommissionerSet, tlvs)?;
        self.poll(now);
        Ok(())
    }

    /// MGMT_ACTIVE_SET / MGMT_PENDING_SET with the TLVs of `dataset` to the
    /// Leader (OT `otDatasetSendMgmtActiveSet` / `PendingSet`); an active
    /// Commissioner adds its Session ID unless the dataset has one.
    #[cfg(feature = "commissioner")]
    pub fn dataset_mgmt_set(
        &mut self,
        active: bool,
        dataset: &opentrust_meshcop::dataset::Dataset,
        now: Instant,
    ) -> Result<()> {
        use opentrust_meshcop::tlv::{WriterExt, ty};
        self.core.now = now;
        if !self.mle.role().is_attached() {
            return Err(Error::InvalidState);
        }
        let mut b = [0u8; 255];
        let mut w = opentrust_core::bytes::Writer::new(&mut b);
        w.write_slice(dataset.as_bytes())?;
        if self.cm.comm.state() == opentrust_meshcop::commissioner::CommissionerState::Active
            && !dataset.contains(ty::COMMISSIONER_SESSION_ID)
        {
            w.commissioner_session_id(self.cm.comm.session_id())?;
        }
        let uri = if active {
            opentrust_coap::uri::Uri::ActiveSet
        } else {
            opentrust_coap::uri::Uri::PendingSet
        };
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm.comm.send_mgmt(now, &mut t, uri, w.written())?;
        self.poll(now);
        Ok(())
    }

    /// MGMT_ACTIVE_GET / MGMT_PENDING_GET for the TLV types `types` (empty:
    /// all) to the Leader or to `dest` (OT `otDatasetSendMgmtActiveGet` /
    /// `PendingGet`).
    #[cfg(feature = "commissioner")]
    pub fn dataset_mgmt_get(
        &mut self,
        active: bool,
        types: &[u8],
        dest: Option<core::net::Ipv6Addr>,
        now: Instant,
    ) -> Result<()> {
        use opentrust_meshcop::tlv::WriterExt;
        self.core.now = now;
        if !self.mle.role().is_attached() {
            return Err(Error::InvalidState);
        }
        let mut b = [0u8; 64];
        let mut w = opentrust_core::bytes::Writer::new(&mut b);
        if !types.is_empty() {
            w.get_list(types)?;
        }
        let uri = if active {
            opentrust_coap::uri::Uri::ActiveGet
        } else {
            opentrust_coap::uri::Uri::PendingGet
        };
        match dest {
            None => {
                let mut t = crate::cm_comm::mesh_transport!(self);
                self.cm.comm.send_mgmt(now, &mut t, uri, w.written())?;
            }
            Some(d) => {
                let src = self.core.cfg.cur.mesh_local_prefix.rloc(self.mle.rloc16());
                self.agent.post(
                    now,
                    &mut self.prng,
                    &mut self.sink,
                    d,
                    Some(src),
                    opentrust_core::message::Priority::Net,
                    uri,
                    w.written(),
                    Some(opentrust_meshcop::commissioner::USER_MGMT),
                )?;
            }
        }
        self.poll(now);
        Ok(())
    }

    /// The Commissioner Session ID.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_session_id(&self) -> u16 {
        self.cm.comm.session_id()
    }

    /// Send an Energy Scan query (`/c/es`) to `dst` (a unicast or multicast
    /// address; OT `otCommissionerEnergyScan`). The reports arrive as
    /// [`Event::EnergyReport`](crate::Event::EnergyReport) and
    /// [`take_energy_report`](Self::take_energy_report).
    /// [`Error::InvalidState`] unless the Commissioner is active.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_energy_scan(
        &mut self,
        channel_mask: u32,
        count: u8,
        period: u16,
        scan_duration: u16,
        dst: core::net::Ipv6Addr,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        self.commissioner_active()?;
        let own = self.mle.rloc16();
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        opentrust_meshcop::scan::send_energy_scan_query(
            &mut self.agent,
            now,
            &mut self.prng,
            &mut self.sink,
            &mlp,
            own,
            dst,
            self.cm.comm.session_id(),
            channel_mask,
            count,
            period,
            scan_duration,
        )?;
        self.poll(now);
        Ok(())
    }

    /// Send a PAN ID Query (`/c/pq`) to `dst` (OT `otCommissionerPanIdQuery`);
    /// conflicts arrive as [`Event::PanIdConflict`](crate::Event::PanIdConflict).
    /// [`Error::InvalidState`] unless the Commissioner is active.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_pan_id_query(
        &mut self,
        pan_id: u16,
        channel_mask: u32,
        dst: core::net::Ipv6Addr,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        self.commissioner_active()?;
        let own = self.mle.rloc16();
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        opentrust_meshcop::scan::send_pan_id_query(
            &mut self.agent,
            now,
            &mut self.prng,
            &mut self.sink,
            &mlp,
            own,
            dst,
            self.cm.comm.session_id(),
            pan_id,
            channel_mask,
        )?;
        self.poll(now);
        Ok(())
    }

    /// Send an Announce Begin request (`/c/ab`) to `dst` (OT
    /// `otCommissionerAnnounceBegin`): the receiver sends MLE Announces on
    /// the channels of `channel_mask`, `count` times, `period` ms apart.
    /// [`Error::InvalidState`] unless the Commissioner is active.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_announce_begin(
        &mut self,
        channel_mask: u32,
        count: u8,
        period: u16,
        dst: core::net::Ipv6Addr,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        self.commissioner_active()?;
        let own = self.mle.rloc16();
        let mlp = self.core.cfg.cur.mesh_local_prefix;
        opentrust_meshcop::scan::send_announce_begin(
            &mut self.agent,
            now,
            &mut self.prng,
            &mut self.sink,
            &mlp,
            own,
            dst,
            self.cm.comm.session_id(),
            channel_mask,
            count,
            period,
        )?;
        self.poll(now);
        Ok(())
    }

    /// The last Energy Report received (channel mask and the energy list in
    /// dBm as signed bytes), if any.
    #[cfg(feature = "commissioner")]
    pub fn take_energy_report(
        &mut self,
    ) -> Option<(
        u32,
        heapless::Vec<u8, { opentrust_meshcop::scan::MAX_ENERGY_RESULTS }>,
    )> {
        self.scan.energy_report.take()
    }

    #[cfg(feature = "commissioner")]
    fn commissioner_active(&self) -> Result<()> {
        if self.cm.comm.state() == opentrust_meshcop::commissioner::CommissionerState::Active {
            Ok(())
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Admit a Joiner (any, an EUI-64 or a discerner) with `pskd` for
    /// `timeout` (OT `otCommissionerAddJoiner`); the Steering Data is
    /// updated at the Leader. Only while active.
    #[cfg(feature = "commissioner")]
    pub fn commissioner_add_joiner(
        &mut self,
        kind: opentrust_meshcop::commissioner::JoinerKind,
        pskd: &str,
        timeout: opentrust_core::time::Duration,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm.comm.add_joiner(now, &mut t, kind, pskd, timeout)?;
        self.poll(now);
        Ok(())
    }

    /// Remove a Joiner entry (OT `otCommissionerRemoveJoiner`).
    #[cfg(feature = "commissioner")]
    pub fn commissioner_remove_joiner(
        &mut self,
        kind: &opentrust_meshcop::commissioner::JoinerKind,
        now: Instant,
    ) -> Result<()> {
        self.core.now = now;
        let mut t = crate::cm_comm::mesh_transport!(self);
        self.cm
            .comm
            .remove_joiner(now, &mut t, kind, opentrust_core::time::Duration::ZERO)?;
        self.poll(now);
        Ok(())
    }

    // ------------------------------------------------------------ border agent

    /// Start the Border Agent on the host's external UDP `port` (OT
    /// `otBorderAgent` with the PSKc of the Active Dataset): the host
    /// feeds datagrams to [`border_agent_receive`](Self::border_agent_receive)
    /// and sends those of
    /// [`border_agent_take_datagram`](Self::border_agent_take_datagram).
    /// Discovery Responses advertise native commissioning if the Security
    /// Policy allows it. [`Error::InvalidState`] without a PSKc.
    #[cfg(feature = "border-agent")]
    pub fn border_agent_start(&mut self, port: u16) -> Result<()> {
        let pskc = self.core.cfg.pskc.clone().ok_or(Error::InvalidState)?;
        self.cm.ba.set_pskc(Some(pskc));
        self.core.border_agent_port = Some(port);
        Ok(())
    }

    /// Stop the Border Agent: close its sessions and discard an ephemeral
    /// key.
    #[cfg(feature = "border-agent")]
    pub fn border_agent_stop(&mut self, now: Instant) {
        let mut io = crate::cm_comm::ba::ba_io!(self, now);
        self.cm.ba.stop_ephemeral_key(now, &mut io);
        self.cm.ba.disconnect(now, &mut io);
        self.cm.ba.set_pskc(None);
        self.core.border_agent_port = None;
        self.poll(now);
    }

    /// A datagram from the external interface for the Border Agent: to
    /// the Border Agent port (`ephemeral == false`) or to the ePSKc port.
    #[cfg(feature = "border-agent")]
    pub fn border_agent_receive(
        &mut self,
        ephemeral: bool,
        peer: &opentrust_coap::endpoint::Peer,
        datagram: &[u8],
        now: Instant,
    ) {
        self.core.now = now;
        if self.core.border_agent_port.is_none() {
            return;
        }
        let cd = self.core.netdata.view().commissioning_data();
        let view = opentrust_meshcop::border_agent::BorderAgentView {
            datasets: &self.core.datasets,
            commissioning_data: cd,
            mesh_local_prefix: self.core.cfg.cur.mesh_local_prefix,
        };
        let mut io = crate::cm_comm::ba::BaIo {
            now,
            agent: &mut self.agent,
            rng: &mut self.prng,
            sink: &mut self.sink,
            rloc: self.core.cfg.cur.mesh_local_prefix.rloc(self.mle.rloc16()),
            down: &mut self.cm.ba_out,
            aloc: &mut self.glue.commissioner_aloc,
        };
        if ephemeral {
            self.cm.ba.handle_ephemeral_udp(
                now,
                &mut self.core.rng,
                &mut io,
                &view,
                peer,
                datagram,
            );
        } else {
            self.cm
                .ba
                .handle_udp(now, &mut self.core.rng, &mut io, &view, peer, datagram);
        }
        self.poll(now);
    }

    /// Accept the ephemeral key `key` (ePSKc, OT
    /// `otBorderAgentEphemeralKeyStart`) on the host's external UDP
    /// `port` for `timeout` (zero: the default); returns the effective
    /// timeout. The key is single use. [`Error::InvalidState`] if the
    /// Border Agent is not running or a key is in use.
    #[cfg(feature = "border-agent")]
    pub fn border_agent_set_ephemeral_key(
        &mut self,
        key: &[u8],
        timeout: opentrust_core::time::Duration,
        port: u16,
        now: Instant,
    ) -> Result<opentrust_core::time::Duration> {
        if self.core.border_agent_port.is_none() {
            return Err(Error::InvalidState);
        }
        let key = opentrust_meshcop::epskc::EphemeralKey::new(key)?;
        let mut io = crate::cm_comm::ba::ba_io!(self, now);
        self.cm
            .ba
            .start_ephemeral_key(now, &mut io, key, timeout, port)
    }

    /// Discard the ephemeral key and close its session.
    #[cfg(feature = "border-agent")]
    pub fn border_agent_clear_ephemeral_key(&mut self, now: Instant) {
        let mut io = crate::cm_comm::ba::ba_io!(self, now);
        self.cm.ba.stop_ephemeral_key(now, &mut io);
    }
}
