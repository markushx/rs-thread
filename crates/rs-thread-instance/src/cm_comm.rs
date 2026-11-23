//! Glue of the on-mesh Commissioner and the Border Agent: their TMF
//! transport, relay messages and responses.

use rand_core::{CryptoRng, Rng};
use rs_thread_coap::message::Code;
use rs_thread_coap::uri::Uri;
use rs_thread_core::Error;
use rs_thread_core::time::Instant;
use rs_thread_platform::SettingsStore;

use crate::{Instance, InstanceCrypto};

/// A relay TMF request (`/c/rx`, `/c/tx`) or `/c/dc` left by the TMF
/// handler for after the dispatch: URI, confirmable, payload.
pub(crate) type Relay = (Uri, bool, heapless::Vec<u8, { crate::TMF_MSG }>);

#[cfg(feature = "commissioner")]
macro_rules! mesh_transport {
    ($self:ident) => {
        rs_thread_meshcop::commissioner::MeshTransport {
            agent: &mut $self.agent,
            rng: &mut $self.prng,
            sink: &mut $self.sink,
            mlp: $self.core.cfg.cur.mesh_local_prefix,
            rloc16: $self.mle.rloc16(),
            aloc16: &mut $self.glue.commissioner_aloc,
        }
    };
}
#[cfg(feature = "commissioner")]
pub(crate) use mesh_transport;

#[cfg(feature = "border-agent")]
pub(crate) mod ba {
    use core::net::{Ipv6Addr, SocketAddrV6};

    use rs_thread_coap::endpoint::{Peer, SendOpts};
    use rs_thread_coap::message::{Code, Type};
    use rs_thread_coap::uri::Uri;
    use rs_thread_core::Result;
    use rs_thread_core::message::Priority;
    use rs_thread_core::time::Instant;
    use rs_thread_meshcop::border_agent::{BorderAgentIo, Listener};
    use rs_thread_net::ip6::SendInfo;

    use crate::TmfAgent;
    use crate::commissioning::BaOut;
    use crate::stack::{MacRng, Outbox};

    /// [`BorderAgentIo`] over disjoint fields of the instance.
    pub(crate) struct BaIo<'a> {
        pub now: Instant,
        pub agent: &'a mut TmfAgent,
        pub rng: &'a mut MacRng,
        pub sink: &'a mut Outbox,
        pub rloc: Ipv6Addr,
        pub down: &'a mut BaOut,
        pub aloc: &'a mut Option<u16>,
    }

    impl BorderAgentIo for BaIo<'_> {
        fn send_to_commissioner(
            &mut self,
            listener: Listener,
            peer: &Peer,
            data: &[u8],
        ) -> Result<()> {
            self.down.push(listener, *peer, data)
        }

        fn tmf_post(
            &mut self,
            _now: Instant,
            dst: Ipv6Addr,
            uri: Uri,
            payload: &[u8],
            confirmable: bool,
            user: Option<u32>,
        ) -> Result<()> {
            if confirmable {
                self.agent.post(
                    self.now,
                    self.rng,
                    self.sink,
                    dst,
                    Some(self.rloc),
                    Priority::Net,
                    uri,
                    payload,
                    user,
                )
            } else {
                self.agent.send_request(
                    self.now,
                    self.rng,
                    self.sink,
                    dst,
                    &SendOpts {
                        src: Some(self.rloc),
                        priority: Priority::Net,
                        multicast_loop: false,
                    },
                    Type::Non,
                    Code::POST,
                    None,
                    |mut b| {
                        b.uri_path(uri.path())?;
                        b.finish_with_payload(payload)
                    },
                )
            }
        }

        fn send_udp(
            &mut self,
            src: &SocketAddrV6,
            dst: &SocketAddrV6,
            payload: &[u8],
        ) -> Result<()> {
            let mut info = SendInfo::new(*dst.ip());
            info.src = Some(*src.ip());
            self.sink.push(info, src.port(), dst.port(), payload)
        }

        fn set_commissioner_aloc(&mut self, aloc16: Option<u16>) {
            *self.aloc = aloc16;
        }
    }

    macro_rules! ba_io {
        ($self:ident, $now:expr) => {
            $crate::cm_comm::ba::BaIo {
                now: $now,
                agent: &mut $self.agent,
                rng: &mut $self.prng,
                sink: &mut $self.sink,
                rloc: $self
                    .core
                    .cfg
                    .cur
                    .mesh_local_prefix
                    .rloc($self.mle.rloc16()),
                down: &mut $self.cm.ba_out,
                aloc: &mut $self.glue.commissioner_aloc,
            }
        };
    }
    pub(crate) use ba_io;
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Timers of the Commissioner and the Border Agent.
    #[allow(clippy::unused_self)]
    pub(crate) fn service_commissioner_roles(&mut self, now: Instant) {
        #[cfg(feature = "commissioner")]
        {
            let mut t = mesh_transport!(self);
            self.cm.comm.poll(now, &mut t);
            while let Some(e) = self.cm.comm.pop_event() {
                self.core.push_event(crate::Event::Commissioner(e));
            }
        }
        #[cfg(feature = "border-agent")]
        {
            let mut io = ba::ba_io!(self, now);
            self.cm.ba.poll(now, &mut io);
            while let Some(e) = self.cm.ba.pop_event() {
                self.core.push_event(crate::Event::BorderAgent(e));
            }
        }
        let _ = now;
    }

    /// Process a relay / dataset-changed request left by the TMF handler.
    #[allow(clippy::unused_self)]
    pub(crate) fn handle_relay(&mut self, now: Instant, relay: Relay) {
        let (uri, con, payload) = relay;
        match uri {
            #[cfg(feature = "ftd")]
            Uri::RelayTx => {
                let mut io = crate::cm_glue::link_io!(self);
                let _ = self.cm.jr.handle_relay_tx(now, &mut io, con, &payload);
            }
            #[cfg(feature = "commissioner")]
            Uri::RelayRx => {
                // The Border Agent's petitioned external Commissioner takes
                // the relay; otherwise the on-mesh Commissioner.
                #[cfg(feature = "border-agent")]
                if self.cm.ba.commissioner_aloc16().is_some() {
                    let mut io = ba::ba_io!(self, now);
                    let _ =
                        self.cm
                            .ba
                            .handle_relay_rx(now, &mut self.core.rng, &mut io, con, &payload);
                    return;
                }
                let mut t = mesh_transport!(self);
                let _ =
                    self.cm
                        .comm
                        .handle_relay_rx(now, &mut self.core.rng, &mut t, con, &payload);
            }
            #[cfg(feature = "commissioner")]
            Uri::DatasetChanged => {
                let _ = self.cm.comm.handle_dataset_changed(con);
            }
            _ => {
                let _ = (now, con, payload);
            }
        }
    }

    /// The next DTLS datagram of the Border Agent for the external
    /// Commissioner; the host sends it on its external interface from the
    /// port of `listener` to `peer`.
    #[cfg(feature = "border-agent")]
    pub fn border_agent_take_datagram(&mut self) -> Option<crate::BaDatagram> {
        self.cm.ba_out.pop_front()
    }

    /// Route the outcome of a TMF request of the Commissioner or the
    /// Border Agent. Returns whether `user` was theirs.
    #[allow(clippy::unused_self)]
    pub(crate) fn commissioning_response(
        &mut self,
        now: Instant,
        user: u32,
        result: core::result::Result<(Code, &[u8]), Error>,
    ) -> bool {
        #[cfg(feature = "commissioner")]
        if rs_thread_meshcop::commissioner::is_commissioner_user(user) {
            let mut t = mesh_transport!(self);
            let _ = self.cm.comm.handle_response(now, &mut t, user, result);
            return true;
        }
        #[cfg(feature = "border-agent")]
        if rs_thread_meshcop::border_agent::is_border_agent_user(user) {
            let mut io = ba::ba_io!(self, now);
            self.cm.ba.handle_tmf_response(now, &mut io, user, result);
            return true;
        }
        let _ = (now, user, result);
        false
    }
}
