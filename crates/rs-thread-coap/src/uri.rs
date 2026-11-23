//! Thread TMF URI list (OT `thread/uri_paths.{hpp,cpp}`, Thread 1.4 spec
//! "TMF URIs"). Paths have no leading slash (`a/aq`); on the wire each
//! segment is one Uri-Path option.

/// A TMF resource. The discriminant is the index in OT's alphabetical path
/// list and doubles as the [`crate::endpoint::ResourceId`] of the resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Uri {
    /// `a/ae`
    AddressError,
    /// `a/an`
    AddressNotify,
    /// `a/aq`
    AddressQuery,
    /// `a/ar`
    AddressRelease,
    /// `a/as`
    AddressSolicit,
    /// `a/sd`
    ServerData,
    /// `a/yl`
    AnycastLocate,
    /// `b/ba`
    BackboneAnswer,
    /// `b/bmr`
    BackboneMlr,
    /// `b/bq`
    BackboneQuery,
    /// `c/ab`
    AnnounceBegin,
    /// `c/ag`
    ActiveGet,
    /// `c/ar`
    ActiveReplace,
    /// `c/as`
    ActiveSet,
    /// `c/ca`
    CommissionerKeepAlive,
    /// `c/cg`
    CommissionerGet,
    /// `c/cp`
    CommissionerPetition,
    /// `c/cs`
    CommissionerSet,
    /// `c/dc`
    DatasetChanged,
    /// `c/er`
    EnergyReport,
    /// `c/es`
    EnergyScan,
    /// `c/je`
    JoinerEntrust,
    /// `c/jf`
    JoinerFinalize,
    /// `c/la`
    LeaderKeepAlive,
    /// `c/lp`
    LeaderPetition,
    /// `c/pc`
    PanIdConflict,
    /// `c/pg`
    PendingGet,
    /// `c/pq`
    PanIdQuery,
    /// `c/ps`
    PendingSet,
    /// `c/rx`
    RelayRx,
    /// `c/tx`
    RelayTx,
    /// `c/ur`
    ProxyRx,
    /// `c/ut`
    ProxyTx,
    /// `d/da`
    DiagnosticGetAnswer,
    /// `d/dg`
    DiagnosticGetRequest,
    /// `d/dq`
    DiagnosticGetQuery,
    /// `d/dr`
    DiagnosticReset,
    /// `n/dn`
    DuaRegistrationNotify,
    /// `n/dr`
    DuaRegistrationRequest,
    /// `n/mr`
    Mlr,
}

impl Uri {
    /// All URIs, sorted by path.
    pub const ALL: [Uri; 40] = [
        Uri::AddressError,
        Uri::AddressNotify,
        Uri::AddressQuery,
        Uri::AddressRelease,
        Uri::AddressSolicit,
        Uri::ServerData,
        Uri::AnycastLocate,
        Uri::BackboneAnswer,
        Uri::BackboneMlr,
        Uri::BackboneQuery,
        Uri::AnnounceBegin,
        Uri::ActiveGet,
        Uri::ActiveReplace,
        Uri::ActiveSet,
        Uri::CommissionerKeepAlive,
        Uri::CommissionerGet,
        Uri::CommissionerPetition,
        Uri::CommissionerSet,
        Uri::DatasetChanged,
        Uri::EnergyReport,
        Uri::EnergyScan,
        Uri::JoinerEntrust,
        Uri::JoinerFinalize,
        Uri::LeaderKeepAlive,
        Uri::LeaderPetition,
        Uri::PanIdConflict,
        Uri::PendingGet,
        Uri::PanIdQuery,
        Uri::PendingSet,
        Uri::RelayRx,
        Uri::RelayTx,
        Uri::ProxyRx,
        Uri::ProxyTx,
        Uri::DiagnosticGetAnswer,
        Uri::DiagnosticGetRequest,
        Uri::DiagnosticGetQuery,
        Uri::DiagnosticReset,
        Uri::DuaRegistrationNotify,
        Uri::DuaRegistrationRequest,
        Uri::Mlr,
    ];

    /// The Uri-Path string (`"a/aq"`).
    pub const fn path(self) -> &'static str {
        match self {
            Uri::AddressError => "a/ae",
            Uri::AddressNotify => "a/an",
            Uri::AddressQuery => "a/aq",
            Uri::AddressRelease => "a/ar",
            Uri::AddressSolicit => "a/as",
            Uri::ServerData => "a/sd",
            Uri::AnycastLocate => "a/yl",
            Uri::BackboneAnswer => "b/ba",
            Uri::BackboneMlr => "b/bmr",
            Uri::BackboneQuery => "b/bq",
            Uri::AnnounceBegin => "c/ab",
            Uri::ActiveGet => "c/ag",
            Uri::ActiveReplace => "c/ar",
            Uri::ActiveSet => "c/as",
            Uri::CommissionerKeepAlive => "c/ca",
            Uri::CommissionerGet => "c/cg",
            Uri::CommissionerPetition => "c/cp",
            Uri::CommissionerSet => "c/cs",
            Uri::DatasetChanged => "c/dc",
            Uri::EnergyReport => "c/er",
            Uri::EnergyScan => "c/es",
            Uri::JoinerEntrust => "c/je",
            Uri::JoinerFinalize => "c/jf",
            Uri::LeaderKeepAlive => "c/la",
            Uri::LeaderPetition => "c/lp",
            Uri::PanIdConflict => "c/pc",
            Uri::PendingGet => "c/pg",
            Uri::PanIdQuery => "c/pq",
            Uri::PendingSet => "c/ps",
            Uri::RelayRx => "c/rx",
            Uri::RelayTx => "c/tx",
            Uri::ProxyRx => "c/ur",
            Uri::ProxyTx => "c/ut",
            Uri::DiagnosticGetAnswer => "d/da",
            Uri::DiagnosticGetRequest => "d/dg",
            Uri::DiagnosticGetQuery => "d/dq",
            Uri::DiagnosticReset => "d/dr",
            Uri::DuaRegistrationNotify => "n/dn",
            Uri::DuaRegistrationRequest => "n/dr",
            Uri::Mlr => "n/mr",
        }
    }

    /// OT's log name (`UriToString`).
    pub const fn name(self) -> &'static str {
        match self {
            Uri::AddressError => "AddressError",
            Uri::AddressNotify => "AddressNotify",
            Uri::AddressQuery => "AddressQuery",
            Uri::AddressRelease => "AddressRelease",
            Uri::AddressSolicit => "AddressSolicit",
            Uri::ServerData => "ServerData",
            Uri::AnycastLocate => "AnycastLocate",
            Uri::BackboneAnswer => "BackboneAnswer",
            Uri::BackboneMlr => "BackboneMlr",
            Uri::BackboneQuery => "BackboneQuery",
            Uri::AnnounceBegin => "AnnounceBegin",
            Uri::ActiveGet => "ActiveGet",
            Uri::ActiveReplace => "ActiveReplace",
            Uri::ActiveSet => "ActiveSet",
            Uri::CommissionerKeepAlive => "CommissionerKeepAlive",
            Uri::CommissionerGet => "CommissionerGet",
            Uri::CommissionerPetition => "CommissionerPetition",
            Uri::CommissionerSet => "CommissionerSet",
            Uri::DatasetChanged => "DatasetChanged",
            Uri::EnergyReport => "EnergyReport",
            Uri::EnergyScan => "EnergyScan",
            Uri::JoinerEntrust => "JoinerEntrust",
            Uri::JoinerFinalize => "JoinerFinalize",
            Uri::LeaderKeepAlive => "LeaderKeepAlive",
            Uri::LeaderPetition => "LeaderPetition",
            Uri::PanIdConflict => "PanIdConflict",
            Uri::PendingGet => "PendingGet",
            Uri::PanIdQuery => "PanIdQuery",
            Uri::PendingSet => "PendingSet",
            Uri::RelayRx => "RelayRx",
            Uri::RelayTx => "RelayTx",
            Uri::ProxyRx => "ProxyRx",
            Uri::ProxyTx => "ProxyTx",
            Uri::DiagnosticGetAnswer => "DiagGetAnswer",
            Uri::DiagnosticGetRequest => "DiagGetRequest",
            Uri::DiagnosticGetQuery => "DiagGetQuery",
            Uri::DiagnosticReset => "DiagReset",
            Uri::DuaRegistrationNotify => "DuaRegNotify",
            Uri::DuaRegistrationRequest => "DuaRegRequest",
            Uri::Mlr => "Mlr",
        }
    }

    /// Look a path up (OT `UriFromPath`).
    pub fn from_path(path: &str) -> Option<Uri> {
        Self::ALL.iter().copied().find(|u| u.path() == path)
    }

    /// Look up by [`Uri::id`].
    pub fn from_id(id: u16) -> Option<Uri> {
        Self::ALL.get(id as usize).copied()
    }

    /// Numeric id (index into [`Uri::ALL`]).
    pub const fn id(self) -> u16 {
        self as u8 as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_matches_ot() {
        assert_eq!(Uri::ALL.len(), 40);
        for (i, u) in Uri::ALL.iter().enumerate() {
            assert_eq!(u.id() as usize, i);
            assert_eq!(Uri::from_path(u.path()), Some(*u));
            assert_eq!(Uri::from_id(i as u16), Some(*u));
        }
        // OT keeps `kEntries` sorted (BinarySearch); so do we.
        assert!(Uri::ALL.windows(2).all(|w| w[0].path() < w[1].path()));
        assert_eq!(Uri::AddressQuery.path(), "a/aq");
        assert_eq!(Uri::Mlr.path(), "n/mr");
        assert_eq!(Uri::DiagnosticGetRequest.name(), "DiagGetRequest");
        assert_eq!(Uri::from_path("a/zz"), None);
        assert_eq!(Uri::from_id(40), None);
    }
}
