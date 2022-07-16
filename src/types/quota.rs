use crate::error::{Error, ParseError};
use crate::parse::{parse_many_into2, parse_until_done, MapOrNot, MapOrNot2};
use crate::types::UnsolicitedResponse;
use imap_proto::Response;
use ouroboros::self_referencing;
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::sync::mpsc;

/// From [SETQUOTA Resource limit](https://datatracker.ietf.org/doc/html/rfc2087#section-4.1)
///
/// Used by [`Session::set_quota`]
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuotaResourceLimit<'a> {
    /// The resource type
    pub name: QuotaResourceName<'a>,
    /// The amount for that resource
    pub amount: u64,
}

impl<'a> QuotaResourceLimit<'a> {
    /// Creates a new [`QuotaResourceLimit`]
    pub fn new(name: QuotaResourceName<'a>, amount: u64) -> Self {
        Self { name, amount }
    }
}

impl Display for QuotaResourceLimit<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.name, self.amount)
    }
}

/// From [Resources](https://datatracker.ietf.org/doc/html/rfc2087#section-3)
///
/// Used by [`QuotaLimit`], and [`QuotaResource`]
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuotaResourceName<'a> {
    /// Sum of messages' RFC822.SIZE, in units of 1024 octets
    Storage,
    /// Number of messages
    Message,
    /// Any other string (for future RFCs)
    Atom(Cow<'a, str>),
}

impl Display for QuotaResourceName<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage => write!(f, "STORAGE"),
            Self::Message => write!(f, "MESSAGE"),
            Self::Atom(s) => write!(f, "{}", s),
        }
    }
}

/// From [QUOTA Response](https://datatracker.ietf.org/doc/html/rfc2087#section-5.1)
///
/// This is a wrapper around a single single [`Quota`].
///
/// Used by [`Session::get_quota`] and [`Session::set_quota`]
#[self_referencing]
pub struct QuotaResponse {
    data: Vec<u8>,
    #[borrows(data)]
    #[covariant]
    pub(crate) quota: Option<Quota<'this>>,
}

impl QuotaResponse {
    /// Parse the [`Quota`] response from a response buffer.
    pub fn parse(
        owned: Vec<u8>,
        unsolicited: &mut mpsc::Sender<UnsolicitedResponse>,
    ) -> Result<Self, Error> {
        QuotaResponseTryBuilder {
            data: owned,
            quota_builder: |input| {
                // There should zero or one QUOTA response
                parse_until_done(input, true, unsolicited, |response| match response {
                    Response::Quota(q) => Ok(MapOrNot::Map(Quota::from_imap_proto(q))),
                    resp => Ok(MapOrNot::Not(resp)),
                })
            },
        }
        .try_build()
    }

    /// Access to the wrapped optional [`Quota`] struct
    pub fn parsed(&self) -> &Option<Quota<'_>> {
        self.borrow_quota()
    }
}

/// From [QUOTA Response](https://datatracker.ietf.org/doc/html/rfc2087#section-5.1)
///
/// Used by [`QuotaResponse`] and [`QuotaRoot`]
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Quota<'a> {
    /// The quota root name
    pub root_name: Cow<'a, str>,
    /// The defined resources with their usage and limits (could be empty)
    pub resources: Vec<QuotaResource<'a>>,
}

impl<'a> Quota<'a> {
    fn from_imap_proto(q: imap_proto::Quota<'a>) -> Self {
        Self {
            root_name: q.root_name,
            resources: q
                .resources
                .into_iter()
                .map(|e| QuotaResource {
                    name: match e.name {
                        imap_proto::QuotaResourceName::Storage => QuotaResourceName::Storage,
                        imap_proto::QuotaResourceName::Message => QuotaResourceName::Message,
                        imap_proto::QuotaResourceName::Atom(e) => QuotaResourceName::Atom(e),
                    },
                    usage: e.usage,
                    limit: e.limit,
                })
                .collect(),
        }
    }
}

/// From [QUOTA Response](https://datatracker.ietf.org/doc/html/rfc2087#section-5.1)
///
/// The quota resource sub-pieces in a [`Quota`]
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuotaResource<'a> {
    /// The resource type
    pub name: QuotaResourceName<'a>,
    /// current usage of the resource
    pub usage: u64,
    /// resource limit
    pub limit: u64,
}

/// From [QUOTAROOT Response](https://datatracker.ietf.org/doc/html/rfc2087#section-5.2)
///
/// Used by [`Session::get_quota_root`]
#[self_referencing]
pub struct QuotaRootResponse {
    data: Vec<u8>,
    #[borrows(data)]
    #[covariant]
    pub(crate) inner: InnerQuotaRootResponse<'this>,
}

impl Debug for QuotaRootResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.borrow_inner())
    }
}
/// Inner struct to manage storing the references for ouroboros
#[derive(Debug)]
pub(crate) struct InnerQuotaRootResponse<'a> {
    pub(crate) quota_root: imap_proto::QuotaRoot<'a>,
    pub(crate) quotas: Vec<Quota<'a>>,
}

impl QuotaRootResponse {
    /// Parse the [`QuotaRoot`] response from a response buffer.
    pub fn parse(
        owned: Vec<u8>,
        unsolicited: &mut mpsc::Sender<UnsolicitedResponse>,
    ) -> Result<Self, Error> {
        QuotaRootResponseTryBuilder {
            data: owned,
            inner_builder: |input| {
                let mut quota_roots = Vec::new();
                let mut quotas = Vec::new();

                parse_many_into2(
                    input,
                    &mut quota_roots,
                    &mut quotas,
                    unsolicited,
                    |response| match response {
                        Response::QuotaRoot(q) => Ok(MapOrNot2::Map1(q)),
                        Response::Quota(q) => Ok(MapOrNot2::Map2(Quota::from_imap_proto(q))),
                        resp => Ok(MapOrNot2::Not(resp)),
                    },
                )?;

                match quota_roots.len() {
                    1 => Ok(InnerQuotaRootResponse {
                        quota_root: quota_roots.remove(0),
                        quotas,
                    }),
                    _ => Err(Error::Parse(ParseError::Invalid(input.to_vec()))),
                }
            },
        }
        .try_build()
    }

    /// The mailbox name
    pub fn mailbox_name(&self) -> &str {
        &*self.borrow_inner().quota_root.mailbox_name
    }

    /// The list of quota roots for the mailbox name (could be empty)
    pub fn quota_root_names(&self) -> impl Iterator<Item = &str> {
        self.borrow_inner()
            .quota_root
            .quota_root_names
            .iter()
            .map(|e| &*e.as_ref())
    }

    /// The set of quotas for each named quota root (could be empty)
    pub fn quotas(&self) -> &[Quota<'_>] {
        &self.borrow_inner().quotas[..]
    }
}
