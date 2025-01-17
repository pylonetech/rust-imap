//! Adds support for the IMAP IDLE command specificed in [RFC
//! 2177](https://tools.ietf.org/html/rfc2177).

use crate::client::Session;
use crate::error::Result;
use crate::parse::parse_idle;
use crate::types::UnsolicitedResponse;
use tokio::{io::{AsyncRead, AsyncWrite}, sync::{mpsc::UnboundedSender, oneshot}, time::Instant, task};
use std::time::Duration;

/// `Handle` allows a client to block waiting for changes to the remote mailbox.
///
/// The handle blocks using the [`IDLE` command](https://tools.ietf.org/html/rfc2177#section-3)
/// specificed in [RFC 2177](https://tools.ietf.org/html/rfc2177) until the underlying server state
/// changes in some way.
///
/// The `wait_while` function takes a callback function which receives any responses
/// that arrive on the channel while IDLE. The callback function implements whatever
/// logic is needed to handle the IDLE response, and then returns a boolean
/// to continue idling (`true`) or stop (`false`).
///
/// For users that want the IDLE to exit on any change (the behavior proior to version 3.0),
/// a convenience callback function [`stop_on_any`] is provided.
///
/// ```no_run
/// use imap::extensions::idle;
/// # #[cfg(feature = "native-tls")]
/// # {
/// let client = imap::ClientBuilder::new("example.com", 993).native_tls()
///     .expect("Could not connect to imap server");
/// let mut imap = client.login("user@example.com", "password")
///     .expect("Could not authenticate");
/// imap.select("INBOX")
///     .expect("Could not select mailbox");
///
/// // Exit on any mailbox change. By default, connections will be periodically
/// // refreshed in the background.
/// let result = imap.idle().wait_while(idle::stop_on_any);
/// # }
/// ```
///
/// Note that the server MAY consider a client inactive if it has an IDLE command running, and if
/// such a server has an inactivity timeout it MAY log the client off implicitly at the end of its
/// timeout period. Because of that, clients using IDLE are advised to terminate the IDLE and
/// re-issue it at least every 29 minutes to avoid being logged off. This is done by default, but
/// can be disabled by calling [`Handle::keepalive`]
///
/// As long as a [`Handle`] is active, the mailbox cannot be otherwise accessed.
#[derive(Debug)]
pub struct Handle<'a, T: AsyncRead + AsyncWrite + std::marker::Unpin> {
    session: &'a mut Session<T>,
    done: bool,
}

/// The result of a wait on a [`Handle`]
#[derive(Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The wait timed out
    TimedOut,
    /// The mailbox was modified
    MailboxChanged,
}

/// A convenience function to always cause the IDLE handler to exit on any change.
pub fn stop_on_any(_response: UnsolicitedResponse) -> bool {
    false
}

/// Must be implemented for a transport in order for a `Session` to use IDLE.
pub trait SetReadTimeout {
    /// Set the timeout for subsequent reads to the given one.
    ///
    /// If `timeout` is `None`, the read timeout should be removed.
    ///
    /// See also `std::net::TcpStream::set_read_timeout`.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()>;
}

impl<'a, T: AsyncRead + AsyncWrite + std::marker::Unpin + 'a> Handle<'a, T> {
    pub(crate) fn make(session: &'a mut Session<T>) -> Self {
        Handle {
            session,
            done: false,
        }
    }

    async fn init(&mut self) -> Result<()> {
        // https://tools.ietf.org/html/rfc2177
        //
        // The IDLE command takes no arguments.
        self.session.run_command("IDLE").await?;

        // A tagged response will be sent either
        //
        //   a) if there's an error, or
        //   b) *after* we send DONE
        let mut v = Vec::new();
        self.session.readline(&mut v).await?;
        if v.starts_with(b"+") {
            self.done = false;
            return Ok(());
        }

        self.session.read_response_onto(&mut v).await?;
        // We should *only* get a continuation on an error (i.e., it gives BAD or NO).
        unreachable!();
    }

    async fn terminate(&mut self) -> Result<()> {
        if !self.done {
            self.done = true;
            self.session.write_line(b"DONE").await?;
            self.session.read_response().await.map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Internal helper that doesn't consume self.
    ///
    /// This is necessary so that we can keep using the inner `Session` in `wait_while`.
    async fn wait_inner(
        &mut self,
        idle_tx: UnboundedSender<UnsolicitedResponse>,
        mut kill_rx: oneshot::Receiver<()>,
    ) -> Result<()>
    {
        let mut v = Vec::new();

        let res = loop {
            tokio::select! {
                _ = &mut kill_rx => {
                    break Ok(());
                },
                x = self.session.readline(&mut v) => match x {
                    Ok(_len) => {
                        //  Handle Dovecot's imap_idle_notify_interval message
                        if v.eq_ignore_ascii_case(b"* OK Still here\r\n") {
                            v.clear();
                            continue;
                        }
                        match parse_idle(&v) {
                            // Something went wrong parsing.
                            (_rest, Some(Err(r))) => break Err(r),
                            // Complete response. We expect rest to be empty.
                            (rest, Some(Ok(response))) => {
                                idle_tx.send(response).unwrap();
    
                                // Assert on partial parse in debug builds - we expect
                                // to always parse all or none of the input buffer.
                                // On release builds, we still do the right thing.
                                debug_assert!(
                                    rest.is_empty(),
                                    "Unexpected partial parse: input: {:?}, output: {:?}",
                                    v,
                                    rest,
                                );
    
                                if rest.is_empty() {
                                    v.clear();
                                } else {
                                    let used = v.len() - rest.len();
                                    v.drain(0..used);
                                }
                            }
                            // Incomplete parse - do nothing and read more.
                            (_rest, None) => {}
                        }
                    }
                    Err(r) => break Err(r),
                },
            }
        };

        res
    }
    
    /// Block until the given callback returns `false`, or until a response
    /// arrives that is not explicitly handled by [`UnsolicitedResponse`].
    pub async fn wait_while(
        mut self,
        idle_tx: UnboundedSender<UnsolicitedResponse>,
        kill_rx: oneshot::Receiver<()>,
    ) -> Result<()>
    {
        self.init().await?;
        // The server MAY consider a client inactive if it has an IDLE command
        // running, and if such a server has an inactivity timeout it MAY log
        // the client off implicitly at the end of its timeout period.  Because
        // of that, clients using IDLE are advised to terminate the IDLE and
        // re-issue it at least every 29 minutes to avoid being logged off.
        // This still allows a client to receive immediate mailbox updates even
        // though it need only "poll" at half hour intervals.
        // TODO
        let res = self.wait_inner(
            idle_tx,
            kill_rx,
        ).await;
        let _ = self.terminate().await.is_ok();
        res
    }
}
