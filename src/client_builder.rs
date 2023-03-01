use std::future::Future;

use crate::{Client, Result};
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpStream};

#[cfg(feature = "native-tls")]
use tokio_native_tls::{TlsConnector, TlsStream};

/// A convenience builder for [`Client`] structs over various encrypted transports.
///
/// Creating a [`Client`] using `native-tls` transport is straightforward:
/// ```no_run
/// # use imap::ClientBuilder;
/// # {} #[cfg(feature = "native-tls")]
/// # fn main() -> Result<(), imap::Error> {
/// let client = ClientBuilder::new("imap.example.com", 993).native_tls()?;
/// # Ok(())
/// # }
/// ```
///
/// The returned [`Client`] is unauthenticated; to access session-related methods (through
/// [`Session`](crate::Session)), use [`Client::login`] or [`Client::authenticate`].
pub struct ClientBuilder {
    domain: String,
    port: u16,
    starttls: bool,
}

impl ClientBuilder
{
    /// Make a new `ClientBuilder` using the given domain and port.
    pub fn new(domain: String, port: u16) -> Self {
        ClientBuilder {
            domain,
            port,
            starttls: false,
        }
    }

    /// Use [`STARTTLS`](https://tools.ietf.org/html/rfc2595) for this connection.
    #[cfg(feature = "native-tls")]
    pub fn starttls(&mut self) -> &mut Self {
        self.starttls = true;
        self
    }

    /// Return a new [`Client`] using a `native-tls` transport.
    #[cfg(feature = "native-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
    pub async fn native_tls(&mut self) -> Result<Client<TlsStream<TcpStream>>> {
        self.connect(async move |domain, tcp| {
            let ssl_conn: TlsConnector = tokio_native_tls::native_tls::TlsConnector::builder().build()?.into();
            Ok(TlsConnector::connect(&ssl_conn, &domain, tcp).await?)
        }).await
    }

    /// Make a [`Client`] using a custom TLS initialization. This function is intended
    /// to be used if your TLS setup requires custom work such as adding private CAs
    /// or other specific TLS parameters.
    ///
    /// The `handshake` argument should accept two parameters:
    ///
    /// - domain: [`&str`]
    /// - tcp: [`TcpStream`]
    ///
    /// and yield a `Result<C>` where `C` is `AsyncRead + AsyncWrite`. It should only perform
    /// TLS initialization over the given `tcp` socket and return the encrypted stream
    /// object, such as a [`native_tls::TlsStream`] or a [`rustls_connector::TlsStream`].
    ///
    /// If the caller is using `STARTTLS` and previously called [`starttls`](Self::starttls)
    /// then the `tcp` socket given to the `handshake` function will be connected and will
    /// have initiated the `STARTTLS` handshake.
    ///
    pub async fn connect<Fut, F, C>(&mut self, handshake: F) -> Result<Client<C>>
    where
        C: AsyncRead + AsyncWrite + std::marker::Unpin,
        Fut: Future<Output = Result<C>>,
        F: FnOnce(String, TcpStream) -> Fut,
    {
        let tcp = if self.starttls {
            let tcp = TcpStream::connect((self.domain.as_ref(), self.port)).await?;
            let mut client = Client::new(tcp);
            client.read_greeting().await?;
            client.run_command_and_check_ok("STARTTLS").await?;
            client.into_inner()?
        } else {
            TcpStream::connect((self.domain.as_ref(), self.port)).await?
        };

        let tls = handshake(self.domain.clone(), tcp).await?;

        let mut client = Client::new(tls);
        if !self.starttls {
            client.read_greeting().await?;
        }

        Ok(client)
    }
}
