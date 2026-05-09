// Copyright 2017-2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use futures::channel::mpsc;
use libp2p_identity::PeerId;
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    MtuDiscoveryConfig, VarInt,
};
use std::{sync::Arc, time::Duration};

/// Default datagram send buffer size (1 MiB) when datagrams are enabled.
const DEFAULT_DATAGRAM_SEND_BUFFER_SIZE: usize = 1024 * 1024;
/// Default datagram receive buffer size (1 MiB) when datagrams are enabled.
const DEFAULT_DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 1024 * 1024;

/// Config for the transport.
#[derive(Clone)]
pub struct Config {
    /// Timeout for the initial handshake when establishing a connection.
    /// The actual timeout is the minimum of this and the [`Config::max_idle_timeout`].
    pub handshake_timeout: Duration,
    /// Maximum duration of inactivity in ms to accept before timing out the connection.
    pub max_idle_timeout: u32,
    /// Period of inactivity before sending a keep-alive packet.
    /// Must be set lower than the idle_timeout of both
    /// peers to be effective.
    ///
    /// See [`quinn::TransportConfig::keep_alive_interval`] for more
    /// info.
    pub keep_alive_interval: Duration,
    /// Maximum number of incoming bidirectional streams that may be open
    /// concurrently by the remote peer.
    pub max_concurrent_stream_limit: u32,

    /// Max unacknowledged data in bytes that may be sent on a single stream.
    pub max_stream_data: u32,

    /// Max unacknowledged data in bytes that may be sent in total on all streams
    /// of a connection.
    pub max_connection_data: u32,

    /// Support QUIC version draft-29 for dialing and listening.
    ///
    /// Per default only QUIC Version 1 / [`libp2p_core::multiaddr::Protocol::QuicV1`]
    /// is supported.
    ///
    /// If support for draft-29 is enabled servers support draft-29 and version 1 on all
    /// QUIC listening addresses.
    /// As client the version is chosen based on the remote's address.
    pub support_draft_29: bool,

    /// Whether to advertise QUIC unreliable datagram support (RFC 9221) to peers.
    ///
    /// When `true`, the underlying [`quinn::TransportConfig`] sets non-zero
    /// send/receive datagram buffer sizes (see [`Config::datagram_send_buffer_size`] and
    /// [`Config::datagram_receive_buffer_size`]) so that datagrams are negotiated during
    /// the QUIC handshake. Applications obtain post-handshake [`quinn::Connection`]
    /// handles via [`Config::post_handshake_connection_sender`] and call
    /// `connection.send_datagram(...)` / `connection.read_datagram().await` directly.
    ///
    /// Default: `false` — bit-identical to upstream libp2p-quic behaviour. Enable only
    /// when downstream code (e.g. nerw-core's audio transport, NRW-000040 Phase B-1b)
    /// needs unreliable datagrams.
    pub enable_datagrams: bool,

    /// Per-connection send buffer size for QUIC unreliable datagrams (in bytes).
    ///
    /// Applied only when [`Config::enable_datagrams`] is `true`. Quinn implements
    /// drop-old policy natively: when the buffer is full, the oldest queued datagram is
    /// discarded to make room for the newest one. Default: 1 MiB.
    pub datagram_send_buffer_size: usize,

    /// Per-connection receive buffer size for QUIC unreliable datagrams (in bytes).
    ///
    /// Applied only when [`Config::enable_datagrams`] is `true`. Default: 1 MiB.
    pub datagram_receive_buffer_size: usize,

    /// Optional channel that delivers each post-handshake [`quinn::Connection`] together
    /// with the remote [`PeerId`] to application code, so the application can call
    /// `Connection::send_datagram` / `Connection::read_datagram` outside the
    /// libp2p Swarm.
    ///
    /// `quinn::Connection` is `Clone` (internally `Arc<ConnectionRef>`), so cloning the
    /// handle into the channel is cheap and does not affect the libp2p stream-multiplexer
    /// path. The fork populates this sender from
    /// [`crate::connection::Connecting`] after the TLS handshake completes (see
    /// `connecting.rs`). On `try_send` failure (channel full or closed) the side-channel
    /// silently drops the handle — application code that has not subscribed yet, or that
    /// has not drained, simply does not learn about that particular connection.
    ///
    /// Default: `None`. Set to `Some(sender)` from a paired
    /// `mpsc::channel::<(PeerId, quinn::Connection)>(...)`. The receiver should be
    /// drained promptly by the application's event loop.
    pub post_handshake_connection_sender: Option<mpsc::Sender<(PeerId, quinn::Connection)>>,

    /// TLS client config for the inner [`quinn::ClientConfig`].
    client_tls_config: Arc<QuicClientConfig>,
    /// TLS server config for the inner [`quinn::ServerConfig`].
    server_tls_config: Arc<QuicServerConfig>,
    /// Libp2p identity of the node.
    keypair: libp2p_identity::Keypair,

    /// Parameters governing MTU discovery. See [`MtuDiscoveryConfig`] for details.
    mtu_discovery_config: Option<MtuDiscoveryConfig>,
}

impl Config {
    /// Creates a new configuration object with default values.
    pub fn new(keypair: &libp2p_identity::Keypair) -> Self {
        let client_tls_config = Arc::new(
            QuicClientConfig::try_from(libp2p_tls::make_client_config(keypair, None).unwrap())
                .unwrap(),
        );
        let server_tls_config = Arc::new(
            QuicServerConfig::try_from(libp2p_tls::make_server_config(keypair).unwrap()).unwrap(),
        );
        Self {
            client_tls_config,
            server_tls_config,
            support_draft_29: false,
            handshake_timeout: Duration::from_secs(5),
            max_idle_timeout: 10 * 1000,
            max_concurrent_stream_limit: 256,
            keep_alive_interval: Duration::from_secs(5),
            max_connection_data: 15_000_000,

            // Ensure that one stream is not consuming the whole connection.
            max_stream_data: 10_000_000,
            keypair: keypair.clone(),
            mtu_discovery_config: Some(Default::default()),
            // Datagram surface ON by default in tolki-datagram fork (Pavel
            // directive 2026-05-09 — wire-protocol-v2 нуждается в RFC 9221
            // datagrams для voice path; обходить через прямой quinn::Connection
            // доступ — anti-pattern). Upstream libp2p-quic ставит false; мы
            // флипаем в форке. Application может opt-out явным
            // .enable_datagrams(false) если нужно.
            enable_datagrams: true,
            datagram_send_buffer_size: DEFAULT_DATAGRAM_SEND_BUFFER_SIZE,
            datagram_receive_buffer_size: DEFAULT_DATAGRAM_RECEIVE_BUFFER_SIZE,
            post_handshake_connection_sender: None,
        }
    }

    /// Set the upper bound to the max UDP payload size that MTU discovery will search for.
    pub fn mtu_upper_bound(mut self, value: u16) -> Self {
        self.mtu_discovery_config
            .get_or_insert_with(Default::default)
            .upper_bound(value);
        self
    }

    /// Disable MTU path discovery (it is enabled by default).
    pub fn disable_path_mtu_discovery(mut self) -> Self {
        self.mtu_discovery_config = None;
        self
    }
}

/// Represents the inner configuration for [`quinn`].
#[derive(Clone)]
pub(crate) struct QuinnConfig {
    pub(crate) client_config: quinn::ClientConfig,
    pub(crate) server_config: quinn::ServerConfig,
    pub(crate) endpoint_config: quinn::EndpointConfig,
    /// Forwarded from [`Config::post_handshake_connection_sender`]. Threaded through
    /// to [`crate::connection::Connecting`] so that newly-handshaked
    /// `quinn::Connection` handles can be surfaced to application code.
    pub(crate) post_handshake_connection_sender:
        Option<mpsc::Sender<(PeerId, quinn::Connection)>>,
}

impl std::fmt::Debug for QuinnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuinnConfig")
            .field("client_config", &"<quinn::ClientConfig>")
            .field("server_config", &"<quinn::ServerConfig>")
            .field("endpoint_config", &self.endpoint_config)
            .field(
                "post_handshake_connection_sender",
                &self.post_handshake_connection_sender.is_some(),
            )
            .finish()
    }
}

impl From<Config> for QuinnConfig {
    fn from(config: Config) -> QuinnConfig {
        let Config {
            client_tls_config,
            server_tls_config,
            max_idle_timeout,
            max_concurrent_stream_limit,
            keep_alive_interval,
            max_connection_data,
            max_stream_data,
            support_draft_29,
            handshake_timeout: _,
            keypair,
            mtu_discovery_config,
            enable_datagrams,
            datagram_send_buffer_size,
            datagram_receive_buffer_size,
            post_handshake_connection_sender,
        } = config;
        let mut transport = quinn::TransportConfig::default();
        // Disable uni-directional streams.
        transport.max_concurrent_uni_streams(0u32.into());
        transport.max_concurrent_bidi_streams(max_concurrent_stream_limit.into());
        // Datagram surface (RFC 9221). When disabled (default — upstream
        // behaviour), `datagram_receive_buffer_size(None)` advertises 0 to
        // the peer, which negotiates datagrams off entirely. When enabled,
        // both buffers are sized so quinn's native drop-old policy has room
        // to absorb burst traffic before evicting the oldest queued datagram.
        if enable_datagrams {
            transport.datagram_send_buffer_size(datagram_send_buffer_size);
            transport.datagram_receive_buffer_size(Some(datagram_receive_buffer_size));
        } else {
            // Disable datagrams (upstream-bit-identical default).
            transport.datagram_receive_buffer_size(None);
        }
        transport.keep_alive_interval(Some(keep_alive_interval));
        transport.max_idle_timeout(Some(VarInt::from_u32(max_idle_timeout).into()));
        transport.allow_spin(false);
        transport.stream_receive_window(max_stream_data.into());
        transport.receive_window(max_connection_data.into());
        transport.mtu_discovery_config(mtu_discovery_config);
        let transport = Arc::new(transport);

        let mut server_config = quinn::ServerConfig::with_crypto(server_tls_config);
        server_config.transport = Arc::clone(&transport);
        // Disables connection migration.
        // Long-term this should be enabled, however we then need to handle address change
        // on connections in the `Connection`.
        server_config.migration(false);

        let mut client_config = quinn::ClientConfig::new(client_tls_config);
        client_config.transport_config(transport);

        let mut endpoint_config = keypair
            .derive_secret(b"libp2p quic stateless reset key")
            .map(|secret| {
                let reset_key = Arc::new(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret));
                quinn::EndpointConfig::new(reset_key)
            })
            .unwrap_or_default();

        if !support_draft_29 {
            endpoint_config.supported_versions(vec![1]);
        }

        QuinnConfig {
            client_config,
            server_config,
            endpoint_config,
            post_handshake_connection_sender,
        }
    }
}
