//! Service types.

use {
    crate::{body::Body, execute::ExecuteCtx, tls::TlsAcceptor, tls::TlsStream, Error},
    acme2_eab::{gen_ec_p256_private_key, AccountBuilder, Csr, DirectoryBuilder, OrderBuilder},
    futures::future::{self, Ready},
    hyper::{
        http::{Request, Response},
        server::conn::{AddrIncoming, AddrStream},
        service::Service,
    },
    openssl::pkey::PKey,
    rustls::{Certificate, PrivateKey, ServerConfig},
    std::{
        convert::Infallible,
        env,
        future::Future,
        net::{IpAddr, SocketAddr},
        pin::Pin,
        sync,
        task::{self, Poll},
        time::Duration,
    },
    tracing::{event, Level},
};

/// A Viceroy service uses a Wasm module and a handler function to respond to HTTP requests.
///
/// This service type is used to compile a Wasm [`Module`][mod], and perform the actions necessary
/// to initialize a [`Server`][serv] and bind the service to a local port.
///
/// Each time a connection is received, a [`RequestService`][req-svc] will be created, to
/// instantiate the module and return a [`Response`][resp].
///
/// [mod]: https://docs.rs/wasmtime/latest/wasmtime/struct.Module.html
/// [req-svc]: struct.RequestService.html
/// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
/// [serv]: https://docs.rs/hyper/latest/hyper/server/struct.Server.html
pub struct ViceroyService {
    ctx: ExecuteCtx,
}

impl ViceroyService {
    /// Create a new Viceroy service, using the given handler function and module path.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::collections::HashSet;
    /// use viceroy_lib::{Error, ExecuteCtx, ProfilingStrategy, ViceroyService};
    /// # fn f() -> Result<(), Error> {
    /// let ctx = ExecuteCtx::new("path/to/a/file.wasm", ProfilingStrategy::None, HashSet::new(), None)?;
    /// let svc = ViceroyService::new(ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(ctx: ExecuteCtx) -> Self {
        Self { ctx }
    }

    /// An internal helper, create a [`RequestService`](struct.RequestService.html).
    fn make_service(&self, remote: IpAddr) -> RequestService {
        RequestService::new(self.ctx.clone(), remote)
    }

    /// Bind this service to the given address and start serving responses.
    ///
    /// This will consume the service, using it to start a server that will execute the given module
    /// each time a new request is sent. This function will only return if an error occurs.
    // FIXME KTM 2020-06-22: Once `!` is stabilized, this should be `Result<!, hyper::Error>`.
    pub async fn serve(self, addr: SocketAddr) -> Result<(), Error> {
        // load ACME env vars
        let contact = env::var("ACME_CONTACT").unwrap_or("".to_string());
        let dir_url = env::var("ACME_DIRECTORY_URL").unwrap();
        let domain = env::var("DOMAIN").unwrap();
        let eab_kid = env::var("ACME_KID").unwrap();
        let key_str = env::var("ACME_HMAC_KEY").unwrap().to_string();

        // load EAB HMAC key
        let key_bytes = base64_url::decode(&key_str).unwrap();
        let eab_key = PKey::hmac(&key_bytes).unwrap();

        // Create a new ACMEv2 directory.
        let dir = DirectoryBuilder::new(dir_url).build().await?;

        // Create an ACME account to use for the certificate order.
        let account = AccountBuilder::new(dir.clone())
            .contact(vec![contact])
            .terms_of_service_agreed(true)
            .external_account_binding(eab_kid, eab_key)
            .build()
            .await?;

        // Create a new order for a specific domain name.
        let order = OrderBuilder::new(account)
            .add_dns_identifier(domain.to_string())
            .build()
            .await?;

        // Poll the order every 1 second until it is ready, up to 30 seconds.
        let order = order.wait_ready(Duration::from_secs(1), 30).await?;

        // Generate an ECDSA private key for the certificate.
        let key = gen_ec_p256_private_key()?;

        // Create a CSR for the order, and request the certificate.
        let order = order.finalize(Csr::Automatic(key.clone())).await?;

        // Poll the order every 1 second until it's valid, up to 30 seconds.
        let order = order.wait_done(Duration::from_secs(1), 30).await?;

        // Download the certificate.
        let x509 = order.certificate().await?.unwrap();

        // Build rustls certificates.
        let certs = x509
            .iter()
            .map(|x| Certificate(x.to_der().unwrap()))
            .collect::<Vec<_>>();

        // Convert openssl key to rustls key.
        let priv_key = PrivateKey(key.private_key_to_pkcs8().unwrap());

        // Create a TCP listener via tokio.
        let incoming = AddrIncoming::bind(&addr)?;

        // Build TLS configuration.
        let mut tls_cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .unwrap();
        tls_cfg.alpn_protocols = vec!["h2".into(), "http/1.1".into()];

        // Build TLS acceptor from vendored hyper-rustls example.
        let tls_acceptor = TlsAcceptor::new(sync::Arc::new(tls_cfg), incoming);

        // Create Hyper server.
        let server = hyper::Server::builder(tls_acceptor).serve(self);
        event!(
            Level::INFO,
            "Listening on https://{}:{}",
            domain,
            addr.port()
        );
        server.await?;
        Ok(())
    }
}

impl<'addr> Service<&'addr AddrStream> for ViceroyService {
    type Response = RequestService;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, addr: &'addr AddrStream) -> Self::Future {
        future::ok(self.make_service(addr.remote_addr().ip()))
    }
}

impl<'tls> Service<&'tls TlsStream> for ViceroyService {
    type Response = RequestService;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _tls: &'tls TlsStream) -> Self::Future {
        let addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
        future::ok(self.make_service(addr.into()))
    }
}

/// A request service is responsible for handling a single request.
///
/// Most importantly, this structure implements the [`tower::Service`][service] trait, which allows
/// it to be dispatched by [`ViceroyService`][viceroy] to handle a single request.
///
/// This object does not need to be used directly; users most likely should use
/// [`ViceroyService::serve`][serve] to bind a service to a port, or
/// [`ExecuteCtx::handle_request`][handle_request] to generate a response for a request when writing
/// test cases.
///
/// [handle_request]: ../execute/struct.ExecuteCtx.html#method.handle_request
/// [serve]: struct.ViceroyService.html#method.serve
/// [service]: https://docs.rs/tower/latest/tower/trait.Service.html
/// [viceroy]: struct.ViceroyService.html
#[derive(Clone)]
pub struct RequestService {
    ctx: ExecuteCtx,
    remote_addr: IpAddr,
}

impl RequestService {
    /// Create a new request service.
    fn new(ctx: ExecuteCtx, remote_addr: IpAddr) -> Self {
        Self { ctx, remote_addr }
    }
}

impl Service<Request<hyper::Body>> for RequestService {
    type Response = Response<Body>;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Process the request and return the response asynchronously.
    fn call(&mut self, req: Request<hyper::Body>) -> Self::Future {
        // Request handling currently takes ownership of the context, which is cheaply cloneable.
        let ctx = self.ctx.clone();
        let remote = self.remote_addr;

        // Now, use the execution context to handle the request.
        Box::pin(async move { ctx.handle_request(req, remote).await.map(|result| result.0) })
    }
}
