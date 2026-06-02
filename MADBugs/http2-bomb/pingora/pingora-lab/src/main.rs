use async_trait::async_trait;
use http::Response;
use log::info;
use pingora::apps::http_app::{HttpServer, ServeHttp};
use pingora::apps::HttpServerOptions;
use pingora::protocols::http::v2::server::H2Options;
use pingora::protocols::http::ServerSession;
use pingora::server::Server;
use pingora::services::listening::Service;

#[derive(Clone)]
struct App;

#[async_trait]
impl ServeHttp for App {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let headers = &session.req_header().headers;
        let bomb_header_count = headers.get_all("a").iter().count();
        let header_count = headers.len();

        info!("accepted request: headers={header_count}, a_headers={bomb_header_count}");

        let body = b"ok\n".to_vec();
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("content-length", body.len().to_string())
            .body(body)
            .unwrap()
    }
}

fn parse_env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn main() {
    env_logger::init();

    let addr = std::env::var("PINGORA_LAB_ADDR").unwrap_or_else(|_| "0.0.0.0:6145".to_string());

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut app = HttpServer::new_app(App);
    let mut server_options = HttpServerOptions::default();
    server_options.h2c = true;
    app.server_options = Some(server_options);

    let mut h2_options = H2Options::new();
    let mut custom_h2 = false;

    if let Some(max_header_list_size) = parse_env_u32("PINGORA_H2_MAX_HEADER_LIST_SIZE") {
        h2_options.max_header_list_size(max_header_list_size);
        custom_h2 = true;
    }
    if let Some(max_concurrent_streams) = parse_env_u32("PINGORA_H2_MAX_CONCURRENT_STREAMS") {
        h2_options.max_concurrent_streams(max_concurrent_streams);
        custom_h2 = true;
    }
    if custom_h2 {
        app.h2_options = Some(h2_options);
    }

    let mut service = Service::new("pingora-hpack-lab".to_string(), app);
    service.add_tcp(&addr);
    server.add_service(service);
    server.run_forever();
}
