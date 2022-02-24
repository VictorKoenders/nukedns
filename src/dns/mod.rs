use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, task::JoinHandle};
use trust_dns_client::{
    client::{AsyncClient, ClientHandle},
    op::LowerQuery,
    udp::UdpClientStream,
};
use trust_dns_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use trust_dns_server::authority::MessageRequest;

pub fn spawn(config: super::Config) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::with_capacity(config.host.len());
    for addr in config.host {
        let handle = tokio::spawn(async move {
            let socket = Arc::new(
                UdpSocket::bind((addr.address, addr.port))
                    .await
                    .expect("Could not spawn DNS thread"),
            );
            log::info!("Listening on {:?}", socket.local_addr().unwrap());

            let mut buf = [0u8; 1024];

            loop {
                let (len, addr) = socket
                    .recv_from(&mut buf)
                    .await
                    .expect("Could not read from UDP socket");
                let partial_buf = (&buf[..len]).to_vec();
                let sock = socket.clone();

                tokio::spawn(async move {
                    handle_request(sock, addr, partial_buf).await;
                });
            }
        });
        handles.push(handle);
    }
    handles
}

async fn handle_request(socket: Arc<UdpSocket>, src: SocketAddr, partial_buf: Vec<u8>) {
    let mut decoder = BinDecoder::new(&partial_buf);
    let request = MessageRequest::read(&mut decoder).unwrap();

    let mut message = Message::new();
    message
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(false)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_authentic_data(false)
        .set_checking_disabled(false);

    let query = request.queries()[0].to_owned();
    let domain = query.name().to_string().trim_end_matches('.').to_string();
    log::info!(target: &domain, "Incoming request",);
    if crate::resolve::is_deny(&domain).await {
        log::info!(target: &domain, "  in deny list",);
        message
            .set_response_code(ResponseCode::NXDomain)
            .set_authoritative(true);
    } else {
        let answers = if let Some(answer) =
            crate::resolve::get_cached(domain.clone(), query.query_type()).await
        {
            log::info!(target: &domain, "  in cache");
            answer
        } else {
            log::info!(target: &domain, "  fetching from upstream");
            let server_answers = recurse(&query).await.unwrap();
            crate::resolve::add_cache(domain.clone(), query.query_type(), server_answers.clone())
                .await;
            log::info!(target: &domain, "  upstream returned");
            server_answers
        };
        log::info!(
            target: &domain,
            "  responding with {:?}",
            answers
                .iter()
                .map(|a| a.rdata().clone())
                .collect::<Vec<_>>()
        );

        message
            .add_query(request.queries()[0].original().to_owned())
            .add_answers(answers)
            .set_response_code(ResponseCode::NoError);
    }

    let mut byte_vec: Vec<u8> = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut byte_vec);
        message.emit(&mut encoder).unwrap();
    }

    socket.send_to(byte_vec.as_slice(), src).await.unwrap();
}

async fn recurse(query: &LowerQuery) -> Option<Vec<Record>> {
    let stream = UdpClientStream::<UdpSocket>::new(([8, 8, 8, 8], 53).into());
    let (mut client, dns_background) = AsyncClient::connect(stream).await.unwrap();

    tokio::spawn(dns_background);

    // Create a query future
    let name: Name = query.name().into();
    let response = client
        .query(name, DNSClass::IN, RecordType::A)
        .await
        .unwrap();

    // validate it's what we expected
    let answers = response.answers().to_owned();

    Some(answers)
}
