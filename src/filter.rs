//! Turns a raw DNS packet into a decision: forward it untouched, answer it
//! ourselves, or drop it.
//!
//! IMPORTANT design rule: we only *parse* packets to read the question. Anything
//! we forward is forwarded as the original bytes, so EDNS options, the DO bit,
//! DNSSEC records, the AD flag, etc. all pass through to/from unbound exactly
//! as the client and unbound intended. Only blocked queries get a response we
//! build ourselves.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};

use crate::{config::BlockMode, rules::Rules};

pub enum Decision {
    /// Not blocked: send the original packet upstream.
    Forward,
    /// Answer the client with these bytes; don't bother upstream.
    Reply(Vec<u8>),
    /// Ignore the packet (e.g. it is itself a response).
    Drop,
}

pub struct Filter {
    rules: Arc<ArcSwap<Rules>>,
    mode: BlockMode,
    ttl: u32,
}

impl Filter {
    pub fn new(rules: Arc<ArcSwap<Rules>>, mode: BlockMode, ttl: u32) -> Self {
        Self { rules, mode, ttl }
    }

    pub fn decide(&self, packet: &[u8]) -> Decision {
        let req = match Message::from_vec(packet) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("unparseable packet: {e}");
                return error_reply(packet, ResponseCode::FormErr).map_or(Decision::Drop, Decision::Reply);
            }
        };
        // Never answer a response: that is how reflection loops start.
        if req.metadata.message_type != MessageType::Query {
            return Decision::Drop;
        }
        // Anything unusual (NOTIFY, multiple questions...) is unbound's problem.
        if req.metadata.op_code != OpCode::Query || req.queries.len() != 1 {
            return Decision::Forward;
        }

        let name = qname(&req.queries[0]);
        // `load()` is a lock-free read; a list reload swaps the Arc atomically.
        if !self.rules.load().is_blocked(&name) {
            return Decision::Forward;
        }
        tracing::debug!(%name, "blocked");
        self.blocked_reply(&req).map_or(Decision::Drop, Decision::Reply)
    }

    fn blocked_reply(&self, req: &Message) -> Option<Vec<u8>> {
        let q = &req.queries[0];
        let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.checking_disabled = req.metadata.checking_disabled;
        // Echo the question exactly as received (keeps 0x20 case randomisation intact).
        resp.add_query(q.clone());

        match self.mode {
            BlockMode::Nxdomain => resp.metadata.response_code = ResponseCode::NXDomain,
            BlockMode::NullIp => {
                resp.metadata.response_code = ResponseCode::NoError;
                let owner = q.name().clone();
                match q.query_type() {
                    RecordType::A => {
                        resp.add_answer(Record::from_rdata(owner, self.ttl, RData::A(A(Ipv4Addr::UNSPECIFIED))));
                    }
                    RecordType::AAAA => {
                        resp.add_answer(Record::from_rdata(owner, self.ttl, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))));
                    }
                    _ => {} // NOERROR + empty answer = "no such record type"
                }
            }
        }
        // RFC 6891: if the query had an OPT record, the response must have one.
        if req.edns.is_some() {
            let mut e = Edns::new();
            e.set_max_payload(1232);
            resp.set_edns(e);
        }
        resp.to_vec().ok()
    }
}

/// Lowercase qname without the trailing dot, which is the form `Rules` expects.
fn qname(q: &hickory_proto::op::Query) -> String {
    let mut s = q.name().to_ascii();
    s.make_ascii_lowercase();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Build a bare error response (FORMERR / SERVFAIL) for a packet, echoing the
/// ID and, if it parses, the question. Returns None if it's too short to be DNS.
pub fn error_reply(packet: &[u8], rcode: ResponseCode) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let mut resp = Message::error_msg(id, OpCode::Query, rcode);
    resp.metadata.recursion_available = true;
    if let Ok(req) = Message::from_vec(packet) {
        resp.metadata.op_code = req.metadata.op_code;
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        for q in req.queries {
            resp.add_query(q);
        }
    }
    resp.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_into;
    use hickory_proto::{op::Query, rr::Name};
    use std::{collections::HashSet, str::FromStr};

    fn filter(mode: BlockMode) -> Filter {
        let mut block = HashSet::new();
        parse_into("ads.example.com\n", &mut block);
        let rules = Rules::new(HashSet::new(), block);
        Filter::new(Arc::new(ArcSwap::from_pointee(rules)), mode, 60)
    }

    fn query(name: &str, ty: RecordType, edns: bool) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), ty));
        if edns {
            let mut e = Edns::new();
            e.set_dnssec_ok(true);
            m.set_edns(e);
        }
        m.to_vec().unwrap()
    }

    #[test]
    fn nxdomain_mode() {
        let f = filter(BlockMode::Nxdomain);
        let pkt = query("Tracker.ADS.example.com.", RecordType::A, true);
        let Decision::Reply(bytes) = f.decide(&pkt) else { panic!("expected reply") };
        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(resp.metadata.id, Message::from_vec(&pkt).unwrap().metadata.id);
        assert!(resp.edns.is_some());
        assert_eq!(resp.queries.len(), 1);
    }

    #[test]
    fn null_ip_mode() {
        let f = filter(BlockMode::NullIp);
        let Decision::Reply(b) = f.decide(&query("ads.example.com.", RecordType::A, false)) else { panic!() };
        let r = Message::from_vec(&b).unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
        let Decision::Reply(b) = f.decide(&query("ads.example.com.", RecordType::HTTPS, false)) else { panic!() };
        let r = Message::from_vec(&b).unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[test]
    fn unblocked_is_forwarded_and_garbage_is_not() {
        let f = filter(BlockMode::Nxdomain);
        assert!(matches!(f.decide(&query("example.com.", RecordType::A, true)), Decision::Forward));
        // A response must never be answered.
        let mut resp = Message::response(1, OpCode::Query);
        resp.add_query(Query::query(Name::from_str("ads.example.com.").unwrap(), RecordType::A));
        assert!(matches!(f.decide(&resp.to_vec().unwrap()), Decision::Drop));
        assert!(matches!(f.decide(&[1, 2, 3]), Decision::Drop));
    }
}
