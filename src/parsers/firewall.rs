use usiem::events::firewall::{FirewallEvent, FirewallOutcome};
use usiem::events::field::{SiemIp, SiemField};
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{SiemEvent, SiemLog};
use usiem::utilities::ip_utils::{ipv4_from_str, ipv6_from_str};
use chrono::prelude::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};
use std::borrow::Cow;

pub fn parse_log(log: SiemLog) -> Result<SiemLog, SiemLog> {
    let log_line = log.message();
    let filterlog_pos = match log_line.find("filterlog") {
        Some(val) => val,
        None => return Err(log),
    };
    let log_start_pos = match log_line[filterlog_pos..].find(": ") {
        Some(val) => val,
        None => return Err(log),
    };

    let syslog_header = &log_line[0..(filterlog_pos + log_start_pos + 1)];
    let log_content = &log_line[(filterlog_pos + log_start_pos + 2)..];

    let mut log_csv = Vec::new();
    let mut last_pos = 0;
    for (pos, c) in log_content.char_indices() {
        if c == ',' {
            log_csv.push(&log_content[last_pos..pos]);
            last_pos = pos + 1;
        }
    }

    log_csv.push(&log_content[last_pos..]);

    let mut syslog_content = Vec::new();
    let syslog_start = match syslog_header.find(">") {
        Some(val) => val,
        None => return Err(log),
    };
    syslog_content.push(&syslog_header[1..syslog_start]);
    let mut last_pos = 0;
    for (pos, c) in syslog_header[syslog_start + 1..].char_indices() {
        if c == ' ' {
            syslog_content.push(&syslog_header[last_pos..pos]);
            last_pos = pos + 1;
        }
    }

    let month = match syslog_content.get(1) {
        Some(val) => val,
        None => return Err(log),
    };
    let day_month = match syslog_content.get(2) {
        Some(val) => val,
        None => return Err(log),
    };
    let hour_day = match syslog_content.get(3) {
        Some(val) => val,
        None => return Err(log),
    };
    let naive = NaiveDateTime::from_timestamp(log.event_received() / 1000, 0);

    // Create a normal DateTime from the NaiveDateTime
    let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
    let event_created = &format!("{} {} {} {}", month, day_month, hour_day, datetime.year())[..];
    let event_created = match Utc.datetime_from_str(event_created, "%b %e %T %Y") {
        Ok(timestamp) => timestamp.timestamp_millis(),
        Err(_err) => 0,
    };

    let interface = match log_csv.get(4) {
        Some(val) => val,
        None => return Err(log),
    };
    let observer_name = match syslog_content.get(4) {
        Some(val) => val,
        None => return Err(log),
    };
    
    let ip_version = match log_csv.get(8) {
        Some(val) => val,
        None => return Err(log),
    };
    let (s_ip,d_ip) = if *ip_version == "4" {
        let sip = match log_csv.get(18){
            Some(val) => val,
            None => return Err(log)
        };
        let dip = match log_csv.get(19){
            Some(val) => val,
            None => return Err(log)
        };
        let sip = match ipv4_from_str(sip){
            Ok(val) => SiemIp::V4(val),
            Err(_e) => return Err(log)
        };
        let dip = match ipv4_from_str(dip){
            Ok(val) => SiemIp::V4(val),
            Err(_e) => return Err(log)
        };
        (sip, dip)
    } else if *ip_version == "6" {
        let sip = match log_csv.get(15){
            Some(val) => val,
            None => return Err(log)
        };
        let dip = match log_csv.get(16){
            Some(val) => val,
            None => return Err(log)
        };
        let sip = match ipv6_from_str(sip){
            Ok(val) => SiemIp::V6(val),
            Err(_e) => return Err(log)
        };
        let dip = match ipv6_from_str(dip){
            Ok(val) => SiemIp::V6(val),
            Err(_e) => return Err(log)
        };
        (sip, dip)
    } else {
        return Err(log);
    };
    let (sport,dport, protocol) = if *ip_version == "4" {
        let sport = match log_csv.get(20){
            Some(val) => match val.parse::<u16>(){
                Ok(val) => val,
                Err(_) => 0
            },
            None => 0
        };
        let dport = match log_csv.get(21){
            Some(val) => match val.parse::<u16>(){
                Ok(val) => val,
                Err(_) => 0
            },
            None => 0
        };
        let protocol = match log_csv.get(16) {
            Some(val) => parse_protocol(val),
            None => return Err(log)
        };
        (sport,dport,protocol)
    }else{
        let sport = match log_csv.get(17){
            Some(val) => match val.parse::<u16>(){
                Ok(val) => val,
                Err(_) => 0
            },
            None => 0
        };
        let dport = match log_csv.get(18){
            Some(val) => match val.parse::<u16>(){
                Ok(val) => val,
                Err(_) => 0
            },
            None => 0
        };
        let protocol = match log_csv.get(12) {
            Some(val) => parse_protocol(val),
            None => return Err(log)
        };
        (sport,dport,protocol)
    };
    
    let outcome = match log_csv.get(6) {
        Some(val) => outcome_to_enum(val),
        None => return Err(log)
    };
    
    //Removing Syslog header
    let mut log = SiemLog::new(log_content.to_string(), log.event_received(), log.origin().clone());
    log.set_event(SiemEvent::Firewall(FirewallEvent {
        source_ip: s_ip,
        destination_ip: d_ip,
        source_port: sport,
        destination_port: dport,
        outcome: outcome,
        network_protocol: protocol,
        //TODO: in/out bytes
        in_bytes: 0,
        out_bytes: 0,
        in_interface: Cow::Owned((*interface).to_owned()),
        out_interface: Cow::Borrowed("")
    }));
    log.set_event_created(event_created);
    log.set_vendor(Cow::Borrowed("OPNSense"));
    log.set_product(Cow::Borrowed("OPNSense"));
    log.set_service(Cow::Borrowed("filterlog"));
    log.set_category(Cow::Borrowed("Firewall"));
    log.add_field("observer.name", SiemField::Text(Cow::Owned(observer_name.to_string())));
    match ipv4_from_str(observer_name) {
        Ok(ip) => {
            log.add_field("observer.ip", SiemField::IP(SiemIp::V4(ip)));
        },
        _ => {}
    };
    return Ok(log);
}

pub fn outcome_to_enum(outcome: &str) -> FirewallOutcome {
    match outcome {
        "pass" => FirewallOutcome::ALLOW,
        "block" => FirewallOutcome::BLOCK,
        _ => FirewallOutcome::UNKNOWN,
    }
}
pub fn parse_protocol(protocol: &str) -> NetworkProtocol {
    match protocol {
        "tcp" => NetworkProtocol::TCP,
        "udp" => NetworkProtocol::UDP,
        _ => NetworkProtocol::OTHER(Cow::Owned(protocol.to_uppercase())),
    }
}

pub fn timestamp_to_i64(timestamp: &str) -> i64 {
    //2020-08-17T20:25:37.563778Z
    let dt = timestamp.parse::<DateTime<Utc>>().unwrap();
    return dt.timestamp_millis();
}

#[cfg(test)]
mod filterlog_tests {
    use usiem::events::field::SiemIp;
    use usiem::events::{SiemLog,SiemEvent};
    use usiem::events::firewall::FirewallOutcome;
    use usiem::utilities::ip_utils::{ipv4_from_str, port_to_u16};
    use super::{parse_log, parse_protocol};

    #[test]
    fn parse_logs() {
        let log = "<134>Aug 23 20:30:25 OPNsense.localdomain filterlog[21853]: 82,,,0,igb0,match,pass,out,4,0x0,,62,25678,0,DF,17,udp,60,192.168.1.8,8.8.8.8,5074,53,40";
        let log_event = SiemLog::new(log.to_owned(), 1000000 as i64, SiemIp::V4(0));
        let logline = parse_log(log_event).unwrap();
        match logline.event() {
            SiemEvent::Firewall(event) => {
                assert_eq!(
                    event.source_ip,
                    SiemIp::V4(ipv4_from_str("192.168.1.8").unwrap())
                );
                assert_eq!(
                    event.destination_ip,
                    SiemIp::V4(ipv4_from_str("8.8.8.8").unwrap())
                );
                assert_eq!(
                    event.source_port,
                    port_to_u16("5074").expect("Cannot parse")
                );
                assert_eq!(
                    event.destination_port,
                    port_to_u16("53").expect("Cannot parse")
                );
                assert_eq!(event.network_protocol, parse_protocol("udp"));
                assert_eq!(event.outcome, FirewallOutcome::ALLOW);
            },
            _ => {}
        }
    }

}
