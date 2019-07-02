use nuts::{ts, pes};
use std::fs::File;
use std::process::exit;

fn main() {
    let filename = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("missing filename");
        exit(1);
    });
    let file = File::open(filename).unwrap_or_else(|e| {
        eprintln!("can't open file: {}", e);
        exit(1);
    });
    let mut parser = ts::ReaderParser::new(file);
    let mut n = 0;
    loop {
        match parser.parse() {
            Ok(Some((input, (packet, data)))) => {
                print_packet(n, input, &packet, &data);
                n += 1;
            },
            Ok(None) => break,
            Err(e) => if parser.recover(e).is_err() { break }
        }
    }
}

fn print_packet(number: u32, input: &[u8], packet: &ts::Packet, data: &ts::Data) {
    use ts::AdaptationFieldControl::*;
    use ts::Data::*;

    let packet_number = commafy(number);

    let header_size = ts::writer::header_len(packet);

    let payload_len = match data {
        PSI(_) => 184,
        PES(pes_packet, payload) => {
            6 + pes_packet
                .header
                .as_ref()
                .map_or(0, |h| pes::writer::header_len(h) as usize)
                + payload.len()
        }
        Data(payload) => payload.len(),
    };

    let (af_len, payload_len) = match &packet.adaptation_field_control {
        AdaptationField(af) => {
            (Some(af.as_ref().map_or(0, |af| ts::writer::adaptation_field_len(af) as usize)),
            None)
        },
        AdaptationFieldAndPayload(af) => {
            (Some(af.as_ref().map_or(0, |af| ts::writer::adaptation_field_len(af) as usize)),
            Some(payload_len))
        },
        _ => (None, Some(payload_len))
    };

    println!(
        "
* Packet {number}
  ---- TS Header ----
  PID: {pid} (0x{pid:04X}), header size: {header_size}, sync: 0x47
  Error: 0, unit start: {pusi}, priority: {priority}
  Scrambling: {scrambling}, continuity counter: {continuity_counter}
  Adaptation field: {af_yn} ({af_len} bytes), payload: {payload_yn} ({payload_len} bytes)",
        number = packet_number,
        pid = packet.pid,
        header_size = header_size,
        pusi = packet.payload_unit_start_indicator as u8,
        priority = packet.transport_priority as u8,
        scrambling = packet.transport_scrambling_control,
        continuity_counter = packet.continuity_counter,
        af_yn = af_len.map_or("no", |_| "yes"),
        af_len = af_len.unwrap_or(0),
        payload_yn=payload_len.map_or("no", |_| "yes"),
        payload_len=payload_len.unwrap_or(0)
    );

    match &packet.adaptation_field_control {
        AdaptationField(af)
        | AdaptationFieldAndPayload(af) => {
            if let Some(af) = af {
                println!("  Discontinuity: {}, random access: {}, ES priority: {}",
                        af.discontinuity_indicator as u8,
                        af.random_access_indicator as u8,
                        af.elementary_stream_priority_indicator as u8
                );
                if let Some(pcr) = &af.program_clock_reference {
                    let pcr = pcr.base * 300 + pcr.extension as u64;
                    println!("  PCR: 0x{:011X}", pcr);
                }
            }
        }
        _ => ()

    };

    if let ts::Data::PES(pes_packet, _) = data {
        use pes::StreamId::*;

        let stream_id: u8 = pes_packet.stream_id.into();
        let stream_id_desc = match pes_packet.stream_id {
            PrivateStream1 => "Private stream 1".to_string(),
            VideoStream(n) => format!("Video {}", n),
            AudioStream(n) => format!("Audio {}", n),
            _ => "Other".into()
        };

        let pes_packet_len_desc = if pes_packet.length > 0 {
            pes_packet.length.to_string()
        } else {
            format!("0 (unbounded)")
        };

        println!("---- PES Header ----
  Stream id: 0x{stream_id:X} ({stream_id_desc})
  PES packet length: {pes_packet_len_desc}",
            stream_id=stream_id,
            stream_id_desc=stream_id_desc,
            pes_packet_len_desc=pes_packet_len_desc
        );
    }

    println!("  ---- Full TS Packet Content ----");
    for chunk in input[0..188].chunks(24) {
        print!("  ");
        for byte in chunk.iter() {
            print!("{:02X} ", byte);
        }
        println!();
    }

    fn commafy(number: u32) -> String {
        let mut a = number;
        let mut res = String::new();
        while a >= 1000 {
            let div = a / 1000;
            let rem = a % 1000;
            res += &format!(",{:03}", rem);
            a = div;
        }
        a.to_string() + &res
    }
}