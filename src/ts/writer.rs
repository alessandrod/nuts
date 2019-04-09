use crate::pes;
use crate::ts::psi;
use crate::ts::{AdaptationFieldControl, Packet};
use crate::ts::adaptation_field::{AdaptationField, AdaptationFieldExtension};
use crate::utils::format_timestamp;
use std::io::{self, Cursor, Write};

pub fn len(_packet: &Packet) -> usize {
    188
}

pub fn header_len(packet: &Packet) -> usize {
    use AdaptationFieldControl::*;
    let mut len = 4;

    len += match &packet.adaptation_field_control {
        AdaptationField(af)
        | AdaptationFieldAndPayload(af) => {
            if let Some(af) = af {
                adaptation_field_len(af) as usize + 1
            } else {
                1
            }
        },
        _ => 0
    };

    len
}

pub fn write_header(packet: &Packet, buf: &mut [u8]) -> usize {
    do_write_header(packet, buf).unwrap()
}

fn do_write_header(packet: &Packet, buf: &mut [u8]) -> io::Result<usize> {
    use AdaptationFieldControl::*;

    let mut buff = Cursor::new(buf);
    buff.write(&[0x47])?;
    let mut tmp = packet.pid.to_be_bytes();
    tmp[0] |= (packet.transport_error_indicator as u8) << 7
        | (packet.payload_unit_start_indicator as u8) << 6
        | (packet.transport_priority as u8) << 5;
    buff.write(&tmp)?;
    let adaptation_field_control = match packet.adaptation_field_control {
        Reserved => 0,
        Payload => 1,
        AdaptationField(_) => 2,
        AdaptationFieldAndPayload(_) => 3,
    };
    let tmp = (packet.transport_scrambling_control as u8) << 6
        | adaptation_field_control << 4
        | packet.continuity_counter;
    buff.write(&[tmp])?;
    match &packet.adaptation_field_control {
        AdaptationField(af)
        | AdaptationFieldAndPayload(af) =>
            {
                if let Some(af) = af {
                    let pos = buff.position() as usize;
                    let af_len = write_adaptation_field(af, &mut buff.get_mut()[pos..])?;
                    buff.set_position((pos + af_len) as u64);
                } else {
                    buff.write(&[0])?;
                }
            },
        _ => ()
    }

    let written = buff.position() as usize;

    Ok(written)
}

pub fn write_packet(packet: &Packet, payload: &[u8], mut buf: &mut [u8]) -> usize {
    let header_len = write_header(&packet, buf);
    buf = &mut buf[header_len..];
    let payload_len = buf.write(payload).unwrap();

    header_len + payload_len
}

pub fn write_psi(packet: &Packet, section: &psi::Section, buf: &mut [u8]) -> usize {
    let written = write_psi_no_stuffing(packet, section, buf);
    let packet_len = len(packet);
    for i in 0..packet_len - written {
        buf[written + i] = 0xFF;
    }

    packet_len
}

pub fn write_psi_no_stuffing(packet: &Packet, section: &psi::Section, buf: &mut [u8]) -> usize {
    let mut header_len = write_header(&packet, buf);
    let mut payload = &mut buf[header_len..];
    if packet.payload_unit_start_indicator {
        // pointer field
        payload[0] = 0;
        payload = &mut payload[1..];
        header_len += 1;
    }
    let section_len = psi::writer::write_section(section, payload);

    header_len + section_len
}

pub fn write_pes_packet(
    packet: &Packet,
    pes_packet: &pes::Packet,
    payload: &[u8],
    mut buf: &mut [u8],
) -> usize {
    let header_len = write_header(&packet, buf);
    buf = &mut buf[header_len..];
    let payload_len = pes::writer::write_packet(pes_packet, payload, buf);

    header_len + payload_len
}

pub fn adaptation_field_len(af: &AdaptationField) -> u8 {
    let mut len = 1;

    if af.program_clock_reference.is_some() {
        len += 6;
    }

    if af.original_program_clock_reference.is_some() {
        len += 6;
    }

    if af.splice_countdown.is_some() {
        len += 1;
    }

    if let Some(data) = &af.transport_private_data {
        if data.len() > 0 {
            len += data.len() as u8 + 1;
        }
    }

    if let Some(ext) = &af.extension {
        len += adaptation_field_ext_len(ext) + 1;
    }

    len += af.stuffing_length;

    len
}

pub fn write_adaptation_field(af: &AdaptationField, buf: &mut [u8]) -> io::Result<usize> {
    let mut buff = Cursor::new(buf);

    let length = adaptation_field_len(af);
    buff.write(&[length])?;

    buff.write(&[(af.discontinuity_indicator as u8) << 7
        | (af.random_access_indicator as u8) << 6
        | (af.elementary_stream_priority_indicator as u8) << 5
        | (af.program_clock_reference.is_some() as u8) << 4
        | (af.original_program_clock_reference.is_some() as u8) << 3
        | (af.splice_countdown.is_some() as u8) << 2
        | (af.transport_private_data.is_some() as u8) << 1
        | af.extension.is_some() as u8])?;

    if let Some(pcr) = &af.program_clock_reference {
        let tmp: u64 = pcr.base << 15
        | 0x3F << 9
        | (pcr.extension & 0x1FF) as u64;
        buff.write(&tmp.to_be_bytes()[2..8])?;
    }

    if let Some(pcr) = &af.original_program_clock_reference {
        let tmp: u64 = pcr.base << 15
        | 0x3F << 9
        | (pcr.extension & 0x1FF) as u64;
        buff.write(&tmp.to_be_bytes()[2..8])?;
    }

    if let Some(countdown) = af.splice_countdown {
        buff.write(&[countdown])?;
    }

    if let Some(data) = &af.transport_private_data {
        buff.write(&[data.len() as u8])?;
        buff.write(data)?;
    }

    if let Some(ext) = &af.extension {
        buff.write(&[adaptation_field_ext_len(ext)])?;
        let tmp = (ext.ltw.is_some() as u8) << 7
            | (ext.piecewise_rate.is_some() as u8) << 6
            | (ext.seamless_splice.is_some() as u8) << 5
            | 0x1F;
        buff.write(&[tmp])?;
        if let Some(ltw) = &ext.ltw {
            let tmp = (ltw.valid as u16) << 15 | ltw.offset & 0x7FFF;
            buff.write(&tmp.to_be_bytes())?;
        }

        if let Some(rate) = ext.piecewise_rate {
            buff.write(&(3 << 22 | rate).to_be_bytes()[1..])?;
        }
        if let Some(splice) = &ext.seamless_splice {
            let tmp = (splice.splice_type as u64) << 36
                | format_timestamp(splice.dts_next_au);
            buff.write(&tmp.to_be_bytes()[3..])?;
        }
        if let Some(data) = &ext.data {
            buff.write(data)?;
        }
    }

    for _ in 0..af.stuffing_length {
        buff.write(&[0xFF])?;
    }

    Ok(buff.position() as usize)
}



fn adaptation_field_ext_len(ext: &AdaptationFieldExtension) -> u8 {
    let mut len = 1;

    if ext.ltw.is_some() {
        len += 2;
    }

    if ext.piecewise_rate.is_some() {
        len += 3;
    }

    if ext.seamless_splice.is_some() {
        len += 5;
    }

    if let Some(data) = &ext.data {
        len += data.len() as u8;
    }

    len
}