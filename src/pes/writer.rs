use crate::pes::{Header, HeaderExtension, HeaderExtension2, Packet, TrickMode};
use crate::utils::format_timestamp;

use std::io::{self, Cursor, Write};

pub fn packet_len(packet: &Packet) -> u16 {
    6 + pes_packet_len(packet)
}

pub fn pes_packet_len(packet: &Packet) -> u16 {
    let mut len = 0u16;

    if let Some(header) = &packet.header {
        len += header_len(header) as u16;
    }

    len
}

pub fn write_packet(packet: &Packet, payload: &[u8], buf: &mut [u8]) -> usize {
    do_write_packet(packet, payload, buf).unwrap()
}

pub fn do_write_packet(packet: &Packet, payload: &[u8], buf: &mut [u8]) -> io::Result<usize> {
    let mut buff = Cursor::new(buf);

    let stream_id: u8 = packet.stream_id.into();
    let data = 1u32 << 8 | stream_id as u32;
    buff.write(&data.to_be_bytes())?;

    buff.write(&packet.length.to_be_bytes())?;

    if packet.stream_id.has_header() != packet.header.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid stream_id/header",
        ));
    }

    if let Some(header) = &packet.header {
        let pos = buff.position();
        let written = write_header(header, &mut buff.get_mut()[pos as usize..])?;
        buff.set_position(pos + written as u64);
    }

    buff.write(&payload)?;

    Ok(buff.position() as usize)
}

pub fn header_len(header: &Header) -> u8 {
    3 + header_data_len(header)
}

fn header_data_len(header: &Header) -> u8 {
    let mut len = 0u8;

    if header.pts.is_some() {
        len += 5;
    }

    if header.dts.is_some() {
        len += 5;
    }

    if header.escr.is_some() {
        len += 6;
    }

    if header.es_rate.is_some() {
        len += 3;
    }

    if header.trick_mode.is_some() {
        len += 1;
    }

    if header.additional_copy_info.is_some() {
        len += 1;
    }

    if header.previous_packet_crc.is_some() {
        len += 2;
    }

    if let Some(ext) = &header.extension {
        len += header_ext_len(ext);
    }

    len += header.stuffing_len;

    len
}

pub fn write_header(header: &Header, buf: &mut [u8]) -> io::Result<usize> {
    let mut buff = Cursor::new(buf);

    let data = 1 << 7
        | ((header.scrambling_control & 0x3) as u8) << 4
        | (header.priority as u8) << 3
        | (header.data_alignment_indicator as u8) << 2
        | (header.copyright as u8) << 1
        | header.original_or_copy as u8;
    buff.write(&[data])?;

    let data = (header.pts.is_some() as u8) << 7
        | (header.dts.is_some() as u8) << 6
        | (header.escr.is_some() as u8) << 5
        | (header.es_rate.is_some() as u8) << 4
        | (header.trick_mode.is_some() as u8) << 3
        | (header.additional_copy_info.is_some() as u8) << 2
        | (header.previous_packet_crc.is_some() as u8) << 1
        | header.extension.is_some() as u8;

    buff.write(&[data])?;

    buff.write(&[header_data_len(header) as u8])?;

    match (&header.pts, &header.dts) {
        (Some(pts), None) => {
            let data = 2 << 36 | format_timestamp(*pts);
            buff.write(&data.to_be_bytes()[3..])?;
        }
        (Some(pts), Some(dts)) => {
            let data = 3 << 36 | format_timestamp(*pts);
            buff.write(&data.to_be_bytes()[3..])?;
            let data = 1 << 36 | format_timestamp(*dts);
            buff.write(&data.to_be_bytes()[3..])?;
        }
        (None, None) => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pts/dts",
            ))
        }
    }

    if let Some(escr) = &header.escr {
        let data = 3 << 46
            | format_timestamp(escr.base) << 10
            | ((escr.extension & 0x1FF) as u64) << 1
            | 1;
        buff.write(&data.to_be_bytes()[2..])?;
    }

    if let Some(es_rate) = &header.es_rate {
        let data = 1u32 << 23 | (es_rate & 0x3FFFFF) << 1 | 1;
        buff.write(&data.to_be_bytes()[1..])?;
    }

    if let Some(tm) = &header.trick_mode {
        use TrickMode::*;

        let data: u8 = match tm {
            FastForward(id, refresh, truncation) => {
                (id & 0x3) << 3 | (*refresh as u8) << 2 | truncation & 0x3
            }
            SlowMotion(control) => 1 << 5 | control & 0x1F,
            FreezeFrame(id) => 2 << 5 | (id & 0x3) << 3 | 7,
            FastReverse(id, refresh, truncation) => {
                3 << 5 | (id & 0x3) << 3 | (*refresh as u8) << 2 | truncation & 0x3
            }
            SlowReverse(control) => 4 << 5 | control & 0x1F,
            Reserved(data) => *data,
        };

        buff.write(&[data])?;
    }

    if let Some(ci) = &header.additional_copy_info {
        let data = 1 << 7 | ci & 0x7F;
        buff.write(&[data])?;
    }

    if let Some(crc) = &header.previous_packet_crc {
        buff.write(&crc.to_be_bytes())?;
    }

    if let Some(ext) = &header.extension {
        let pos = buff.position();
        let written = write_header_ext(ext, &mut buff.get_mut()[pos as usize..])?;
        buff.set_position(pos + written as u64);
    }

    for _ in 0..header.stuffing_len {
        buff.write(&[0xFF])?;
    }

    Ok(buff.position() as usize)
}

pub fn header_ext_len(ext: &HeaderExtension) -> u8 {
    let mut len = 1u8;

    if ext.private_data.is_some() {
        len += 16;
    }

    if let Some(pack_header) = &ext.pack_header {
        len += 1 + pack_header.len() as u8;
    }

    if ext.program_packet_sequence_counter.is_some() {
        len += 2;
    }

    if ext.p_std_buffer.is_some() {
        len += 2;
    }

    if let Some(ext) = &ext.extension_2 {
        len += header_ext2_len(ext);
    }

    len
}

pub fn write_header_ext(ext: &HeaderExtension, buf: &mut [u8]) -> io::Result<usize> {
    let mut buff = Cursor::new(buf);

    let data = (ext.private_data.is_some() as u8) << 7
        | (ext.pack_header.is_some() as u8) << 6
        | (ext.program_packet_sequence_counter.is_some() as u8) << 5
        | (ext.p_std_buffer.is_some() as u8) << 4
        | 7 << 1
        | ext.extension_2.is_some() as u8;
    buff.write(&[data])?;

    if let Some(data) = &ext.private_data {
        if data.len() < 16 {
            let mut d = data.clone();
            d.resize(16, 0xFE);
            buff.write(&d)?;
        } else {
            buff.write(&data)?;
        }
    }

    if let Some(data) = &ext.pack_header {
        buff.write(&[data.len() as u8])?;
        buff.write(data)?;
    }

    if let Some(p) = &ext.program_packet_sequence_counter {
        let data = 1 << 7 | p.counter;
        buff.write(&[data])?;
        let data = 1 << 7 | (p.mpeg1_mpeg2_identifier as u8) << 6 | p.original_stuff_length;
        buff.write(&[data])?;
    }

    if let Some(b) = &ext.p_std_buffer {
        let data: u16 = 1u16 << 14 | (b.scale as u16) << 13 | b.size as u16;
        buff.write(&data.to_be_bytes())?;
    }

    if let Some(ext) = &ext.extension_2 {
        let pos = buff.position();
        let written = write_header_ext2(ext, &mut buff.get_mut()[pos as usize..])?;
        buff.set_position(pos + written as u64);
    }

    Ok(buff.position() as usize)
}

pub fn header_ext2_len(ext: &HeaderExtension2) -> u8 {
    use HeaderExtension2::*;

    // FIXME: this is the buffer length, not PES_extension_field_length
    let mut len = 2u8;

    len += match ext {
        StreamIdExtension(_) => 0,
        TREF(_) => 5,
    };

    len
}

pub fn write_header_ext2(ext: &HeaderExtension2, buf: &mut [u8]) -> io::Result<usize> {
    use HeaderExtension2::*;

    let mut buff = Cursor::new(buf);

    // FIXME: PES_extension_field_length is buffer_length - 1
    let data = 1 << 7 | header_ext2_len(ext) - 1;
    buff.write(&[data])?;

    match ext {
        StreamIdExtension(id) => {
            buff.write(&[*id])?;
        }
        TREF(tref) => {
            let data = 0xFF << 1;
            buff.write(&[data])?;
            let data = 0xF << 36 | format_timestamp(*tref);
            buff.write(&data.to_be_bytes()[3..])?;
        }
    }

    Ok(buff.position() as usize)
}