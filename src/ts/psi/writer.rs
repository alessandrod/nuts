use crate::crc;
use crate::ts::psi::{Section, PATSection, PMTSection};
use std::io::{self, Cursor, Write};

pub fn write_section<'a>(section: &Section, buf: &'a mut [u8]) -> usize {
    use Section::*;

    let mut buf = Cursor::new(buf);

    match section {
        PAT(pat) => write_pat(pat, &mut buf).unwrap(),
        PMT(pmt) => write_pmt(pmt, &mut buf).unwrap(),
        Unsupported(_, data) => { buf.write(&data).unwrap(); }
    }

    buf.position() as usize
}

fn write_pat(section: &PATSection, buf: &mut Cursor<&mut [u8]>) -> io::Result<()> {
    buf.write(&[0x00])?;

    let mut tmp = pat_section_len(section).to_be_bytes();
    tmp[0] |= (section.section_syntax_indicator as u8) << 7 | 0 << 6 | 3 << 4;
    buf.write(&tmp)?;

    buf.write(&section.transport_stream_id.to_be_bytes())?;
    let tmp = 3 << 6 | (section.version_number & 0x1F) << 1 | section.current_next_indicator as u8;
    buf.write(&[tmp])?;

    buf.write(&[section.section_number])?;
    buf.write(&[section.last_section_number])?;

    for (program, pid) in section.pmt_pids.iter() {
        buf.write(&program.to_be_bytes())?;
        let data = 7 << 13 | pid & 0x1FFF;
        buf.write(&data.to_be_bytes())?;
    }

    let pat_crc = {
        let data = &buf.get_ref()[0..buf.position() as usize];
        crc::sum32(data)
    };
    buf.write(&pat_crc.to_be_bytes())?;

    Ok(())
}

fn write_pmt(section: &PMTSection, buf: &mut Cursor<&mut [u8]>) -> io::Result<()> {
    buf.write(&[0x02])?;

    let tmp = (section.section_syntax_indicator as u16) << 15
        | 3 << 12
        | (pmt_section_len(section) & 0xFFF);
    buf.write(&tmp.to_be_bytes())?;
    buf.write(&section.program_number.to_be_bytes())?;
    let tmp = 3 << 6
        | (section.version_number & 0x1F) << 1
        | section.current_next_indicator as u8;
    buf.write(&[tmp])?;
    buf.write(&[section.section_number])?;
    buf.write(&[section.last_section_number])?;
    buf.write(&(7 << 13 | (section.pcr_pid & 0x1FFF)).to_be_bytes())?;
    buf.write(&(15 << 12 | (pmt_program_info_len(section) & 0xFFF)).to_be_bytes())?;
    buf.write(&section.descriptors)?;
    for stream in section.streams.iter() {
        buf.write(&[stream.stream_type])?;
        buf.write(&(7 << 13 | (stream.pid & 0x1FFF)).to_be_bytes())?;
        buf.write(&(15 << 12 | (stream.descriptors.len() as u16 & 0xFFF)).to_be_bytes())?;
        buf.write(&stream.descriptors)?;
    }

    let pmt_crc = {
        let data = &buf.get_ref()[0..buf.position() as usize];
        crc::sum32(data)
    };
    buf.write(&pmt_crc.to_be_bytes())?;

    Ok(())
}

pub fn pat_len(pat: &PATSection) -> u16 {
    // header up to and including the section_length field
    3 + pat_section_len(pat)
}

pub fn pat_section_len(pat: &PATSection) -> u16 {
    // fixed part including CRC32
    let mut len = 9u16;

    // (program_number, pid) for each pmt entry
    len += pat.pmt_pids.len() as u16 * 4;

    len
}

pub fn pmt_len(pmt: &PMTSection) -> u16 {
    // header up to and including the section_length field
    3 + pmt_section_len(pmt)
}

pub fn pmt_section_len(pmt: &PMTSection) -> u16 {
    // fixed part including CRC32
    let mut len = 13u16;

    len += pmt_program_info_len(pmt);

    len += pmt.streams.iter().map(|s| {
        5 + s.descriptors.len() as u16
    }).sum::<u16>();

    len
}

fn pmt_program_info_len(pmt: &PMTSection) -> u16 {
    pmt.descriptors.len() as u16
}