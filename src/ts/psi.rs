/*!
 * Program Specific Information (PSI) parser and types.
 */
#[doc(hidden)]
pub mod writer;

use std::collections::{HashSet, HashMap};

use nom::{
    be_u32, be_u8, bits, bytes, call, complete, cond, do_parse, length_bytes, many0, peek, rest,
    switch, take, value, verify, IResult,
};

use crate::ts::packet::Packet;

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
use proptest::collection;

#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Debug, PartialEq)]
pub enum Section {
    Unsupported(u8, Vec<u8>),
    PAT(PATSection),
    PMT(PMTSection),
}

#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct PATSection {
    #[cfg_attr(test, proptest(value = "0"))]
    pub table_id: u8,
    pub section_syntax_indicator: bool,
    pub transport_stream_id: u16,
    #[cfg_attr(test, proptest(strategy = "0..2u8.pow(5)"))]
    pub version_number: u8,
    pub current_next_indicator: bool,
    pub section_number: u8,
    pub last_section_number: u8,
    #[cfg_attr(test, proptest(strategy(pid_map)))]
    pub pmt_pids: HashMap<u16, u16>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PAT {
    pub transport_stream_id: u16,
    pub version_number: u8,
    pub pmt_pids: HashMap<u16, u16>,
}

#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct PMTSection {
    #[cfg_attr(test, proptest(value = "2"))]
    pub table_id: u8,
    pub section_syntax_indicator: bool,
    pub program_number: u16,
    #[cfg_attr(test, proptest(strategy = "0..2u8.pow(5)"))]
    pub version_number: u8,
    pub current_next_indicator: bool,
    pub section_number: u8,
    pub last_section_number: u8,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(13)"))]
    pub pcr_pid: u16,
    #[cfg_attr(
        test,
        proptest(strategy = "proptest::collection::vec(any::<u8>(), 0..100)")
    )]
    pub descriptors: Vec<u8>,
    #[cfg_attr(
        test,
        proptest(strategy = "proptest::collection::vec(any::<Stream>(), 0..10)")
    )]
    pub streams: Vec<Stream>,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PMT {
    pub program_number: u16,
    pub version_number: u8,
    pub pcr_pid: u16,
    pub streams: HashMap<u16, Stream>,
}

#[derive(Clone, Default, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct Stream {
    pub stream_type: u8,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(13)"))]
    pub pid: u16,
    pub descriptors: Vec<u8>
}

pub fn build_pat<T: Iterator<Item = PATSection>>(mut sections: T) -> Option<PAT> {
    let PATSection {
        transport_stream_id,
        version_number,
        pmt_pids,
        ..
    } = sections.next()?;
    let pat = PAT {
        transport_stream_id,
        version_number,
        pmt_pids: sections.fold(pmt_pids, |mut pmt_pids, section| {
            pmt_pids.extend(section.pmt_pids.iter());
            pmt_pids
            }),
    };

    Some(pat)
    }

pub fn build_pmt<T: Iterator<Item = PMTSection>>(mut sections: T) -> Option<PMT> {
    let PMTSection {
        program_number,
        version_number,
        pcr_pid,
        mut streams,
        ..
    } = sections.next()?;
    let streams: HashMap<u16, Stream> = streams
        .drain(..)
        .map(|stream| (stream.pid, stream))
        .collect();
    let pmt = PMT {
        program_number,
        version_number,
        pcr_pid,
        streams: sections.fold(streams, |mut streams, mut section| {
            streams.extend(section.streams.drain(..).map(|stream| (stream.pid, stream)));
            streams
            }),
    };

    Some(pmt)
    }

impl PATSection {
    pub fn is_complete(&self) -> bool {
        self.section_number == self.last_section_number && self.current_next_indicator
    }
}

impl PMTSection {
    pub fn is_complete(&self) -> bool {
        self.section_number == self.last_section_number && self.current_next_indicator
    }
}

impl PAT {
    pub fn programs(&self) -> HashSet<u16> {
        self.pmt_pids.keys().cloned().collect()
    }
}

fn parse_program_association_section(input: &[u8]) -> IResult<&[u8], Section> {
    let mut section = PATSection::default();
    let mut section_length = 0u16;

    let (input, (mappings, _crc32)) = do_parse!(input,
        bits!(parse_bits!(
            u8, 8, section.table_id,
            x, u8, 1, section.section_syntax_indicator = x == 1,
            _0, u8, 1, (),
            _reserved, u8, 2, (),
            u16, 12, section_length
        )) >>
        verify!(value!(section_length), |len| len >= 9) >>
        ret: slice!(section_length,
                do_parse!(
                    bits!(parse_bits!(
                        u16, 16, section.transport_stream_id,
                        _reserved, u8, 2, (),
                        u8, 5, section.version_number,
                        x, u8, 1, section.current_next_indicator = x == 1,
                        u8, 8, section.section_number,
                        u8, 8, section.last_section_number
                    )) >>
                    mappings: slice!(section_length - 5 - 4, many0!(complete!(call!(parse_pat_mapping)))) >>
                    crc32: call!(be_u32) >>
                    (mappings, crc32)
                )
        ) >>
        (ret)
    )?;

    section.pmt_pids = mappings.iter().cloned().collect();

    return Ok((input, Section::PAT(section)));

    fn parse_pat_mapping(input: &[u8]) -> IResult<&[u8], (u16, u16)> {
        let mut program_number = 0u16;
        let mut pmt_pid = 0u16;

        let (input, _) = bits!(input, parse_bits!(
            u16, 16, program_number,
            _reserved, u8, 3, (),
            u16, 13, pmt_pid
        ))?;

        Ok((input, (program_number, pmt_pid)))
    }
}

fn parse_program_map_section(input: &[u8]) -> IResult<&[u8], Section> {
    let mut section = PMTSection::default();
    let mut section_length = 0u16;
    let mut program_info_length = 0u16;

    let (input, (descriptors, definitions, _crc32)) = do_parse!(input,
        bits!(parse_bits!(
            u8, 8, section.table_id,
            x, u8, 1, section.section_syntax_indicator = x == 1,
            _0, u8, 1, (),
            _reserved, u8, 2, (),
            u16, 12, section_length
        )) >>
        verify!(value!(section_length), |len| len >= 13) >>
        ret: slice!(section_length,
            do_parse!(
                bits!(parse_bits!(
                    u16, 16, section.program_number,
                    _reserved, u8, 2, (),
                    u8, 5, section.version_number,
                    x, u8, 1, section.current_next_indicator = x == 1,
                    u8, 8, section.section_number,
                    u8, 8, section.last_section_number,
                    _reserved, u8, 3, (),
                    u16, 13, section.pcr_pid,
                    _reserved, u8, 4, (),
                    u16, 12, program_info_length
                )) >>
                verify!(value!(section_length), |len| len >= 13 + program_info_length) >>
                descriptors: take!(program_info_length) >>
                definitions: slice!(section_length - 9 - program_info_length - 4,
                    many0!(complete!(call!(parse_pmt_definition)))
                ) >>
                crc32: call!(be_u32) >>
                (descriptors, definitions, crc32)
            )
        ) >>
        (ret)
    )?;

    section.descriptors = descriptors.into();
    section.streams = definitions;

    return Ok((input, Section::PMT(section)));

    fn parse_pmt_definition(input: &[u8]) -> IResult<&[u8], Stream> {
        let mut stream = Stream::default();
        let mut info_len = 0u16;

        let (input, descriptors) = bits!(input, do_parse!(
            parse_bits!(
                u8, 8, stream.stream_type,
                _reserved, u8, 3, (),
                u16, 13, stream.pid,
                _reserved, u8, 4, (),
                u16, 12, info_len
            ) >>
            descriptors: bytes!(take!(info_len)) >>
            (descriptors)
        ))?;

        stream.descriptors = descriptors.into();

        Ok((input, stream))
    }
}

/// Parse the PSI content of a packet.
///
/// This is the low level nom parser. You most likely want to use one of
/// [`ReaderParser`](struct.ReaderParser.html) and [`Parser`](struct.Parser.html)
/// instead.
pub fn parse_psi<'a>(packet: &Packet, input: &'a [u8]) -> IResult<&'a [u8], Section> {
    do_parse!(input,
        cond!(packet.payload_unit_start_indicator, length_bytes!(be_u8)) >>
        table_id: peek!(take!(1)) >>
        section: switch!(value!(table_id),
            b"\x00" => call!(parse_program_association_section) |
            b"\x02" => call!(parse_program_map_section) |
            _ => do_parse!(
                    data: call!(rest) >>
                    (Section::Unsupported(table_id[0], data.to_vec())))
        ) >>
        (section)
    )
}

#[cfg(test)]
fn pid_map() -> impl Strategy<Value = HashMap<u16, u16>> {
    collection::hash_map(0..2u16.pow(13), 0..2u16.pow(13), 0..10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::writer;

    proptest! {
        #[test]
        fn test_pat_section(mut pat: PATSection) {
            let mut buf = Vec::new();
            buf.resize(writer::pat_len(&pat) as usize, 0u8);
            let section = Section::PAT(pat);
            
            let written = writer::write_section(&section, &mut buf);
            assert_eq!(written, buf.len());

            let res = parse_program_association_section(&buf).unwrap();
            assert_eq!(res, (&[][..], section));
        }

        #[test]
        fn test_pmt_section(mut pmt: PMTSection) {
            let mut buf = Vec::new();
            buf.resize(writer::pmt_len(&pmt) as usize, 0u8);
            let section = Section::PMT(pmt);
            
            let written = writer::write_section(&section, &mut buf);
            assert_eq!(written, buf.len());

            let res = parse_program_map_section(&buf).unwrap();
            assert_eq!(res, (&[][..], section));
        }
    }
}
