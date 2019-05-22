use std::convert::From;
use std::collections::{HashMap, HashSet};
use std::iter::Iterator;
use std::cmp;
use std::io::{self, Read};
use nom::{self, Needed};

use crate::ts;
use crate::ts::psi::{parse_psi, PATSection, PMTSection, PSISections, Section, PAT, PMT};
use crate::pes;
use nom::IResult;

use fixedbitset::FixedBitSet;

pub const PACKET_SIZE: usize = 188;
pub const SYNC_LENGTH: usize = 2 * PACKET_SIZE + 1;

#[derive(Debug)]
pub struct Parser {
    pat_sections: Vec<PATSection>,
    pat: Option<PAT>,
    pmt_sections: HashMap<u16, Vec<PMTSection>>,
    pmts: HashMap<u16, PMT>,
    psi_pids: FixedBitSet
}

#[derive(Debug)]
pub enum ParseError {
    Incomplete(usize),
    LostSync,
    Unrecoverable
}

#[derive(Debug)]
pub enum Data<'a> {
    PSI(Section),
    PES(pes::Packet, &'a [u8]),
    Data(&'a [u8])
}

fn init_psi_pids(pids: &mut FixedBitSet) {
    pids.clear();
    pids.insert_range(0..4);
}

impl Parser {
    pub fn new() -> Self {
        let mut psi_pids = FixedBitSet::with_capacity(0x1FFF);
        init_psi_pids(&mut psi_pids);
        Self {
            pat_sections: Vec::new(),
            pat: None,
            pmt_sections: HashMap::new(),
            pmts: HashMap::new(),
            psi_pids: psi_pids
        }
    }

    fn handle_pat(&mut self, pat: &PATSection) {
        if let Some(current_pat) = &self.pat {
            /* only process PAT updates, handling version_number wrap arounds */
            if pat.version_number <= current_pat.version_number && current_pat.version_number < 31 {
                return;
            }
        }

        self.pat_sections.push(pat.clone());
        if pat.is_complete() {
            let pat = self.pat_sections.complete().unwrap();
            init_psi_pids(&mut self.psi_pids);
            for pid in pat.pmt_pids.values() {
                self.psi_pids.insert(*pid as usize);
            }
            self.pat = Some(pat);
        }
    }

    fn handle_pmt(&mut self, pmt: &PMTSection) {
        if let Some(active_pmt) = self.pmts.get(&pmt.program_number) {
            /* only process PMT updates, handling version_number wrap arounds */
            if pmt.version_number <= active_pmt.version_number && active_pmt.version_number < 31 {
                return;
            }
        }
        let program_number = pmt.program_number;
        let sections = self.pmt_sections.entry(pmt.program_number).or_insert_with(Vec::new);
        sections.push(pmt.clone());
        if pmt.is_complete() {
            let pmt = sections.complete().unwrap();
            self.pmts.insert(program_number, pmt);
        }
    }

    pub fn pat(&self) -> Option<&PAT> {
        self.pat.as_ref()
    }

    pub fn get_pmt(&self, program: u16) -> Option<&PMT> {
        self.pmts.get(&program)
    }

    pub fn pmts(&self) -> &HashMap<u16, PMT> {
        &self.pmts
    }

    pub fn sync<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.len() < SYNC_LENGTH {
            return None
        }

        let input = &data[..cmp::min(data.len() - SYNC_LENGTH, 1024 * 1024)];
        for (i, x) in input.iter().cloned().enumerate() {
            if x == 0x47 && input[i + 188] == 0x47 && input[i + 2 * 188] == 0x47 {
                return Some(&data[i..]);
            }
        };

        None
    }

    fn is_psi(&self, packet: &ts::Packet) -> bool {
        self.psi_pids.contains(packet.pid as usize)
    }

    fn parse_psi<'a>(&self, packet: &ts::Packet, payload: &'a [u8]) -> IResult<&'a [u8], Section> {
        parse_psi(packet, payload)
    }

    fn is_pes(&self, packet: &ts::Packet, data: &[u8]) -> bool {
        if packet.payload_unit_start_indicator && data.len() >= 4 {
            if data[..3] == [0, 0, 1] {
                return true;
            }
        }

        return false;
    }

    pub fn parse<'a>(&mut self, input: &'a [u8]) -> Result<(&'a [u8], (ts::Packet, Data<'a>)), ParseError> {
        let (rest, (packet, payload)) = ts::parse_packet(input)?;

        if self.is_psi(&packet) {
            let (_, section) = self.parse_psi(&packet, payload)?;
            match &section {
                Section::PAT(pat) => self.handle_pat(pat),
                Section::PMT(pmt) => self.handle_pmt(pmt),
                Section::Unsupported(_, _) => ()
            }
            return Ok((rest, (packet, Data::PSI(section))))
        }
        if self.is_pes(&packet, &payload) {
            let (payload_rest, (pes_packet, payload)) = pes::parse_packet(payload)?;
            assert!(payload_rest.len() == 0);
            return Ok((rest, (packet, Data::PES(pes_packet, payload))))
        }

        Ok((rest, (packet, Data::Data(payload))))
    }
}

#[derive(Debug)]
struct ParserBuffer<T: Read> {
    inner: T,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize
}

impl<T: Read> ParserBuffer<T> {
    fn new(size: usize, reader: T) -> Self {
        let mut buf = Vec::with_capacity(size);
        buf.resize(size, 0xFE);
        ParserBuffer {
            inner: reader,
            buf: buf.into_boxed_slice(),
            pos: 0,
            cap: 0
        }
    }

    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.cap {
            debug_assert!(self.pos == self.cap);
            self.cap = self.inner.read(&mut self.buf)?;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.cap);
    }

    fn compact(&mut self) {
        if self.pos < self.cap {
            self.buf.rotate_left(self.pos);
            self.cap -= self.pos;
            self.pos = 0;
        }
    }
}

impl From<io::Error> for ParseError {
    fn from(error: io::Error) -> ParseError {
        ParseError::Unrecoverable
    }
}

impl<T> From<nom::Err<T>> for ParseError {
    fn from(error: nom::Err<T>) -> ParseError {
        match error {
            nom::Err::Incomplete(Needed::Size(needed)) => ParseError::Incomplete(needed),
            _ => ParseError::LostSync
        }
    }
}

#[derive(Debug)]
pub struct ReaderParser<T: Read> {
    parser: Parser,
    buffer: ParserBuffer<T>,
    consumed: usize
}

impl<T: Read> ReaderParser<T> {
    pub fn new(reader: T) -> Self {
        ReaderParser {
            parser: Parser::new(),
            buffer: ParserBuffer::new(PACKET_SIZE * 100, reader),
            consumed: 0
        }
    }

    pub fn recover(&mut self, error: ParseError) -> Result<(), ParseError> {
        use ParseError::*;
        match error {
            Incomplete(needed) => {
                self.buffer.compact();
                let input = self.buffer.fill_buf()?;
                if input.len() < needed {
                    return Err(Unrecoverable)
                }

                Ok(())
            },
            LostSync => {
                self.buffer.compact();
                let input = self.buffer.fill_buf()?;
                if let Some(next_input) = self.parser.sync(input) {
                    let skipped = input.len() - next_input.len();
                    self.buffer.consume(skipped);
                    return Ok(())
                }

                return Err(Unrecoverable)
            },
            Unrecoverable => Err(Unrecoverable)
        }
    }

    pub fn parse(&mut self) -> Result<Option<(&[u8], ts::Packet, ts::Data)>, ParseError> {
        self.buffer.consume(self.consumed);
        self.consumed = 0;

        let input = self.buffer.fill_buf()?;
        if input.len() == 0 {
            return Ok(None)
        }
        let (rest, (packet, data)) = self.parser.parse(input)?;
        self.consumed = input.len() - rest.len();
        Ok(Some((input, packet, data)))
    }

    pub fn pat(&self) -> Option<&PAT> {
        self.parser.pat()
    }

    pub fn get_pmt(&self, program: u16) -> Option<&PMT> {
        self.parser.get_pmt(program)
    }

    pub fn pmts(&self) -> &HashMap<u16, PMT> {
        self.parser.pmts()
    }
}