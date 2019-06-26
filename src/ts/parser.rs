use std::convert::From;
use std::collections::{HashMap, HashSet};
use std::iter::Iterator;
use std::cmp;
use std::io::{self, Read};
use std::fmt;
use std::error::Error;
use nom::{self, Needed};

use crate::ts;
use crate::ts::psi::{parse_psi, PATSection, PMTSection, PSISections, Section, PAT, PMT};
use crate::pes;
use nom::IResult;

use fixedbitset::FixedBitSet;

#[derive(Debug)]
pub struct Parser {
    pat_sections: Vec<PATSection>,
    pat: Option<PAT>,
    pmt_sections: HashMap<u16, Vec<PMTSection>>,
    pmts: HashMap<u16, PMT>,
    psi_pids: FixedBitSet,
    pub packet_size: usize
}

#[derive(Debug)]
pub enum ParserError {
    Incomplete(usize),
    Corrupt,
    LostSync
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
        Parser::with_packet_size(188)
    }

    pub fn with_packet_size(size: usize) -> Self {
        assert!(size >= 188);
        let mut psi_pids = FixedBitSet::with_capacity(0x1FFF);
        init_psi_pids(&mut psi_pids);
        Self {
            pat_sections: Vec::new(),
            pat: None,
            pmt_sections: HashMap::new(),
            pmts: HashMap::new(),
            psi_pids: psi_pids,
            packet_size: size
        }
    }

    pub fn discover_packet_size(input: &[u8]) -> Option<usize> {
        let sizes: [usize; 4] = [188, 192, 204, 208];
        let mut parser = Parser::new();
        for size in sizes.iter().cloned() {
            parser.packet_size = size;
            if parser.sync(input).is_some() {
                return Some(size);
            }
        }

        None
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
        ts::sync(data, self.packet_size)
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

    pub fn parse<'a>(&mut self, input: &'a [u8]) -> Result<(&'a [u8], (ts::Packet, Data<'a>)), ParserError> {
        let offset = self.packet_size - 188;
        let (rest, (packet, payload)) = ts::parse_packet(&input[offset..])?;

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

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for ParserError {
    fn description(&self) -> &str {
        use ParserError::*;
        match self {
            Incomplete(_) => "incomplete input buffer",
            Corrupt => "corrupt packet",
            LostSync => "lost sync"
        }
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl<T> From<nom::Err<T>> for ParserError {
    fn from(error: nom::Err<T>) -> ParserError {
        match error {
            nom::Err::Incomplete(Needed::Size(needed)) => ParserError::Incomplete(needed),
            nom::Err::Error(nom::Context::Code(_, nom::ErrorKind::Complete)) => ParserError::Corrupt,
            _ => ParserError::LostSync
        }
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

#[derive(Debug)]
pub enum ReaderParserError {
    ParserError(ParserError),
    ReadError(io::Error)
}

impl fmt::Display for ReaderParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.description(), self.source().unwrap())
    }
}

impl Error for ReaderParserError {
    fn description(&self) -> &str {
        use ReaderParserError::*;
        match self {
            ParserError(_) => "error parsing transport stream",
            ReadError(_) => "error reading input"
        }
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ReaderParserError::*;
        match self {
            ParserError(e) => Some(e),
            ReadError(e) => Some(e)
        }
    }
}

impl From<io::Error> for ReaderParserError {
    fn from(error: io::Error) -> Self {
        ReaderParserError::ReadError(error)
    }
}

impl From<ParserError> for ReaderParserError {
    fn from(error: ParserError) -> Self {
        ReaderParserError::ParserError(error)
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
        ReaderParser::with_packet_size(reader, 188)
    }

    pub fn with_packet_size(reader: T, size: usize) -> Self {
        ReaderParser {
            parser: Parser::new(),
            buffer: ParserBuffer::new(size * 100, reader),
            consumed: 0
        }
    }

    pub fn recover(&mut self, error: ReaderParserError) -> Result<(), ReaderParserError> {
        use ParserError::*;

        let error = match error {
            ReaderParserError::ParserError(e) => e,
            e => return Err(e)
        };

        match error {
            Incomplete(needed) => {
                self.buffer.compact();
                let input = self.buffer.fill_buf()?;
                if input.len() < needed {
                    return Err(Incomplete(needed).into());
                }

                Ok(())
            }
            Corrupt => {
                self.buffer.consume(1);
                self.recover(ParserError::LostSync.into())
            }
            LostSync => {
                self.buffer.compact();
                let input = self.buffer.fill_buf()?;
                if let Some(next_input) = self.parser.sync(input) {
                    let skipped = input.len() - next_input.len();
                    assert!(skipped > 0, "Parser stuck at sync point. This is a bug.");
                    self.buffer.consume(skipped);
                    return Ok(())
                }

                Err(LostSync.into())
            }
        }
    }

    pub fn parse(&mut self) -> Result<Option<(&[u8], ts::Packet, ts::Data)>, ReaderParserError> {
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