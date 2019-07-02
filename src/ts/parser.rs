use std::convert::From;
use std::collections::HashMap;
use std::cmp;
use std::io::{self, Read};
use std::fmt;
use std::error::Error;
use nom::{self, Needed};

use crate::ts;
use crate::ts::psi::{parse_psi, PATSection, PMTSection, PSISections, Section, PAT, PMT};
use crate::pes;

use fixedbitset::FixedBitSet;

/// High level transport stream parser that can be used to parse byte slices. See
/// [`parse`](#method.parse).
///
/// The parser keeps track of Program Specific Information (PSI) internally and
/// exposes it via the [`pat`](#method.pat) and [`get_pmt`](#method.get_pmt)
/// methods.
#[derive(Debug)]
pub struct Parser {
    pat_sections: Vec<PATSection>,
    pat: Option<PAT>,
    pmt_sections: HashMap<u16, Vec<PMTSection>>,
    pmts: HashMap<u16, PMT>,
    psi_pids: FixedBitSet,
    pub packet_size: usize
}

/// The error type returned by [`Parser`](struct.Parser.html).
#[derive(Debug)]
pub enum ParserError {
    /// Parsing needs at least `usize` bytes to continue.
    Incomplete(usize),
    /// Could not find a valid packet.
    Corrupt,
    /// The parser has lost sync and needs to be resynced. See
    /// [`Parser::sync`](struct.Parser.html#method.sync).
    LostSync
}

/// The data contained in a transport stream packet.
#[derive(Debug)]
pub enum Data<'a> {
    /// The packet contains a PSI section.
    PSI(Section),
    /// The packet contains a PES packet and payload.
    PES(pes::Packet, &'a [u8]),
    /// The packet contains data.
    Data(&'a [u8])
}

fn init_psi_pids(pids: &mut FixedBitSet) {
    pids.clear();
    pids.insert_range(0..4);
}

impl Parser {
    /// Create a new parser instance.
    pub fn new() -> Self {
        Parser::with_packet_size(188)
    }

    /// Create a new parser instance for a stream with non standard packet size.
    ///
    /// Use this when parsing streams having extended packets like M2TS, ATSC
    /// etc. `size` must be larger than the standard packet length. (188 bytes)
    ///
    /// If you're not sure what packet size you're dealing with, you can use
    /// [`ts::discover_packet_size`](fn.discover_packet_size.html) to find out.
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

    /// Parse one packet from the given input.
    ///
    /// Returns the sub slice of `input` starting after the packet that has just
    /// been parsed, the packet header and the payload.
    ///
    /// # Errors
    ///
    /// Will fail if the given input is too small or if it doesn't contain a vaild packet.
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> Result<(&'a [u8], (ts::Packet, Data<'a>)), ParserError> {
        let offset = self.packet_size - 188;
        let (rest, (packet, payload)) = ts::parse_packet(&input[offset..])?;

        if self.is_psi(&packet) {
            let (_, section) = parse_psi(&packet, payload)?;
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

    /// Get the last version of the Program Association Table (PAT) found in the stream.
    ///
    /// Returns `None` if no PAT has been parsed yet.
    pub fn pat(&self) -> Option<&PAT> {
        self.pat.as_ref()
    }

    /// Return a map of the programs and the last version of their associated Program Map Table(s) (PMT).
    ///
    /// The returned value only includes the programs for which a PMT has been found.
    pub fn pmts(&self) -> &HashMap<u16, PMT> {
        &self.pmts
    }

    /// Get the last version of the Program Map Table (PMT) for the given program number.
    ///
    /// Returns `None` if the given program is not in the transport stream or if
    /// its PMT hasn't been parsed yet.
    pub fn get_pmt(&self, program: u16) -> Option<&PMT> {
        self.pmts.get(&program)
    }

    /// Scan the input looking for the closest valid sync point.
    ///
    /// A sync point is a point in the stream where parsing can start or resume
    /// after a corruption in the stream. Returns the sub slice of `input`
    /// starting a the sync point or `None` if no sync point is found.
    pub fn sync<'a>(&self, input: &'a [u8]) -> Option<&'a [u8]> {
        ts::sync(input, self.packet_size)
    }

    fn is_psi(&self, packet: &ts::Packet) -> bool {
        self.psi_pids.contains(packet.pid as usize)
    }

    fn is_pes(&self, packet: &ts::Packet, data: &[u8]) -> bool {
        if packet.payload_unit_start_indicator && data.len() >= 4 {
            if data[..3] == [0, 0, 1] {
                return true;
            }
        }

        return false;
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

/// The error type returned by [`ReaderParser`](struct.ReaderParser.html).
///
/// [`ReaderParser::parse`](struct.ReaderParser.html#method.parse) does two
/// things: calls `Read::read` on the provided `reader` and then parses the data.
/// Both operations can fail, in which case the original error is wrapped and
/// returned to the caller.
#[derive(Debug)]
pub enum ReaderParserError {
    /// Parsing error.
    ParserError(ParserError),
    /// IO Error.
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

/// High level transport stream parser that can be used with data sources that
/// implement the `Read` trait.
///
/// You can create a parser with [`new`](#method.new) or
/// [`with_packet_size`](#method.with_packet_size), then call
/// [`parse`](#method.parse) repeatedly to parse packets.
///
/// The parser uses an internal buffer and [`parse`](#method.parse) returns
/// `Ok(None)` to signal `eof`. As packets are parsed, it keeps track of Program
/// Specific Information (PSI) internally and exposes it via the
/// [`pat`](#method.pat) and [`get_pmt`](#method.get_pmt) methods.
#[derive(Debug)]
pub struct ReaderParser<T: Read> {
    parser: Parser,
    buffer: ParserBuffer<T>,
    consumed: usize
}

impl<T: Read> ReaderParser<T> {
    /// Create a new parser instance.
    ///
    /// The parser will read data from the given reader type.
    pub fn new(reader: T) -> Self {
        ReaderParser::with_packet_size(reader, 188)
    }

    /// Create a new parser instance for a stream with non standard packet size.
    ///
    /// Use this when parsing streams having extended packets like M2TS, ATSC
    /// etc. `size` must be larger than the standard packet length. (188 bytes)
    ///
    /// If you're not sure what packet size you're dealing with, you can use
    /// [`ts::discover_packet_size`](fn.discover_packet_size.html) to find out.
    pub fn with_packet_size(reader: T, size: usize) -> Self {
        ReaderParser {
            parser: Parser::new(),
            buffer: ParserBuffer::new(size * 100, reader),
            consumed: 0
        }
    }

    /// Parse the next packet.
    ///
    /// Returns a tuple where the first element is the input packet, the second
    /// element is in turn a tuple containing the parsed packet header and the
    /// payload. Returns `None` when the parser reaches `eof`.
    ///
    /// # Errors
    ///
    /// Will fail in case of parsing errors or if reading from the inner reader
    /// fails. See also [`recover`](#method.recovner).
    pub fn parse(&mut self) -> Result<Option<(&[u8], ts::Packet, ts::Data)>, ReaderParserError> {
        self.buffer.consume(self.consumed);
        self.consumed = 0;

        let input = self.buffer.fill_buf()?;
        if input.len() == 0 {
            return Ok(None)
        }
        let (rest, (packet, data)) = self.parser.parse(input)?;
        let size = input.len() - rest.len();
        self.consumed = size;
        Ok(Some((&input[..size], packet, data)))
    }

    /// Try to recover from the last parsing error.
    ///
    /// When [`parse`](#method.parse) returns an error and the error is
    /// recoverable, calling this function will attempt to recover.
    ///
    /// # Errors
    ///
    /// Will fail if the given error can not be recovered from or if the error
    /// recovery logic fails too.
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

    /// Get the last version of the Program Association Table (PAT) found in the stream.
    ///
    /// Returns `None` if no PAT has been parsed yet.
    pub fn pat(&self) -> Option<&PAT> {
        self.parser.pat()
    }

    /// Get the last version of the Program Map Table (PMT) for the given program number.
    ///
    /// Returns `None` if the given program is not in the transport stream or if
    /// its PMT hasn't been parsed yet.
    pub fn get_pmt(&self, program: u16) -> Option<&PMT> {
        self.parser.get_pmt(program)
    }

    /// Return a map of the programs and the last version of their associated Program Map Table(s) (PMT).
    ///
    /// The returned value only includes the programs for which a PMT has been found.
    pub fn pmts(&self) -> &HashMap<u16, PMT> {
        self.parser.pmts()
    }
}