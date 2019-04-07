use std::collections::{HashMap, HashSet};
use std::iter::Iterator;
use std::cmp::min;

use crate::ts;
use crate::ts::psi::{parse_psi, PATSection, PMTSection, PSISections, Section, PAT, PMT};
use crate::pes;
use nom::IResult;

pub const SYNC_LENGTH: usize = 2 * 188 + 1;

pub struct Parser {
    pat_sections: Vec<PATSection>,
    active_pat: Option<PAT>,
    pmt_sections: HashMap<u16, Vec<PMTSection>>,
    active_pmts: HashMap<u16, PMT>,
    psi_pids: HashSet<u16>,
}

fn initial_psi_pids() -> HashSet<u16> {
    [0, 1, 2, 3].iter().cloned().collect()
}

#[derive(Debug)]
pub enum Data<'a> {
    PSI(Section),
    PES(pes::Packet, &'a [u8]),
    Data(&'a [u8])
}

impl Parser {
    pub fn new() -> Self {
        Self {
            pat_sections: Vec::new(),
            active_pat: None,
            pmt_sections: HashMap::new(),
            active_pmts: HashMap::new(),
            psi_pids: initial_psi_pids()
        }
    }

    fn handle_pat(&mut self, pat: &PATSection) {
        if let Some(active_pat) = self.active_pat.as_ref() {
            /* only process PAT updates, handling version_number wrap arounds */
            if pat.version_number <= active_pat.version_number && active_pat.version_number < 31 {
                return;
            }
        }

        let complete = pat.section_number == pat.last_section_number && pat.current_next_indicator;
        self.pat_sections.push(pat.clone());
        if complete {
            let pat = self.pat_sections.complete().unwrap();
            self.psi_pids = initial_psi_pids();
            self.psi_pids.extend(pat.pmt_pids.values());
            self.active_pat = Some(pat);
        }
    }

    fn handle_pmt(&mut self, pmt: &PMTSection) {
        if let Some(active_pmt) = self.active_pmts.get(&pmt.program_number) {
            /* only process PMT updates, handling version_number wrap arounds */
            if pmt.version_number <= active_pmt.version_number && active_pmt.version_number < 31 {
                return;
            }
        }
        let program_number = pmt.program_number;
        let sections = self.pmt_sections.entry(pmt.program_number).or_insert_with(Vec::new);
        let complete = pmt.section_number == pmt.last_section_number && pmt.current_next_indicator;
        sections.push(pmt.clone());
        if complete {
            let pmt = sections.complete().unwrap();
            self.active_pmts.insert(program_number, pmt);
        }
    }

    pub fn sync<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.len() < SYNC_LENGTH {
            return None
        }

        let input = &data[..min(data.len() - SYNC_LENGTH, 1024 * 1024)];
        for (i, x) in input.iter().cloned().enumerate() {
            if x == 0x47 && input[i + 188] == 0x47 && input[i + 2 * 188] == 0x47 {
                return Some(&data[i..]);
            }
        };

        None
    }

    pub fn is_psi(&self, packet: &ts::Packet) -> bool {
        self.psi_pids.contains(&packet.pid)
    }

    pub fn parse_psi<'a>(&self, packet: &ts::Packet, payload: &'a [u8]) -> IResult<&'a [u8], Section> {
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

    pub fn parse<'a>(&mut self, input: &'a [u8]) -> IResult<&'a [u8], (ts::Packet, Data<'a>)> {
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
