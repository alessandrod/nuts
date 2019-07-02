use nom::{bits, call, cond, do_parse, tag, take, IResult};

use super::adaptation_field::{parse_adaptation_field, AdaptationField};

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
use proptest_derive::Arbitrary;

/// Enum used to represent the adaptation field control field in a transport
/// stream packet.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum AdaptationFieldControl {
    Reserved,
    /// The packet contains payload data only.
    Payload,
    /// The packet contains an adaptaton field only (no payload).
    AdaptationField(Option<AdaptationField>),
    /// The packet contains both an adaptation field and payload data.
    AdaptationFieldAndPayload(Option<AdaptationField>),
}

/// Transport stream packet header.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct Packet {
    pub transport_error_indicator: bool,
    pub payload_unit_start_indicator: bool,
    pub transport_priority: bool,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(13)"))]
    pub pid: u16,
    #[cfg_attr(test, proptest(strategy = "0..4u8"))]
    pub transport_scrambling_control: u8,
    pub adaptation_field_control: AdaptationFieldControl,
    #[cfg_attr(test, proptest(strategy = "0..16u8"))]
    pub continuity_counter: u8,
}

impl Default for AdaptationFieldControl {
    fn default() -> Self {
        AdaptationFieldControl::Reserved
    }
}

impl Packet {
    pub fn adaptation_field(&self) -> Option<&AdaptationField> {
        use AdaptationFieldControl::*;
        match &self.adaptation_field_control {
            AdaptationField(af) | AdaptationFieldAndPayload(af) => af.as_ref(),
            _ => None
        }
    }
}

/// Parse one transport stream packet.
///
/// This is the low level nom parser. You most likely want to use one of
/// [`ReaderParser`](struct.ReaderParser.html) and [`Parser`](struct.Parser.html)
/// instead.
pub fn parse_packet<'a>(input: &'a [u8]) -> IResult<&[u8], (Packet, &'a [u8])> {
    use AdaptationFieldControl::*;

    let mut packet = Packet::default();
    let mut afc = 0u8;

    let (input, (adaptation_field, payload)) = slice!(input, 188,
        do_parse!(
            tag!(&[0x47]) >>
            bits!(
                do_parse!(
                    parse_flags!(
                        packet.transport_error_indicator,
                        packet.payload_unit_start_indicator,
                        packet.transport_priority
                    ) >>
                    parse_bits!(
                        u16, 13, packet.pid,
                        u8, 2, packet.transport_scrambling_control,
                        u8, 2, afc,
                        u8, 4, packet.continuity_counter
                    ) >>
                    ()
                )
            ) >>
            adaptation_field: cond!(afc == 2 || afc == 3,
                call!(parse_adaptation_field)
            ) >>
            // FIXME: make af.length Option<u8>, set it only when parsing
            payload: take!(184 - {
                match &adaptation_field {
                    Some(Some(af)) => super::writer::adaptation_field_len(af) + 1,
                    Some(None) => 1,
                    None => 0
                }
            }) >>
            (adaptation_field, payload)
        )
    )?;

    packet.adaptation_field_control = match afc {
        0 => Reserved,
        1 => Payload,
        2 => AdaptationField(adaptation_field.unwrap()),
        3 => AdaptationFieldAndPayload(adaptation_field.unwrap()),
        _ => unreachable!()
    };

    return Ok((input, (packet, payload)));
}

/// Scan the input looking for the closest valid sync point.
///
/// A sync point is a point in the stream where parsing can start or resume
/// after a corruption in the stream. Returns the sub slice of `input`
/// starting a the sync point or `None` if no sync point is found.
pub fn sync<'a>(mut input: &'a [u8], packet_size: usize) -> Option<&'a [u8]> {
    assert!(packet_size >= 188);
    let sync_size = packet_size * 2;
    let offset = packet_size - 188;
    while input.len() >= sync_size {
        if input[offset] == 0x47
            && input[packet_size + offset] == 0x47
            && input[2 * packet_size + offset] == 0x47 {
            return Some(&input);
        }

        input = &input[1..];
    }

    None
}

/// Given some transport stream data, try to find out the packet size.
///
/// Returns None if `input` contains invalid data or if the buffer is too small
/// (it needs to hold at least 3 packets).
pub fn discover_packet_size(input: &[u8]) -> Option<usize> {
    let sizes: [usize; 4] = [188, 192, 204, 208];
    for size in sizes.iter().cloned() {
        if sync(input, size).is_some() {
            return Some(size);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts::writer;

    proptest! {
        #[test]
        fn test_packet(gen_packet: Packet) {
            let mut buf = Vec::new();
            buf.resize(writer::len(&gen_packet), 0xFF);

            let header_len = writer::write_header(&gen_packet, &mut buf);
            assert_eq!(header_len, writer::header_len(&gen_packet));

            let (rest, (packet, payload)) = parse_packet(&buf).unwrap();
            assert_eq!(rest, &[]);

            assert_eq!((packet, payload), (gen_packet, &buf[header_len..]));
        }
    }
}
