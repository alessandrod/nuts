use nom::{bits, call, cond, do_parse, tag, take, IResult};
use std::io::{self, Cursor, Write};

use super::adaptation_field::{parse_adaptation_field, AdaptationField};

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum AdaptationFieldControl {
    Reserved,
    Payload,
    AdaptationField(Option<AdaptationField>),
    AdaptationFieldAndPayload(Option<AdaptationField>),
}

#[derive(Default, Debug, PartialEq)]
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
    pub fn header_length(&self) -> usize {
        use AdaptationFieldControl::*;
        let mut len = 4;

        len += match &self.adaptation_field_control {
            AdaptationField(af)
            | AdaptationFieldAndPayload(af) => {
                if let Some(af) = af {
                    af.length() as usize + 1
                } else {
                    1
                }
            },
            _ => 0
        };

        len
    }

    pub fn write(&self, buf: &mut [u8]) -> io::Result<()> {
        use AdaptationFieldControl::*;

        let mut buff = Cursor::new(buf);
        buff.write(&[0x47])?;
        let mut tmp = self.pid.to_be_bytes();
        tmp[0] |= (self.transport_error_indicator as u8) << 7
            | (self.payload_unit_start_indicator as u8) << 6
            | (self.transport_priority as u8) << 5;
        buff.write(&tmp)?;
        let adaptation_field_control = match self.adaptation_field_control {
            Reserved => 0,
            Payload => 1,
            AdaptationField(_) => 2,
            AdaptationFieldAndPayload(_) => 3,
        };
        let tmp = (self.transport_scrambling_control as u8) << 6
            | adaptation_field_control << 4
            | self.continuity_counter;
        buff.write(&[tmp])?;
        match &self.adaptation_field_control {
            AdaptationField(af)
            | AdaptationFieldAndPayload(af) =>
                {
                    if let Some(af) = af {
                        let pos = buff.position() as usize;
                        af.write(&mut buff.get_mut()[pos..])?;
                    } else {
                        buff.write(&[0])?;
                    }
                },
            _ => ()
        }

        Ok(())
    }
}

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
            payload: take!(184 - {
                match adaptation_field.as_ref() {
                    Some(Some(af)) => af.length() + 1,
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

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn test_packet(mut packet: Packet) {
            let mut buf = Vec::new();
            buf.resize(188, 0xFF);
            packet.write(&mut buf).unwrap();
            let header_length = packet.header_length();
            let (rest, parsed_packet) = parse_packet(&buf).unwrap();
            assert_eq!((rest, parsed_packet), (&[][..], (packet, &buf[header_length..])));
        }
    }
}
