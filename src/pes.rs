pub mod writer;

use crate::utils::parse_timestamp;
use nom::{
    be_u16, be_u8, bits, bytes, call, complete, cond, do_parse, length_bytes, map, map_res,
    rest, switch, tag, tag_bits, take, take_bits, tap, value, verify, IResult
};
use std::convert::{TryFrom, From};

#[cfg(test)]
use proptest::{collection, option, prelude::*};
#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum StreamId {
    ProgramStreamMap,
    PrivateStream1,
    PaddingStream,
    PrivateStream2,
    #[cfg_attr(test, proptest(strategy("(0..2u8.pow(5)).prop_map(|n| StreamId::AudioStream(n))")))]
    AudioStream(u8),
    #[cfg_attr(test, proptest(strategy("(0..2u8.pow(4)).prop_map(|n| StreamId::VideoStream(n))")))]
    VideoStream(u8),
    ECMStream,
    EMMStream,
    DSMCCStream,
    MHEGStream,
    H2221A,
    H2221B,
    H2221C,
    H2221D,
    H2221E,
    AncillaryStream,
    _144961SLPacketizedStream,
    _144961SLFlexMuxStream,
    MetadataStream,
    ExtendedStreamId,
    ReservedDataStream,
    ProgramStreamDirectory,
    #[cfg_attr(test, proptest(strategy("(0..0xBCu8).prop_map(|n| StreamId::Unknown(n))")))]
    Unknown(u8)
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
// FIXME: merge his and PCR?
pub struct ESCR {
    #[cfg_attr(test, proptest(strategy = "0..2u64.pow(33)"))]
    pub base: u64,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(9)"))]
    pub extension: u16,
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum TrickMode {
    #[cfg_attr(test, proptest(strategy("tests::trick_mode_fast_forward()")))]
    FastForward(u8, bool, u8),
    #[cfg_attr(test, proptest(strategy("tests::trick_mode_slow_motion()")))]
    SlowMotion(u8),
    #[cfg_attr(test, proptest(strategy("tests::trick_mode_freeze_frame()")))]
    FreezeFrame(u8),
    #[cfg_attr(test, proptest(strategy("tests::trick_mode_fast_reverse()")))]
    FastReverse(u8, bool, u8),
    #[cfg_attr(test, proptest(strategy("tests::trick_mode_slow_reverse()")))]
    SlowReverse(u8),
    #[cfg_attr(test, proptest(strategy("tests::trick_mode_reserved()")))]
    Reserved(u8)
}

#[derive(Default, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
#[cfg_attr(test, proptest(filter = "|header| !(header.pts.is_none() && header.dts.is_some())"))]
pub struct Header {
    #[cfg_attr(test, proptest(strategy = "0..4u8"))]
    pub scrambling_control: u8,
    pub priority: bool,
    pub data_alignment_indicator: bool,
    pub copyright: bool,
    pub original_or_copy: bool,
    #[cfg_attr(test, proptest(strategy = "option::of(0..2u64.pow(33))"))]
    pub pts: Option<u64>,
    #[cfg_attr(test, proptest(strategy = "option::of(0..2u64.pow(33))"))]
    pub dts: Option<u64>,
    pub escr: Option<ESCR>,
    #[cfg_attr(test, proptest(strategy = "option::of(0..2u32.pow(22))"))]
    pub es_rate: Option<u32>,
    pub trick_mode: Option<TrickMode>,
    #[cfg_attr(test, proptest(strategy = "option::of(0..2u8.pow(7))"))]
    pub additional_copy_info: Option<u8>,
    pub previous_packet_crc: Option<u16>,
    pub extension: Option<HeaderExtension>,
    #[cfg_attr(test, proptest(value = "0"))] /* FIXME: find the max value */
    pub stuffing_len: u8
}
#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ProgramPacketSequenceCounter {
    #[cfg_attr(test, proptest(strategy = "0..2u8.pow(7)"))]
    pub counter: u8,
    pub mpeg1_mpeg2_identifier: bool,
    #[cfg_attr(test, proptest(strategy = "0..2u8.pow(6)"))]
    pub original_stuff_length: u8,
}

#[derive(Default, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct PSTDBuffer {
    #[cfg_attr(test, proptest(strategy = "0..2u8"))]
    scale: u8,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(13)"))]
    size: u16
}

#[derive(Default, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct HeaderExtension {
    #[cfg_attr(test, proptest(strategy("option::of(collection::vec(any::<u8>(), 16))")))]
    pub private_data: Option<Vec<u8>>,
    #[cfg_attr(test, proptest(strategy("option::of(collection::vec(any::<u8>(), 0..128))")))]
    pub pack_header: Option<Vec<u8>>,
    pub p_std_buffer: Option<PSTDBuffer>,
    pub program_packet_sequence_counter: Option<ProgramPacketSequenceCounter>,
    pub extension_2: Option<HeaderExtension2>
}

#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum HeaderExtension2 {
    #[cfg_attr(test, proptest(strategy("tests::header_extension_2_stream_id()")))]
    StreamIdExtension(u8),
    #[cfg_attr(test, proptest(strategy("tests::header_extension_2_tref()")))]
    TREF(u64)
}

#[derive(Default, Debug, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
#[cfg_attr(test, proptest(filter="|p| tests::packet_filter(p)"))]
pub struct Packet {
    pub stream_id: StreamId,
    pub length: u16,
    pub header: Option<Header>,
}

impl StreamId {
    pub fn has_header(&self) -> bool {
        use StreamId::*;

        match self {
            ProgramStreamMap
            | PrivateStream2
            | ECMStream
            | EMMStream
            | ProgramStreamDirectory
            | DSMCCStream => false,
            _ => true
        }
    }
}

impl TryFrom<u8> for StreamId {
    type Error = ();
    fn try_from(stream_type: u8) -> Result<Self, Self::Error> {
        use StreamId::*;

        if stream_type < 0xBC {
            return Ok(Unknown(stream_type));
        }

        if (0xC0..0xE0).contains(&stream_type) {
            return Ok(AudioStream(stream_type - 0xC0));
        }

        if (0xE0..0xF0).contains(&stream_type) {
            return Ok(VideoStream(stream_type - 0xE0));
        }

        Ok(match stream_type {
            0xBC => ProgramStreamMap,
            0xBD => PrivateStream1,
            0xBE => PaddingStream,
            0xBF => PrivateStream2,
            0xF0 => ECMStream,
            0xF1 => EMMStream,
            0xF2 => DSMCCStream,
            0xF3 => MHEGStream,
            0xF4 => H2221A,
            0xF5 => H2221B,
            0xF6 => H2221C,
            0xF7 => H2221D,
            0xF8 => H2221E,
            0xF9 => AncillaryStream,
            0xFA => _144961SLPacketizedStream,
            0xFB => _144961SLFlexMuxStream,
            0xFC => MetadataStream,
            0xFD => ExtendedStreamId,
            0xFE => ReservedDataStream,
            0xFF => ProgramStreamDirectory,
            _ => unreachable!()
        })
    }
}

impl From<StreamId> for u8 {
    fn from(stream_id: StreamId) -> u8 {
        use StreamId::*;

        match stream_id {
            Unknown(n) => n,
            ProgramStreamMap => 0xBC,
            PrivateStream1 => 0xBD,
            PaddingStream => 0xBE,
            PrivateStream2 => 0xBF,
            AudioStream(n) => 0xC0 + n,
            VideoStream(n) => 0xE0 + n,
            ECMStream => 0xF0,
            EMMStream => 0xF1,
            DSMCCStream => 0xF2,
            MHEGStream => 0xF3,
            H2221A => 0xF4,
            H2221B => 0xF5,
            H2221C => 0xF6,
            H2221D => 0xF7,
            H2221E => 0xF8,
            AncillaryStream => 0xF9,
            _144961SLPacketizedStream => 0xFA,
            _144961SLFlexMuxStream => 0xFB,
            MetadataStream => 0xFC,
            ExtendedStreamId => 0xFD,
            ReservedDataStream => 0xFE,
            ProgramStreamDirectory => 0xFF
        }
    }
}

impl Default for StreamId {
    fn default() -> Self {
        StreamId::ReservedDataStream
    }
}

pub fn parse_packet<'a>(input: &'a [u8]) -> IResult<&[u8], (Packet, &'a [u8])> {
    let (input, (stream_id, length)) = do_parse!(input,
        tag!(&[0x00, 0x00, 0x01]) >>
        id: map_res!(call!(be_u8), |id| StreamId::try_from(id)) >>
        length: call!(be_u16) >>
        (id, length)
    )?;

    let mut packet = Packet::default();
    packet.stream_id = stream_id;
    packet.length = length;

    let (input, data) = if stream_id.has_header() {
        let (input, (header, data)) = parse_header_and_data(input)?;

        packet.header = Some(header);
        (input, data)
    } else {
        complete!(input, take!(length))?
    };

    return Ok((input, (packet, data)));
}

fn parse_header_and_data<'a>(input: &'a [u8]) -> IResult<&'a [u8], (Header, &'a [u8])> {
    let mut header = Header::default();
    let mut pts_dts_flag = 0u8;
    let mut escr_flag = false;
    let mut es_rate_flag = false;
    let mut dsm_trick_mode_flag = false;
    let mut additional_copy_info_flag = false;
    let mut pes_crc_flag = false;
    let mut pes_extension_flag = false;

    let (input, (extension, stuffing_len, data)) = do_parse!(input,
        length: bits!(do_parse!(
            tag_bits!(u8, 2, 0x2) >>
            parse_bits!(
                u8, 2, header.scrambling_control
            ) >>
            parse_flags!(
                header.priority,
                header.data_alignment_indicator,
                header.copyright,
                header.original_or_copy
            ) >>
            parse_bits!(
                u8, 2, pts_dts_flag
            ) >>
            verify!(value!(pts_dts_flag), |flag| flag != 1) >>
            parse_flags!(
                escr_flag,
                es_rate_flag,
                dsm_trick_mode_flag,
                additional_copy_info_flag,
                pes_crc_flag,
                pes_extension_flag
            ) >>
            length: bytes!(call!(be_u8)) >>
            (length)
        )) >>
        res: slice!(length,
            do_parse!(
                cond!(pts_dts_flag == 2 || pts_dts_flag == 3, bits!(do_parse!(
                    tag_bits!(u8, 4, pts_dts_flag) >>
                    tap!(ts: call!(parse_timestamp) => header.pts = Some(ts)) >>
                    ()
                ))) >>
                cond!(pts_dts_flag == 3, bits!(do_parse!(
                    tag_bits!(u8, 4, 1) >>
                    tap!(ts: call!(parse_timestamp) => header.dts = Some(ts)) >>
                    ()
                ))) >>
                cond!(escr_flag,
                    tap!(escr: call!(parse_escr) => header.escr = Some(escr))) >>
                cond!(es_rate_flag, bits!(do_parse!(
                    tag_bits!(u8, 1, 1) >>
                    tap!(x: take_bits!(u32, 22) => header.es_rate = Some(x)) >>
                    tag_bits!(u8, 1, 1) >>
                    ()
                ))) >>
                cond!(dsm_trick_mode_flag,
                    tap!(tm: call!(parse_trick_mode) => header.trick_mode = Some(tm))) >>
                cond!(additional_copy_info_flag, bits!(
                    parse_bits!(
                        _marker, u8, 1, (),
                        x, u8, 7, header.additional_copy_info = Some(x)
                    )
                )) >>
                cond!(pes_crc_flag,
                    tap!(crc: call!(be_u16) => header.previous_packet_crc = Some(crc))
                ) >>
                extension: cond!(pes_extension_flag, call!(parse_header_extension)) >>
                stuffing_bytes: call!(rest) >>
                (extension, stuffing_bytes.len() as u8)
            )
        ) >>
        data: call!(rest) >>
        (res.0, res.1, data)
    )?;

    header.extension = extension;
    header.stuffing_len = stuffing_len;

    return Ok((input, (header, data)));

    fn parse_escr(input: &[u8]) -> IResult<&[u8], ESCR> {
        bits!(input, do_parse!(
            take_bits!(u8, 2) >>
            base: call!(parse_timestamp) >>
            extension: take_bits!(u16, 9) >>
            tag_bits!(u8, 1, 1) >>
            (ESCR { base, extension })
        ))

    }

    fn parse_trick_mode(input: &[u8]) -> IResult<&[u8], TrickMode> {
        use TrickMode::*;

        let mut field_id = 0u8;
        let mut intra_slice_refresh = false;
        let mut frequency_truncation = 0u8;
        let mut rep_cntrl = 0u8;

        bits!(input, do_parse!(
            control: take_bits!(u8, 3) >>
            res: switch!(value!(control),
                0 => do_parse!(
                    parse_bits!(
                        u8, 2, field_id,
                        x, u8, 1, intra_slice_refresh = x == 1,
                        u8, 2, frequency_truncation
                    ) >>
                    (FastForward(field_id, intra_slice_refresh, frequency_truncation))
                ) |
                1 => do_parse!(
                    parse_bits!(
                        u8, 5, rep_cntrl
                    ) >>
                    (SlowMotion(rep_cntrl))
                ) |
                2 => do_parse!(
                    parse_bits!(
                        u8, 2, field_id
                    ) >>
                    (FreezeFrame(field_id))
                ) |
                3 => do_parse!(
                    parse_bits!(
                        u8, 2, field_id,
                        x, u8, 1, intra_slice_refresh = x == 1,
                        u8, 2, frequency_truncation
                    ) >>
                    (FastReverse(field_id, intra_slice_refresh, frequency_truncation))
                ) |
                4 => do_parse!(
                    parse_bits!(
                        u8, 5, rep_cntrl
                    ) >>
                    (SlowReverse(rep_cntrl))
                ) |
                _ => do_parse!(
                    parse_bits!(
                        u8, 5, field_id
                    ) >>
                    (Reserved(control << 5 | field_id))
                )
            ) >>
            (res)
        ))
    }
}

fn parse_header_extension(input: &[u8]) -> IResult<&[u8], HeaderExtension> {
    use HeaderExtension2::*;

    let mut ext = HeaderExtension::default();
    let mut private_data_flag = false;
    let mut pack_header_field_flag = false;
    let mut program_packet_sequence_counter_flag = false;
    let mut p_std_buffer_flag = false;
    let mut extension_flag_2 = false;

    let (input, (private_data, pack_header, counter, p_std_buffer, extension_2)) = bits!(
        input,
        do_parse!(
            parse_flags!(
                private_data_flag,
                pack_header_field_flag,
                program_packet_sequence_counter_flag,
                p_std_buffer_flag
            ) >>
            parse_bits!(
                _reserved, u8, 3, (),
                x, u8, 1, extension_flag_2 = x == 1
            ) >>
            private_data: cond!(private_data_flag, bytes!(slice!(16, take!(16)))) >>
            pack_header: cond!(pack_header_field_flag, bytes!(length_bytes!(call!(be_u8)))) >>
            counter: cond!(program_packet_sequence_counter_flag, do_parse!(
                verify!(take_bits!(u8, 1), |marker| marker == 1) >>
                counter: take_bits!(u8, 7) >>
                verify!(take_bits!(u8, 1), |marker| marker == 1) >>
                mpeg1_mpeg2_identifier: take_bits!(u8, 1) >>
                original_stuff_length: take_bits!(u8, 6) >>
                (ProgramPacketSequenceCounter {
                    counter,
                    mpeg1_mpeg2_identifier: mpeg1_mpeg2_identifier == 1,
                    original_stuff_length
                })
            )) >>
            p_std_buffer: cond!(p_std_buffer_flag, do_parse!(
                take_bits!(u8, 2) >>
                scale: take_bits!(u8, 1) >>
                size: take_bits!(u16, 13) >>
                (PSTDBuffer { scale, size })
            )) >>
            extension_2: cond!(extension_flag_2, do_parse!(
                take_bits!(u8, 1) >>
                len: verify!(take_bits!(u8, 7), |len| len >= 1) >>
                ext_2: bytes!(slice!(len, bits!(
                    switch!(take_bits!(u8, 1),
                        0 => map!(take_bits!(u8, 7), |x| Some(StreamIdExtension(x))) |
                        1 => do_parse!(
                            take_bits!(u8, 6) >>
                            tref_ext_flag: take_bits!(u8, 1) >>
                            tref: cond!(tref_ext_flag == 0, do_parse!(
                                take_bits!(u8, 4) >>
                                tref: map!(call!(parse_timestamp), |ts| TREF(ts)) >>
                                (tref)
                            )) >>
                            (tref)
                        ) |
                        _ => value!(None)
                        )
                ))) >>
                (ext_2)
            )) >>
            (private_data, pack_header, counter, p_std_buffer, extension_2)
        )
    )?;

    ext.private_data = private_data.map(|d| d.into());
    ext.pack_header = pack_header.map(|d| d.into());
    ext.program_packet_sequence_counter = counter;
    ext.p_std_buffer = p_std_buffer;
    ext.extension_2 = extension_2.unwrap_or(None);

    Ok((input, ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::writer;

    proptest! {
        #[test]
        fn test_header_extension(mut ext: HeaderExtension) {
            let mut buf = Vec::new();
            let len = writer::header_ext_len(&ext) as usize;
            buf.resize(len, 0);
            writer::write_header_ext(&ext, &mut buf).unwrap();
            assert_eq!(parse_header_extension(&buf), Ok((&buf[len..], ext)))
        }
        #[test]

        fn test_header(mut header: Header) {
            let mut buf = Vec::new();
            let len = writer::header_len(&header) as usize;
            buf.resize(len, 0);
            writer::write_header(&header, &mut buf).unwrap();
            let (input, (parsed_header, _data)) = parse_header_and_data(&buf)?;
            assert_eq!(parsed_header, header);
            assert_eq!(input, &buf[writer::header_len(&header) as usize..]);
        }

        #[test]
        fn test_packet(mut packet: Packet) {
            let mut buf = Vec::new();
            let len = writer::packet_len(&packet) as usize;
            packet.length = writer::pes_packet_len(&packet);
            buf.resize(len, 0);
            writer::write_packet(&packet, &[], &mut buf);
            let (input, (parsed_packet, _data)) = parse_packet(&buf)?;
            assert_eq!(parsed_packet, packet);
            assert_eq!(input, &buf[writer::packet_len(&packet) as usize..]);
        }
    }

    pub fn trick_mode_fast_forward() -> impl Strategy<Value = TrickMode> {
        (0..3u8, any::<bool>(), 0..3u8).prop_map(|(a, b, c)| {
            TrickMode::FastForward(a, b, c)
        })
    }

    pub fn trick_mode_slow_motion() -> impl Strategy<Value = TrickMode> {
        (0..2u8.pow(5)).prop_map(|v| TrickMode::SlowMotion(v))
    }

    pub fn trick_mode_freeze_frame() -> impl Strategy<Value = TrickMode> {
        (0..3u8).prop_map(|v| TrickMode::FreezeFrame(v))
    }

    pub fn trick_mode_fast_reverse() -> impl Strategy<Value = TrickMode> {
        (0..3u8, any::<bool>(), 0..3u8).prop_map(|(a, b, c)| {
            TrickMode::FastReverse(a, b, c)
        })
    }

    pub fn trick_mode_slow_reverse() -> impl Strategy<Value = TrickMode> {
        (0..2u8.pow(5)).prop_map(|v| TrickMode::SlowReverse(v))
    }

    pub fn trick_mode_reserved() -> impl Strategy<Value = TrickMode> {
        (0xA0..=0xFFu8).prop_map(|v| TrickMode::Reserved(v))
    }

    pub fn header_extension_2_stream_id() -> impl Strategy<Value = HeaderExtension2> {
        (0..2u8.pow(7)).prop_map(|v| HeaderExtension2::StreamIdExtension(v))
    }

    pub fn header_extension_2_tref() -> impl Strategy<Value = HeaderExtension2> {
        (0..2u64.pow(33)).prop_map(|v| HeaderExtension2::TREF(v))
    }

    pub fn packet_filter(packet: &Packet) -> bool {
        packet.stream_id.has_header() == packet.header.is_some()
    }
}