/*!
 * Adaptation field parser and types.
 */
use nom::{be_u8, bits, call, cond, do_parse, length_bytes, rest, take, take_bits, tap, IResult};
use crate::utils::parse_timestamp;

#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct PCR {
    #[cfg_attr(test, proptest(strategy = "0..2u64.pow(33)"))]
    pub base: u64,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(9)"))]
    pub extension: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct LTW {
    pub valid: bool,
    #[cfg_attr(test, proptest(strategy = "0..2u16.pow(15)"))]
    pub offset: u16,
}

#[derive(Copy, Debug, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct SeamlessSplice {
    #[cfg_attr(test, proptest(strategy = "0..2u8.pow(4)"))]
    pub splice_type: u8,
    #[cfg_attr(test, proptest(strategy = "0..2u64.pow(33)"))]
    pub dts_next_au: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct AdaptationFieldExtension {
    pub ltw: Option<LTW>,
    #[cfg_attr(test, proptest(strategy(piecewise_rate)))]
    pub piecewise_rate: Option<u32>,
    pub seamless_splice: Option<SeamlessSplice>,
    #[cfg_attr(test, proptest(strategy(data_vec)))]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct AdaptationField {
    #[cfg_attr(test, proptest(value = "false"))]
    pub discontinuity_indicator: bool,
    pub random_access_indicator: bool,
    pub elementary_stream_priority_indicator: bool,
    pub program_clock_reference: Option<PCR>,
    pub original_program_clock_reference: Option<PCR>,
    pub splice_countdown: Option<u8>,
    #[cfg_attr(test, proptest(strategy(data_vec)))]
    pub transport_private_data: Option<Vec<u8>>,
    pub extension: Option<AdaptationFieldExtension>,
    // FIXME
    #[cfg_attr(test, proptest(value = "0u8"))]
    pub stuffing_length: u8,
}

/// Parse the adaptation field part of a packet.
///
/// This is the low level nom parser. You most likely want to use one of
/// [`ReaderParser`](struct.ReaderParser.html) and [`Parser`](struct.Parser.html)
/// instead.
pub fn parse_adaptation_field(
    input: &[u8],
) -> IResult<&[u8], Option<AdaptationField>> {
    let mut af = AdaptationField::default();

    let mut pcr_flag = false;
    let mut opcr_flag = false;
    let mut transport_private_data_flag = false;
    let mut splicing_point_flag = false;
    let mut extension_flag = false;
    let (input, length) = do_parse!(input,
        length: call!(be_u8) >>
        cond!(length > 0,
            slice!(length,
                do_parse!(
                    bits!(
                        parse_flags!(
                            af.discontinuity_indicator,
                            af.random_access_indicator,
                            af.elementary_stream_priority_indicator,
                            pcr_flag,
                            opcr_flag,
                            splicing_point_flag,
                            transport_private_data_flag,
                            extension_flag
                        )
                    ) >>
                    cond!(pcr_flag, call!(parse_pcr, &mut af.program_clock_reference)) >>
                    cond!(opcr_flag, call!(parse_pcr, &mut af.original_program_clock_reference)) >>
                    cond!(splicing_point_flag, bits!(parse_bits!(x, u8, 8, af.splice_countdown = Some(x)))) >>
                    cond!(transport_private_data_flag,
                        tap!(data: length_bytes!(be_u8) => af.transport_private_data = Some(data.to_vec()))
                    ) >>
                    cond!(extension_flag, call!(parse_extension, &mut af.extension)) >>
                    tap!(s: call!(rest) => af.stuffing_length = s.len() as u8) >>
                    ()
                )
            )
        ) >>
        (length)
    )?;

    return if length > 0 {
        Ok((input, Some(af)))
    } else {
        Ok((input, None))
    };

    fn parse_pcr<'a>(
        input: &'a [u8],
        opt: &mut Option<PCR>,
    ) -> IResult<&'a [u8], ()> {
        let mut pcr = PCR { base: 0, extension: 0};

        let (input, _) = bits!(input, parse_bits!(
            u64, 33, pcr.base,
            _reserved, u8, 6, (),
            u16, 9, pcr.extension
        ))?;

        *opt = Some(pcr);

        Ok((input, ()))
    }

    fn parse_extension<'a>(
        input: &'a [u8],
        opt: &mut Option<AdaptationFieldExtension>,
    ) -> IResult<&'a [u8], ()> {
        let mut ltw_flag = false;
        let mut piecewise_rate_flag = false;
        let mut seamless_splice_flag = false;
        let mut ltw = LTW {
            valid: false,
            offset: 0,
        };
        let mut piecewise_rate = 0u32;
        let mut splice = SeamlessSplice {
            splice_type: 0,
            dts_next_au: 0,
        };

        let (input, data) = do_parse!(input,
            extension_length: call!(be_u8) >>
            len_at_start: input_len!() >>
            bits!(
                do_parse!(
                    parse_flags!(
                        ltw_flag,
                        piecewise_rate_flag,
                        seamless_splice_flag
                    ) >>
                    parse_bits!(_reserved, u8, 5, ()) >>
                    cond!(ltw_flag, parse_bits!(
                        x, u8, 1, ltw.valid = x == 1,
                        u16, 15, ltw.offset
                    )) >>
                    cond!(piecewise_rate_flag, parse_bits!(
                        _reserved, u8, 2, (),
                        u32, 22, piecewise_rate
                    )) >>
                    cond!(seamless_splice_flag,
                        tap!(res: call!(parse_splice) => splice = res)
                    ) >>
                    ()
                )
            ) >>
            remaining_len: input_len!() >>
            data: take!(extension_length as usize - (len_at_start - remaining_len)) >>
            (data)
        )?;

        *opt = Some(AdaptationFieldExtension {
            ltw: if ltw_flag { Some(ltw) } else { None },
            piecewise_rate: if piecewise_rate_flag { Some(piecewise_rate) } else { None },
            seamless_splice: if seamless_splice_flag { Some(splice) } else { None },
            data: if data.len() > 0 { Some(data.to_vec()) } else { None }
        });

        Ok((input, ()))
    }

    fn parse_splice(input: (&[u8], usize)) -> IResult<(&[u8], usize), SeamlessSplice> {
        let (input, (splice_type, dts_next_au)) = do_parse!(input,
            splice_type: take_bits!(u8, 4) >>
            dts_next_au: call!(parse_timestamp) >>
            (splice_type, dts_next_au)
        )?;

        Ok((
            input,
            SeamlessSplice {
                splice_type,
                dts_next_au,
            },
        ))
    }
}

#[cfg(test)]
fn data_vec() -> impl Strategy<Value = Option<Vec<u8>>> {
    proptest::collection::vec(any::<u8>(), 0..10).prop_map(|data| {
        if data.len() > 0 {
            Some(data)
        } else {
            None
        }
    })
}

#[cfg(test)]
fn piecewise_rate() -> impl Strategy<Value = Option<u32>> {
    (any::<Option<u32>>(), 0..2u32.pow(22)).prop_map(|(opt, val)| match opt {
        None => None,
        _ => Some(val),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts::writer;

    proptest! {
        #[test]
        fn test_adaptation_field(af: AdaptationField) {
            let mut buf = Vec::new();
            let len = writer::adaptation_field_len(&af) as usize;
            buf.resize(len + 1, 0);
            writer::write_adaptation_field(&af, &mut buf).unwrap();
            assert_eq!(parse_adaptation_field(&buf), Ok((&buf[len + 1..], Some(af))))
        }
    }
}
