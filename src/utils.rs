use nom::{do_parse, tag_bits, take_bits, IResult};

#[doc(hidden)]
#[macro_export]
macro_rules! parse_bits {
    ($input:expr, $name:ident, $type:ty, $bitcount:expr, $e:expr, $($rest:tt)+) => (
        match $crate::parse_bits!($input, $name, $type, $bitcount, $e) {
            Err(err) => Err(err),
            Ok(res) => {
                $crate::parse_bits!(res.0, $($rest)+)
            }
        }
    );
    ($input:expr, $name:ident, $type:ty, $bitcount:expr, $e:expr) => (
        {
            let res = match nom::take_bits!($input, $type, $bitcount) {
                Err(err) => Err(err),
                Ok(res) => {
                    let $name = res.1;
                    $e;
                    Ok(res)
                }
              };
            res
        }
    );
    ($input:expr, $type:tt, $bitcount:expr, $e:expr, $($rest:tt)+) => (
        $crate::parse_bits!($input, x, $type, $bitcount, $e = x, $($rest)+)
    );
    ($input:expr, $type:tt, $bitcount:expr, $e:expr) => (
        $crate::parse_bits!($input, x, $type, $bitcount, $e = x)
    )
}

#[doc(hidden)]
#[macro_export]
macro_rules! parse_flags {
    ($input:ident, $($flag:expr),+) => {
        $crate::parse_bits!($input, $(
            x, u8, 1, $flag = x == 1
        ),+)
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! input_len {
    ($input:ident,) => {{
        Ok(($input, $input.len()))
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! print {
    ($input:ident, $($args:expr),+) => (
        {
            println!($($args),+);
            Ok(($input, ()))
        }
    )
}

#[doc(hidden)]
#[macro_export]
macro_rules! slice {
    ($i:ident, $len:expr, $submac:ident!( $($args:tt)* )) => (
        {
            let (rest, sub) = take!($i, $len)?;
            match nom::complete!(sub, $submac!($($args)*)) {
                Ok((_, result)) => Ok((rest, result)),
                Err(e) => Err(e)
            }
        }
    );
}

pub fn parse_timestamp(input: (&[u8], usize)) -> IResult<(&[u8], usize), u64> {
    do_parse!(input,
        high: take_bits!(u64, 3) >>
        tag_bits!(u8, 1, 1) >>
        mid: take_bits!(u64, 15) >>
        tag_bits!(u8, 1, 1) >>
        low: take_bits!(u64, 15) >>
        tag_bits!(u8, 1, 1) >>
        (high << 30 | mid << 15 | low)
    )
}

pub fn format_timestamp(ts: u64) -> u64 {
    let ts = (ts & 0x1c0000000) << 3
        | 1 << 32
        | (ts & 0x3FFF8000) << 2
        | 1 << 16
        | (ts & 0x7FFF) << 1
        | 1;

    ts
}

#[cfg(test)]
mod tests {
    use nom::{do_parse, tag, bits};

    #[test]
    fn test_parse_bits() {
        let mut a = 0;
        let mut b = 0;
        struct C {
            c: u16
        };
        let mut c = C { c: 0 };
        let input: &[u8] = &[0xa, 0xbc, 0xde, 0xf0, 0x1];
        do_parse!(input,
            tag!([0xa]) >>
            bits!(
                parse_bits!(
                    u8, 4, a,
                    u8, 4, b,
                    u16, 12, c.c
                )
            ) >>
            tag!([0x1]) >>
            ()
        ).unwrap();
        assert_eq!(a, 0xb);
        assert_eq!(b, 0xc);
        assert_eq!(c.c, 0xdef);
    }
}
