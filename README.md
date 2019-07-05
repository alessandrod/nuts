nuts
====
A Rust library to parse MPEG Transport Streams. 

Early stages but the bulk of the format is implemented and parsing is pretty
robust. There are no major known bugs and as it is today the crate includes
enough functionality to implement fully functional parsers and demuxers.

The API is still unstable and is going to change.

# Installation

Add `nuts` to your `Cargo.toml`:

```ignore
[dependencies]
nuts = "0.1"
```

# Documentation

The reference documentation is at http://docs.rs/nuts

# Example 

This example implements a function called `dump` which parses all the packets
from a transport stream file and prints out some fields. For a similar but
more complete example, see `src/examples/nuts-dump.rs`.
```rust
use nuts::ts;
use std::fs::File;

fn dump(filename: &str) {
    let file = File::open(filename).unwrap();
    let mut parser = ts::ReaderParser::new(file);
    loop {
        match parser.parse() {
            Ok(Some((input, (packet, data)))) => match data {
                ts::Data::PSI(s) => println!("found PSI: {:?}", s),
                ts::Data::PES(pes_packet, payload) => println!(
                    "found PES packet, pid: {}, size: {}",
                    packet.pid,
                    payload.len()
                ),
                ts::Data::Data(payload) => println!(
                    "found payload packet, pid: {}, size: {}",
                    packet.pid,
                    payload.len()
                ),
            },
            Ok(None) => break,
            Err(e) => {
                if let Err(e) = parser.recover(e) {
                    println!("error: {}", e);
                    break;
                }
            }
        }
    }
}
```