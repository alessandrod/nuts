/*!
 * Transport Stream parsers and utils.
 */
#[doc(inline)]
pub mod adaptation_field;
mod packet;
mod parser;
pub mod psi;
#[doc(hidden)]
pub mod writer;

#[doc(inline)]
pub use packet::{discover_packet_size, parse_packet, sync, AdaptationFieldControl, Packet};
#[doc(inline)]
pub use parser::{Data, Parser, ParserError, ReaderParser, ReaderParserError};
