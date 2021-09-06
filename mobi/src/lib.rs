use nom::{
    bytes::complete::{tag, take_while_m_n},
    combinator::map_res,
    sequence::tuple,
    IResult,
};
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, PartialEq)]
pub struct PalmDOCHeader {
    compression: u8,  // 0 (2)
    unused1: u8,      // 2 (2)
    text_len: u8,     // 4 (4)
    record_count: u8, // 8 (2)
    record_size: u8,  // 10 (2)
    cur_pos: u8,      // 12 (4)
}
// pub fn eat_one(input: &str) -> IResult<&str, ()> {

//     Ok(("", ())

// }

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn it_works() {
        let mobi_path = "./existentialist.mobi";
        let mut mobi = File::open(mobi_path).unwrap();
        let mut buf = vec![];
        mobi.read_to_end(&mut buf);

        // dbg!(&buf[0..16]);
        //
        let doc_type = String::from_utf8_lossy(&buf[60..64]);
        dbg!(&doc_type);
        assert_eq!(doc_type.to_string(), "BOOK");

        let doc_creator = String::from_utf8_lossy(&buf[64..68]);
        dbg!(&doc_creator);
        assert_eq!(doc_creator.to_string(), "MOBI");

        // let header = &buf[0..16];

        // let compression = &header[0..2];

        // dbg!(&compression);
        // let compression = u16::from_be_bytes(compression.try_into().unwrap());
        // dbg!(&compression);
    }
}
