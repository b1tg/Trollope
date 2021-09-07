use nom::error::ErrorKind;
use nom::error::ParseError;
use nom::number::complete::*;
use nom::{
    bytes::complete::{tag, take, take_while_m_n},
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

#[derive(Debug, PartialEq)]
pub struct EXTHHeader {
    identify: u32, // "EXTH"
    header_len: u32,
    record_count: u32,
    exth_records: Vec<EXTHRecord>,
}

#[derive(Debug, PartialEq)]
pub struct EXTHRecord {
    record_type: u32,
    record_len: u32,
    data: u32, // TODO
}

#[derive(Debug, PartialEq)]
pub struct MOBIHeader {
    identify: String,
    header_len: u32,
    mobi_type: u32,
    text_encoding: u32,
    uid: u32,
    file_version: u32,
    ortographic_index: u32,
    inflection_index: u32,
    index_names: u32,
    index_keys: u32,
    extra_index0: u32,
    extra_index1: u32,
    extra_index2: u32,
    extra_index3: u32,
    extra_index4: u32,
    extra_index5: u32,
    first_non_book_index: u32,
    full_name_offset: u32,
    full_name_length: u32,
    locale: u32,
    input_lan: u32,
    output_lan: u32,
    min_ver: u32,
    first_image_index: u32,
    huffman_record_offset: u32,
    huffman_record_count: u32,
    huffman_table_offset: u32,
    huffman_table_length: u32,
    exth_flags: u32,
    unknow1: [u8; 32],
    unknow2: [u8; 4],
    drm_offset: u32,
    drm_count: u32,
    drm_size: u32,
    drm_flags: u32,
    unknow3: [u8; 8],
    first_content_record_number: u16,
    last_content_record_number: u16,
    unknow4: u32,
    fcis_record_number: u32,
    fcis_record_count: u32,
    flis_record_number: u32,
    flis_record_count: u32,
    unknow5: [u8; 8],
    unknow6: [u8; 4],
    first_compilation_data_section_count: u32,
    number_of_compilation_data_sections: u32,
    unknow7: u32,
    extra_record_data_flags: u32,
    indx_record_offset: u32,
    unknow8: u32,
    unknow9: u32,
    unknowa: u32,
    unknowb: u32,
    unknowc: u32,
    unknowd: u32,
}
// pub fn eat_one(input: &str) -> IResult<&str, ()> {

//     Ok(("", ())

// }
fn eat_3(input: &[u8]) -> IResult<&[u8], u32, ()> {
    // let a0 = input[0];
    //
    // let a1 = input[1];
    // let a2 = input[2];
    let (res, tree) = take::<_, _, ()>(3usize)(input).unwrap();
    let meat = [input[0], input[1], input[2], 0];

    let num = u32::from_be_bytes(meat);
    // let num = be_u32::<_, _>(meat).unwrap().1;
    return Ok((res, num));
}

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
        let parser_u16 = |s: &[u8]| be_u16::<_, ()>(s).unwrap().1;

        // let num_of_records = u16::from_be_bytes((&buf[76..76 + 2]).try_into().unwrap()); // 563
        // let num_of_records = be_u16::<_, ()>(&buf[76..]).unwrap().1;
        // let offset = be_u32::<_, ()>(&buf[78..]).unwrap().1;
        // let attr = be_u8::<_, ()>(&buf[82..]).unwrap().1;

        let num_of_records = be_u16::<_, ()>(&buf[76..]).unwrap().1;
        let mut off = 0;
        println!("num_of_records: {}", &num_of_records);
        let mut contents: Vec<u8> = vec![];
        for i in 0..num_of_records {
            let (offset, attr, uid) =
                tuple::<_, _, (), _>((be_u32, be_u8, eat_3))(&buf[76 + 2 + off..])
                    .unwrap()
                    .1;
            //dbg!(&num_of_records, &offset, &attr, &uid);
            //if i>=240 && i< 252 {
            if i < 10 {
                println!("{}, {}, {}", &offset, &attr, &uid);
                //break;
            }
            if i < 5 {
                // otherwise there would be code issue
                contents.extend_from_slice(&buf[offset as usize..offset as usize + 4096]);
                // let content = String::from_utf8_lossy(&buf[offset as usize..offset as usize+4096+2]);
            }
            off += 8;
        }
        let contents_str = String::from_utf8_lossy(&contents);
        println!("contents: {}", &contents_str);
        let (offset, attr, uid) = tuple::<_, _, (), _>((be_u32, be_u8, eat_3))(&buf[76 + 2..])
            .unwrap()
            .1;

        dbg!(&num_of_records, &offset, &attr, &uid);

        let (
            compression,
            _,
            text_len,
            record_count,
            record_size,
            cur_pos,
            identify,
            header_len,
            mobi_type,
            text_encoding,
        ) = tuple::<_, _, (), _>((
            be_u16,
            be_u16,
            be_u32,
            be_u16,
            be_u16,
            be_u32,
            take(4usize),
            be_u32,
            be_u32,
            be_u32,
        ))(&buf[offset as usize..])
        .unwrap()
        .1;

        let first_image_index = be_u32::<_, ()>(&buf[offset as usize + 108..]).unwrap().1;
        let first_content_record_number = be_u16::<_, ()>(&buf[offset as usize + 192..]).unwrap().1;
        let last_content_record_number = be_u16::<_, ()>(&buf[offset as usize + 194..]).unwrap().1;
        let fcis_record_number = be_u32::<_, ()>(&buf[offset as usize + 200..]).unwrap().1;
        let flis_record_number = be_u32::<_, ()>(&buf[offset as usize + 208..]).unwrap().1;

        let indx_record_offset = be_u32::<_, ()>(&buf[offset as usize + 244..]).unwrap().1;

        println!(
            "{} => {} => {}",
            first_content_record_number, last_content_record_number, indx_record_offset
        );
        dbg!(&first_image_index);
        dbg!(&fcis_record_number);
        dbg!(&flis_record_number);

        let identify = String::from_utf8_lossy(identify);

        assert_eq!(4096, record_size);
        assert_eq!(&identify, "MOBI");
        dbg!(
            compression,
            text_len,
            record_count,
            record_size,
            cur_pos,
            identify,
            header_len,
            mobi_type,
            text_encoding
        );

        let exth_flags = be_u32::<_, ()>(&buf[offset as usize + 128..]).unwrap().1;
        dbg!(&exth_flags & 0x0040);
        if &exth_flags & 0x0040 == 0x0040 {
            println!("there's an EXTH record");
        }

        // let uid = be_u32::<_, ()>([&buf[83..83+3]).unwrap().1;
        // let uid = 0;
        // let header = &buf[0..16];

        // let compression = &heaer[0..2];

        // let compression = u16::from_be_bytes(compression.try_into().unwrap());
        // dbg!(&compression);
    }
}
