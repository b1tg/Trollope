#![feature(exclusive_range_pattern)]
 use std::convert::TryInto;
struct Parser<'a> {
    input: &'a [u8]
}

enum Register {
}


impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input: input,
        }
    }

    fn parse(&self) -> Result<(),()>{

        let mut idx = 0;
        loop {
            if idx >= self.input.len() {
                break;
            }
            let op0 = self.input[idx];
            dbg!(op0);
            match op0 {
            0x90 => println!("NOP"),
            0xb8..0xc0 => {
                let reg_num = op0 - 0xb8;
                let reg = match reg_num {
                    0 => "EAX",
                    1 => "EBX",
                    _ => "Unknow Register",
                };
                let imm = u32::from_le_bytes(self.input[idx+1..idx+5].try_into().unwrap());
                println!("MOV {}, {}", reg, imm);
                idx += 5;
                continue;

            },
            _ => println!("Unknow Op"),
            };
            idx +=1;
        }

        Ok(())
    }
}











#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);

        let input = [0x90u8, 0xb8, 0x01, 0x00, 0x00, 0x00];
        let parser = Parser::new(&input);
        parser.parse();
    }
// { 0x90, 0xB8, 0x01, 0x00, 0x00, 0x00 }
// 0:  90                      nop
// 1:  b8 01 00 00 00          mov    eax,0x1

}
