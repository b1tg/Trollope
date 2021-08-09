#![feature(exclusive_range_pattern)]

use std::convert::TryInto;
use std::convert::TryFrom;
use std::fmt;
//use std::fmt::Error;
struct Parser<'a> {
    input: &'a [u8]
}

#[derive(Debug)]
enum Register {
    Eax,
    Ebx,
    Ecx,
    Edx,
    IP,
    Eflags,
    Unknow,
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rstr = match self {
            Register::Eax => "eax",
            Register::Ebx => "ebx",
            Register::Ecx => "ecx",
            Register::Edx => "edx",
            Register::IP => "eip",
            Register::Eflags => "eflags",
            _ => "unknow",
        };
        write!(f, "{}", rstr)
    }
}

impl TryFrom<u8> for Register {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
            let res = match value {
                0b000 => Register::Eax,
                0b011 => Register::Ebx,
                0b001 => Register::Ecx,
                0b010 => Register::Edx,
                _ => Register::Unknow,
            };
            return Ok(res);
    }
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
            0x90 => println!("nop"),
            0xb8..0xc0 => {
                let reg_num = op0 - 0xb8;
                let reg:Register = reg_num.try_into().unwrap();
                let imm = u32::from_le_bytes(self.input[idx+1..idx+5].try_into().unwrap());
                println!("mov {}, {}", reg, imm);
                idx += 4;
            },
            0x89 => {
                let reg_n = self.input[idx+1];
                // >>> "{0:b}".format(195)
                // '11000011'
                let reg_l:Register = (reg_n & 0b11).try_into().unwrap();
                let reg_r:Register = (reg_n & 0b1100).try_into().unwrap();
                println!("mov {}, {}", reg_l, reg_r);
                idx += 6;
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

        let input = [0x90u8, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x89, 0xc3];
        let parser = Parser::new(&input);
        parser.parse();
    }
// { 0x90, 0xB8, 0x01, 0x00, 0x00, 0x00 }
// 0:  90                      nop
// 1:  b8 01 00 00 00          mov    eax,0x1

// 0:  b8 01 00 00 00          mov    eax,0x1
// 5:  89 c3                   mov    ebx,eax
}



// useful links:
// https://en.wikibooks.org/wiki/X86_Assembly/Machine_Language_Conversion
// https://defuse.ca/online-x86-assembler.htm#disassembly
// https://faydoc.tripod.com/cpu/mov.htm
