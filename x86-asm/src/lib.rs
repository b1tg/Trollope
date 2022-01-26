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

impl Register {
    fn to_str(self, width: u8) -> &'static str {
        match width {
            16 => {
                match self {
                    Register::Eax => "ax",
                    Register::Ebx => "bx",
                    Register::Ecx => "cx",
                    Register::Edx => "dx",
                    Register::IP => "ip",
                    Register::Eflags => "eflags",
                    _ => "unknow",            
                }
            }
            _ => {
                match self {
                    Register::Eax => "eax",
                    Register::Ebx => "ebx",
                    Register::Ecx => "ecx",
                    Register::Edx => "edx",
                    Register::IP => "eip",
                    Register::Eflags => "eflags",
                    _ => "unknow",            
                }                
            }
        }
    }
}
// impl fmt::Display for Register {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let rstr = match self {
//             Register::Eax => "eax",
//             Register::Ebx => "ebx",
//             Register::Ecx => "ecx",
//             Register::Edx => "edx",
//             Register::IP => "eip",
//             Register::Eflags => "eflags",
//             _ => "unknow",
//         };
//         write!(f, "{}", rstr)
//     }
// }

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

    fn parse(&self) -> Result<Vec<String>,()>{
        let mut idx = 0;
        let mut result: Vec<String> = vec![];
        let mut width = 32;
        loop {
            if idx >= self.input.len() {
                break;
            }
            let op0 = self.input[idx];
            println!("0x{:x}", op0);
            idx += 1;

            match op0 {
            0x66 => {
                width = 16;
                continue;
            },
            0x90 => {
                result.push("nop".to_string());
            },
            0xb8..0xc0 => {
                let reg_num = op0 - 0xb8;
                let reg:Register = reg_num.try_into().unwrap();
                let imm = u32::from_le_bytes(self.input[idx..idx+4].try_into().unwrap());
                let tmp = format!("mov {}, 0x{:x}", reg.to_str(width), imm);
                result.push(tmp.to_string());
                idx += 4;
            },
            0x89 => {
                let reg_n = self.input[idx];
                idx += 1;
                // >>> "{0:b}".format(195) # 0xc3 == 195
                // '11000011'
                let reg_l:Register = (reg_n & 0b11).try_into().unwrap();
                let reg_r:Register = (reg_n & 0b1100).try_into().unwrap();
                let tmp = format!("mov {}, {}", reg_l.to_str(width), reg_r.to_str(width));
                result.push(tmp.to_string());
                
            },
            _ => println!("Unknow Op"),
            };
        }
        Ok(result)
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
        let output = parser.parse();
        assert_eq!(output.unwrap(), vec!["nop".to_string(), "mov eax, 0x1".to_string(), "mov ebx, eax".to_string()]);

        let input = [0x89u8, 0xc3, 0x66, 0x89, 0xc3];
        let parser = Parser::new(&input);
        let output = parser.parse();
        assert_eq!(output.unwrap(), vec!["mov ebx, eax".to_string(), "mov bx, ax".to_string()])


    }
// { 0x90, 0xB8, 0x01, 0x00, 0x00, 0x00 }
// 0:  90                      nop
// 1:  b8 01 00 00 00          mov    eax,0x1

// 0:  b8 01 00 00 00          mov    eax,0x1
// 5:  89 c3                   mov    ebx,eax

// 0:  89 c3                   mov    ebx,eax
// 2:  66 89 c3                mov    bx,ax 
}



// useful links:
// https://en.wikibooks.org/wiki/X86_Assembly/Machine_Language_Conversion
// https://defuse.ca/online-x86-assembler.htm#disassembly
// https://faydoc.tripod.com/cpu/mov.htm
// https://nju-projectn.github.io/ics-pa-gitbook/ics2017/i386-intro.html
// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
// https://web.archive.org/web/20150212055048/http://x86.renejeschke.de/html/file_module_x86_id_176.html