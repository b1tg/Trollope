#![feature(exclusive_range_pattern)]

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
//use std::fmt::Error;
struct Parser<'a> {
    input: &'a [u8],
}

#[derive(Debug)]
enum Register {
    Eax,
    Ebx,
    Ecx,
    Edx,
    Esi,
    Ebp,
    IP,
    Eflags,
    Unknow,
}

impl Register {
    fn to_str(self, width: u8) -> &'static str {
        match width {
            16 => match self {
                Register::Eax => "ax",
                Register::Ebx => "bx",
                Register::Ecx => "cx",
                Register::Edx => "dx",
                Register::Esi => "si",
                Register::Ebp => "bp",
                Register::IP => "ip",
                Register::Eflags => "eflags",
                _ => "unknow",
            },
            _ => match self {
                Register::Eax => "eax",
                Register::Ebx => "ebx",
                Register::Ecx => "ecx",
                Register::Edx => "edx",
                Register::Esi => "esi",
                Register::Ebp => "ebp",
                Register::IP => "eip",
                Register::Eflags => "eflags",
                _ => "unknow",
            },
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
            0b110 => Register::Esi,
            0b101 => Register::Ebp,
            // 0b111 => Register::Edi,
            _ => Register::Unknow,
        };
        return Ok(res);
    }
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input: input }
    }

    fn parse(&self) -> Result<Vec<String>, ()> {
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
                0x31 => {
                    // 31 /r
                    let mod_rm = self.input[idx];
                    idx += 1;
                    let mod1: u8 = ((mod_rm & 0b11000000) >> 6).try_into().unwrap();
                    let reg: Register = ((mod_rm & 0b00111000) >> 3).try_into().unwrap();
                    let rm: Register = (mod_rm & 0b00000111).try_into().unwrap();
                    let mut offset = 0u32;
                    if mod1 == 0 {
                        offset = 0;
                    } else if mod1 == 0b01 {
                        offset = self.input[idx].into();
                        idx += 1;
                        // mov    esi,DWORD PTR [ebp+0x8]
                    } else if mod1 == 0b10 {
                        offset = u32::from_le_bytes(self.input[idx..idx + 4].try_into().unwrap());
                        idx += 4;
                    } else if mod1 == 0b11 {
                    }

                    let tmp = {
                        if offset == 0 {
                            if mod1 == 0b11 {
                                format!("xor {}, {}", reg.to_str(width), rm.to_str(width))
                            } else {
                                format!(
                                    "xor {}, DWORD PTR [{}]",
                                    reg.to_str(width),
                                    rm.to_str(width)
                                )
                            }
                        } else {
                            format!(
                                "xor {}, DWORD PTR [{}+0x{:x}]",
                                reg.to_str(width),
                                rm.to_str(width),
                                offset
                            )
                        }
                    };
                    result.push(tmp.to_string());
                }
                0x66 => {
                    width = 16;
                    continue;
                }
                0x90 => {
                    result.push("nop".to_string());
                }
                0xb8..0xc0 => {
                    let reg_num = op0 - 0xb8;
                    let reg: Register = reg_num.try_into().unwrap();
                    let imm = u32::from_le_bytes(self.input[idx..idx + 4].try_into().unwrap());
                    let tmp = format!("mov {}, 0x{:x}", reg.to_str(width), imm);
                    result.push(tmp.to_string());
                    idx += 4;
                }
                0x89 => {
                    let reg_n = self.input[idx];
                    idx += 1;
                    // >>> "{0:b}".format(195) # 0xc3 == 195
                    // '11000011'
                    let reg_l: Register = (reg_n & 0b11).try_into().unwrap();
                    let reg_r: Register = (reg_n & 0b1100).try_into().unwrap();
                    let tmp = format!("mov {}, {}", reg_l.to_str(width), reg_r.to_str(width));
                    result.push(tmp.to_string());
                }
                0x8B => {
                    // 8B /r
                    // 0x75 01110101 7 5
                    // mod = 01
                    // reg = 110 esi
                    // rm = 101 [EBP]+disp8
                    let mod_rm = self.input[idx];
                    idx += 1;
                    let mod1: u8 = ((mod_rm & 0b11000000) >> 6).try_into().unwrap();
                    let reg: Register = ((mod_rm & 0b00111000) >> 3).try_into().unwrap();
                    let rm: Register = (mod_rm & 0b00000111).try_into().unwrap();

                    let mut offset = 0u32;
                    if mod1 == 0 {
                        offset = 0;
                    } else if mod1 == 0b01 {
                        offset = self.input[idx].into();
                        idx += 1;
                        // mov    esi,DWORD PTR [ebp+0x8]
                    } else if mod1 == 0b10 {
                        offset = u32::from_le_bytes(self.input[idx..idx + 4].try_into().unwrap());
                        idx += 4;
                    } else if mod1 == 0b11 {
                        unimplemented!();
                    }

                    let tmp = {
                        if offset == 0 {
                            format!(
                                "mov {}, DWORD PTR [{}]",
                                reg.to_str(width),
                                rm.to_str(width)
                            )
                        } else {
                            format!(
                                "mov {}, DWORD PTR [{}+0x{:x}]",
                                reg.to_str(width),
                                rm.to_str(width),
                                offset
                            )
                        }
                    };
                    result.push(tmp.to_string());
                }
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
        assert_eq!(
            output.unwrap(),
            vec![
                "nop".to_string(),
                "mov eax, 0x1".to_string(),
                "mov ebx, eax".to_string()
            ]
        );

        let input = [0x89u8, 0xc3, 0x66, 0x89, 0xc3];
        let parser = Parser::new(&input);
        let output = parser.parse();
        assert_eq!(
            output.unwrap(),
            vec!["mov ebx, eax".to_string(), "mov bx, ax".to_string()]
        );

        //  { 0x8B, 0x75, 0x08, 0x31, 0xC9, 0x8B, 0x06 }
        // 0:  8b 75 08                mov    esi,DWORD PTR [ebp+0x8]
        // 3:  31 c9                   xor    ecx,ecx
        // 5:  8b 06                   mov    eax,DWORD PTR [esi]
        let input = [0x8B, 0x75, 0x08, 0x31, 0xC9, 0x8B, 0x06];
        let parser = Parser::new(&input);
        let output = parser.parse();
        assert_eq!(
            output.unwrap(),
            vec![
                "mov esi, DWORD PTR [ebp+0x8]".to_string(),
                "xor ecx, ecx".to_string(),
                "mov eax, DWORD PTR [esi]".to_string(),
            ]
        );
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
// P40 Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte
// https://web.archive.org/web/20150212055048/http://x86.renejeschke.de/html/file_module_x86_id_176.html
