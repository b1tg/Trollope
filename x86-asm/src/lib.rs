#![feature(exclusive_range_pattern)]

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
//use std::fmt::Error;
struct Parser<'a> {
    input: &'a [u8],
}

#[derive(Debug, PartialEq)]
enum Register {
    Eax,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Ebp,
    Esi,
    Edi,
    IP,
    Eflags,
    Unknow,
}

impl Register {
    fn to_str(self, width: u8) -> &'static str {
        match width {
            16 => match self {
                Register::Eax => "ax",
                Register::Ecx => "cx",
                Register::Edx => "dx",
                Register::Ebx => "bx",
                Register::Esp => "sp",
                Register::Ebp => "bp",
                Register::Esi => "si",
                Register::Edi => "di",
                Register::IP => "ip",
                Register::Eflags => "eflags",
                _ => "unknow",
            },
            _ => match self {
                Register::Eax => "eax",
                Register::Ecx => "ecx",
                Register::Edx => "edx",
                Register::Ebx => "ebx",
                Register::Esp => "esp",
                Register::Ebp => "ebp",
                Register::Esi => "esi",
                Register::Edi => "edi",
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
            0b001 => Register::Ecx,
            0b010 => Register::Edx,
            0b011 => Register::Ebx,
            0b100 => Register::Esp,
            0b101 => Register::Ebp,
            0b110 => Register::Esi,
            0b111 => Register::Edi,
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
                0xC0..=0xCF => match op0 {
                    0xC3 => {
                        result.push("ret".to_string());
                    }
                    _ => {
                        unimplemented!()
                    }
                },
                0x50..=0x5F => {
                    // PUSH/POP
                    let action = if op0 < 0x58 { "push" } else { "pop" };
                    let reg: Register = if op0 < 0x58 {
                        (op0 - 0x50).try_into().unwrap()
                    } else {
                        (op0 - 0x58).try_into().unwrap()
                    };
                    let tmp = format!("{} {}", action, reg.to_str(width));
                    result.push(tmp.to_string());
                }
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
                    // 89 /r
                    // MOV r/m32,r32

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
                        // unimplemented!();
                    }

                    let tmp = {
                        if offset == 0 {
                            if mod1 == 0b11 {
                                format!("mov {}, {}", rm.to_str(width), reg.to_str(width))
                            } else {
                                format!(
                                    "mov DWORD PTR [{}], {}",
                                    rm.to_str(width),
                                    reg.to_str(width)
                                )
                            }
                        } else {
                            format!(
                                "mov DWORD PTR [{}+0x{:x}], {}",
                                rm.to_str(width),
                                offset,
                                reg.to_str(width)
                            )
                        }
                    };
                    result.push(tmp.to_string());
                }
                0x8B => {
                    // 8B /r
                    // MOV r32,r/m32
                    // 0x75 01110101 7 5
                    // mod = 01
                    // reg = 110 esi
                    // rm = 101 [EBP]+disp8

                    // 0x44 1000100
                    // mod = 01
                    // reg = 000
                    // rm = 100
                    let mod_rm = self.input[idx];
                    idx += 1;
                    let mod1: u8 = ((mod_rm & 0b11000000) >> 6).try_into().unwrap();
                    let reg: Register = ((mod_rm & 0b00111000) >> 3).try_into().unwrap();
                    let mut rm: Register = (mod_rm & 0b00000111).try_into().unwrap();
                    // let mut rm: Register = rm1;
                    let mut scale_factor: u8 = 0;
                    let mut index: u8 = 0;
                    // If rm == 0x100, means a SIB follows the ModR/M byte
                    // P40 Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte (NOTES 1)

                    // register [0..3]
                    // Indicate the register used as the index (SIB byte bits 3, 4 and 5)
                    // and the scaling factor (determined by SIB byte bits 6 and 7)
                    let mut has_sib = false;
                    if rm == Register::Esp {
                        // 0x100
                        let sib = self.input[idx];
                        idx += 1;
                        // 00100100
                        scale_factor = (sib & 0b11000000) >> 6;
                        index = (sib & 0b00111000) >> 3;
                        rm = (sib & 0b00000111).try_into().unwrap();
                        has_sib = true;
                    }
                    // let mut right = "".to_string();
                    // if scale_factor == 0b00 {
                    //     right = format!("[{}]", rm.to_str(width));
                    // } else {
                    //     let scale = 2u8.pow(scale_factor.into());
                    //     right = format!("[{}*{}]", rm.to_str(width), scale);
                    // }
                    // let tmp = format!("mov {}, {}", reg.to_str(width), right);
                    // result.push(tmp.to_string());
                    // } else {
                    let mut offset = 0u32;
                    if mod1 == 0b00 {
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
                    let mut right = "".to_string();

                    if has_sib {
                        if scale_factor == 0b00 {
                            right = format!("{}", rm.to_str(width));
                        } else {
                            let scale = 2u8.pow(scale_factor.into());
                            right = format!("{}*{}", rm.to_str(width), scale);
                        }
                    } else {
                        right = format!("{}", rm.to_str(width));
                    }
                    if offset > 0 {
                        right = format!("{}+0x{:x}", right, offset);
                    } else if offset < 0 {
                        unimplemented!()
                    } else {
                        right = format!("{}", right);
                    }
                    let tmp = format!("mov {}, DWORD PTR [{}]", reg.to_str(width), right);
                    // let tmp = {
                    //     if offset == 0 {
                    //         format!(
                    //             "mov {}, DWORD PTR [{}]",
                    //             reg.to_str(width),
                    //             rm.to_str(width)
                    //         )
                    //     } else {
                    //         format!(
                    //             "mov {}, DWORD PTR [{}+0x{:x}]",
                    //             reg.to_str(width),
                    //             rm.to_str(width),
                    //             offset
                    //         )
                    //     }
                    // };
                    result.push(tmp.to_string());
                    // }
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

        // { 0x90, 0xB8, 0x01, 0x00, 0x00, 0x00 }
        // 0:  90                      nop
        // 1:  b8 01 00 00 00          mov    eax,0x1

        // 0:  b8 01 00 00 00          mov    eax,0x1
        // 5:  89 c3                   mov    ebx,eax

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

        // 0:  89 c3                   mov    ebx,eax
        // 2:  66 89 c3                mov    bx,ax

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

        // 0:  50                      push   eax
        // 1:  8b 44 24 08             mov    eax,DWORD PTR [esp+0x8]
        // 5:  89 04 24                mov    DWORD PTR [esp],eax
        // 8:  8b 04 24                mov    eax,DWORD PTR [esp]
        // b:  0f af 04 24             imul   eax,DWORD PTR [esp]
        // f:  5a                      pop    edx
        // 10: c3                      ret

        let input = [
            0x50, 0x8B, 0x44, 0x24, 0x08, 0x89, 0x04, 0x24, 0x8B, 0x04, 0x24, 0x0F, 0xAF, 0x04,
            0x24, 0x5A, 0xC3,
        ];
        let parser = Parser::new(&input);
        let output = parser.parse();
        assert_eq!(
            output.unwrap(),
            vec![
                "push eax",
                "mov eax, DWORD PTR [esp+0x8]",
                "mov DWORD PTR [esp], eax",
                "mov eax, DWORD PTR [esp]",
                // "imul eax,DWORD PTR [esp]", // TODO
                "pop edx",
                "ret"

                // "mov esi, DWORD PTR [ebp+0x8]".to_string(),
                // "xor ecx, ecx".to_string(),
                // "mov eax, DWORD PTR [esi]".to_string(),
            ]
        );
    }
}

// useful links:
// https://en.wikibooks.org/wiki/X86_Assembly/Machine_Language_Conversion
// https://defuse.ca/online-x86-assembler.htm#disassembly
// https://faydoc.tripod.com/cpu/mov.htm
// https://nju-projectn.github.io/ics-pa-gitbook/ics2017/i386-intro.html
// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
// P40 Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte
// P2030 Table A-2. One-byte Opcode Map: (08H — FFH) *  PUSH/POP
// https://web.archive.org/web/20150212055048/http://x86.renejeschke.de/html/file_module_x86_id_176.html
