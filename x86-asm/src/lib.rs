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
    Undefined,
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
            _ => Register::Undefined,
        };
        return Ok(res);
    }
}

#[derive(Debug, PartialEq)]
struct ModRM {
    has_ptr: bool,
    // mode: u8,
    reg: Register,
    base_reg: Register,
    // SIB
    scale_factor: u8,
    index_reg: Register,
    offset: i32,
}

impl ModRM {
    fn from_u8(src: &[u8], idx_ptr: &mut usize) -> Self {
        // let mut idx = 0;
        let mut idx = *idx_ptr;
        let mod_rm = src[idx];
        idx += 1;
        let mod1: u8 = ((mod_rm & 0b11000000) >> 6).try_into().unwrap();
        let reg: Register = ((mod_rm & 0b00111000) >> 3).try_into().unwrap();
        let mut rm: Register = (mod_rm & 0b00000111).try_into().unwrap();
        // If rm == 0x100, means a SIB follows the ModR/M byte
        // P40 Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte (NOTES 1)

        // register [0..3]
        // Indicate the register used as the index (SIB byte bits 3, 4 and 5)
        // and the scaling factor (determined by SIB byte bits 6 and 7)
        let mut scale_factor: u8 = 0;
        let mut index_reg: Register = Register::Undefined;
        let mut base_reg: Register = Register::Undefined;
        if mod1 != 0b11 && rm == Register::Esp {
            // SIB
            // [
            //     scale: scale factor
            //     index: index register
            //     base: base register
            // ]
            // 0x100
            let sib = src[idx];
            idx += 1;
            // 00100100
            scale_factor = (sib & 0b11000000) >> 6;
            index_reg = ((sib & 0b00111000) >> 3).try_into().unwrap();
            base_reg = (sib & 0b00000111).try_into().unwrap();
            rm = base_reg
            // has_sib = true;
        }
        let mut offset = 0i32;
        if mod1 == 0b00 {
            offset = 0;
        } else if mod1 == 0b01 {
            offset = i8::from_le_bytes([src[idx].try_into().unwrap()]).into();
            idx += 1;
            // mov    esi,DWORD PTR [ebp+0x8]
        } else if mod1 == 0b10 {
            offset = i32::from_le_bytes(src[idx..idx + 4].try_into().unwrap());
            idx += 4;
        } else if mod1 == 0b11 {
        }
        *idx_ptr = idx;
        ModRM {
            // mode: mod1,
            has_ptr: mod1 != 0b11,
            reg: reg,
            base_reg: rm,
            // SIB
            scale_factor: scale_factor,
            index_reg: index_reg,
            // offset
            offset: offset,
        }
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
                0xE8 => {
                    // E8 cd
                    // CALL rel32
                    // let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    // dbg!(&mode_rm);
                    // dbg!(&self.input[idx..idx + 4]);
                    let rel32 = i32::from_le_bytes(self.input[idx..idx + 4].try_into().unwrap());
                    idx += 4;
                    // dbg!(&rel32);
                    let off = idx as i32 + rel32;
                    let tmp = format!("call {:x}", off);
                    result.push(tmp.to_string());
                }
                0xC3 => {
                    result.push("ret".to_string());
                }
                0xC7 => {
                    //  C7 / 0
                    //  MOV r/m32, imm32
                    let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    let factor = 2u32.pow(mode_rm.scale_factor.into());
                    let mut left = format!("{}", mode_rm.base_reg.to_str(width));
                    if factor > 1 {
                        left.push_str(&format!("*0x{:x}", factor))
                    }
                    if mode_rm.offset > 0 {
                        left.push_str(&format!("+0x{:x}", mode_rm.offset));
                    }
                    let imm32 = u32::from_le_bytes(self.input[idx..idx + 4].try_into().unwrap());
                    idx += 4;
                    let tmp = if mode_rm.has_ptr {
                        format!("mov DWORD PTR [{}], 0x{:x}", left, imm32)
                    } else {
                        format!("mov {}, 0x{:x}", left, imm32)
                    };
                    result.push(tmp.to_string());
                }
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
                0x83 => {
                    // 83 /5 ib
                    // SUB r/m32, imm8
                    // P1306

                    // 83 /0 ib
                    // ADD r/m32, imm8
                    let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    // dbg!(&mode_rm, &mode_rm.reg);

                    let op = {
                        match mode_rm.reg {
                            Register::Eax => {
                                // 83 /0 ib
                                "add"
                            }
                            Register::Ebp => {
                                // 83 /5 ib
                                "sub"
                            }
                            _ => {
                                unreachable!();
                            }
                        }
                    };

                    let imm8 = self.input[idx];
                    idx += 1;
                    let tmp = if mode_rm.has_ptr {
                        format!(
                            "{} DWORD PTR [{}], 0x{:x}",
                            op,
                            mode_rm.base_reg.to_str(width),
                            imm8
                        )
                    } else {
                        format!("{} {}, 0x{:x}", op, mode_rm.base_reg.to_str(width), imm8)
                    };
                    result.push(tmp.to_string());
                }
                0x89 => {
                    // 89 /r
                    // MOV r/m32,r32
                    let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    // dbg!(&mode_rm, mode_rm.offset > 0);
                    let factor = 2u32.pow(mode_rm.scale_factor.into());
                    let mut left = format!("{}", mode_rm.base_reg.to_str(width));
                    if factor > 1 {
                        left.push_str(&format!("*0x{:x}", factor))
                    }
                    if mode_rm.offset > 0 {
                        left.push_str(&format!("+0x{:x}", mode_rm.offset));
                    } else if mode_rm.offset < 0 {
                        left.push_str(&format!("-0x{:x}", mode_rm.offset.abs()));
                    }
                    let tmp = if mode_rm.has_ptr {
                        format!("mov DWORD PTR [{}], {}", left, mode_rm.reg.to_str(width))
                    } else {
                        format!("mov {}, {}", left, mode_rm.reg.to_str(width))
                    };
                    result.push(tmp.to_string());
                }
                0x8b => {
                    // 8B /r
                    // MOV r32,r/m32
                    let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    let factor = 2u32.pow(mode_rm.scale_factor.into());
                    let mut right = format!("{}", mode_rm.base_reg.to_str(width));
                    if factor > 1 {
                        right.push_str(&format!("*0x{:x}", factor))
                    }
                    if mode_rm.offset > 0 {
                        right.push_str(&format!("+0x{:x}", mode_rm.offset));
                    }

                    let tmp = if mode_rm.has_ptr {
                        format!("mov {}, DWORD PTR [{}]", mode_rm.reg.to_str(width), right)
                    } else {
                        format!("mov {}, {}", mode_rm.reg.to_str(width), right)
                    };

                    result.push(tmp.to_string());
                }
                0x8d => {
                    // 8D /r
                    // LEA r32, m
                    let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    let factor = 2u32.pow(mode_rm.scale_factor.into());
                    let mut right = format!("{}", mode_rm.base_reg.to_str(width));
                    if factor > 1 {
                        right.push_str(&format!(
                            "+{}*0x{:x}",
                            mode_rm.index_reg.to_str(width),
                            factor
                        ))
                    }
                    if mode_rm.offset > 0 {
                        right.push_str(&format!("+0x{:x}", mode_rm.offset));
                    }
                    let tmp = if mode_rm.has_ptr {
                        format!("lea {}, [{}]", mode_rm.reg.to_str(width), right)
                    } else {
                        format!("lea {}, {}", mode_rm.reg.to_str(width), right)
                    };

                    result.push(tmp.to_string());
                }
                0x0F => {
                    // 0F AF / r
                    // IMUL r32, r/m32
                    if self.input[idx] != 0xAF {
                        unimplemented!();
                    }
                    idx += 1;
                    let mode_rm = ModRM::from_u8(&self.input, &mut idx);
                    let factor = 2u32.pow(mode_rm.scale_factor.into());
                    let mut right = format!("{}", mode_rm.base_reg.to_str(width));
                    if factor > 1 {
                        right.push_str(&format!("*0x{:x}", factor))
                    }
                    if mode_rm.offset > 0 {
                        right.push_str(&format!("+0x{:x}", mode_rm.offset));
                    }
                    let tmp = if mode_rm.has_ptr {
                        format!("imul {}, DWORD PTR [{}]", mode_rm.reg.to_str(width), right)
                    } else {
                        format!("imul {}, {}", mode_rm.reg.to_str(width), right)
                    };

                    result.push(tmp.to_string());
                }
                _ => {
                    println!("Undefined Op 0x{:x}", op0);
                    unimplemented!();
                }
            };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[ignore]
    #[test]
    fn test_modrm() {
        // 0x8D, 0x74, 0xC3, 0x04
        // lea esi, [ebx+8*eax+4]
        let src = [0x8D, 0x74, 0xC3, 0x04];
        let mut idx = 1;
        let mod_rm = ModRM::from_u8(&src, &mut idx);
        println!("mode_rm: {:?}", mod_rm);
        println!("idx: {:?}", idx);
        assert_eq!(
            mod_rm,
            ModRM {
                has_ptr: true,
                reg: Register::Esi,
                base_reg: Register::Ebx,
                scale_factor: 3,
                index_reg: Register::Eax,
                offset: 4,
            }
        );

        // mov    eax,DWORD PTR [esp+0x8]
        let src = [0x8B, 0x44, 0x24, 0x08];
        let mut idx = 1;
        let mod_rm = ModRM::from_u8(&src, &mut idx);
        // println!("mode_rm: {:?}", mod_rm);
        // println!("idx: {:?}", idx);
        assert_eq!(
            mod_rm,
            ModRM {
                has_ptr: true,
                reg: Register::Eax,
                base_reg: Register::Esp,
                scale_factor: 0,
                index_reg: Register::Esp,
                offset: 8,
            }
        );

        // mov    DWORD PTR [esp],eax
        let src = [0x89, 0x04, 0x24];
        let mut idx = 1;
        let mod_rm = ModRM::from_u8(&src, &mut idx);
        assert_eq!(
            mod_rm,
            ModRM {
                has_ptr: true,
                reg: Register::Eax,
                base_reg: Register::Esp,
                scale_factor: 0,
                index_reg: Register::Esp,
                offset: 0,
            }
        );

        // mov    eax,DWORD PTR [edx+eax*4]
        let src = [0x8B, 0x04, 0x82];
        let mut idx = 1;
        let mod_rm = ModRM::from_u8(&src, &mut idx);
        assert_eq!(
            mod_rm,
            ModRM {
                has_ptr: true,
                reg: Register::Eax,
                base_reg: Register::Edx,
                scale_factor: 2,
                index_reg: Register::Eax,
                offset: 0,
            }
        );

        // 8b 06
        // mov    eax,DWORD PTR [esi]
        let src = [0x8B, 0x06];
        let mut idx = 1;
        let mod_rm = ModRM::from_u8(&src, &mut idx);
        assert_eq!(
            mod_rm,
            ModRM {
                has_ptr: true,
                reg: Register::Eax,
                base_reg: Register::Esi,
                scale_factor: 0,
                index_reg: Register::Undefined,
                offset: 0,
            }
        );

        // 89 c3
        // mov    ebx,eax
        let src = [0x89, 0xc3];
        let mut idx = 1;
        let mod_rm = ModRM::from_u8(&src, &mut idx);
        assert_eq!(
            mod_rm,
            ModRM {
                has_ptr: false,
                reg: Register::Eax,
                base_reg: Register::Ebx,
                scale_factor: 0,
                index_reg: Register::Undefined,
                offset: 0,
            }
        );
    }

    #[test]
    fn test_mov() {
        // 0:  55                      push   ebp
        // 1:  89 e5                   mov    ebp,esp
        // 3:  83 ec 18                sub    esp,0x18
        // 6:  b8 01 00 00 00          mov    eax,0x1
        // b:  c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
        // 12: 89 45 fc                mov    DWORD PTR [ebp-0x4],eax
        // 15: e8 fc ff ff ff          call   16 <_main+0x16>
        // 1a: b9 00 00 00 00          mov    ecx,0x0
        // 1f: 89 45 f8                mov    DWORD PTR [ebp-0x8],eax
        // 22: 89 c8                   mov    eax,ecx
        // 24: 83 c4 18                add    esp,0x18
        // 27: 5d                      pop    ebp
        // 28: c3                      ret

        let input = [
            0x55, 0x89, 0xE5, 0x83, 0xEC, 0x18, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC7, 0x04, 0x24,
            0x01, 0x00, 0x00, 0x00, 0x89, 0x45, 0xFC, 0xE8, 0xFC, 0xFF, 0xFF, 0xFF, 0xB9, 0x00,
            0x00, 0x00, 0x00, 0x89, 0x45, 0xF8, 0x89, 0xC8, 0x83, 0xC4, 0x18, 0x5D, 0xC3,
        ];
        // let input = [
        //     0xB8, 0x01, 0x00, 0x00, 0x00
        // ];
        let parser = Parser::new(&input);
        let output = parser.parse();

        assert_eq!(
            output.unwrap(),
            vec![
                "push ebp",
                "mov ebp, esp",
                "sub esp, 0x18",
                "mov eax, 0x1",
                "mov DWORD PTR [esp], 0x1",
                "mov DWORD PTR [ebp-0x4], eax",
                "call 16",
                "mov ecx, 0x0",
                "mov DWORD PTR [ebp-0x8], eax",
                "mov eax, ecx",
                "add esp, 0x18",
                "pop ebp",
                "ret",
            ]
        );
    }

    #[ignore]
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
                "imul eax, DWORD PTR [esp]",
                "pop edx",
                "ret"

                // "mov esi, DWORD PTR [ebp+0x8]".to_string(),
                // "xor ecx, ecx".to_string(),
                // "mov eax, DWORD PTR [esi]".to_string(),
            ]
        );

        // 0x8D, 0x74, 0xC3, 0x04
        // lea esi, [ebx+8*eax+4]
        let input = [0x8D, 0x74, 0xC3, 0x04];
        let parser = Parser::new(&input);
        let output = parser.parse();
        assert_eq!(output.unwrap(), vec!["lea esi, [ebx+eax*0x8+0x4]",]);
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
