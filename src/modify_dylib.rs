

fn read_uint32(data: &[u8], offset: usize) -> u32 {
    let value:u32 =  data[offset] as u32
        | ((data[offset + 1] as u32) << 8)
        | ((data[offset + 2] as u32) << 16)
        | ((data[offset + 3] as u32) << 24);
    return value;
}

fn read_uint32_be(data: &[u8], offset: usize) -> u32 {
    let value:u32 =  ((data[offset] as u32) << 24)
        | ((data[offset + 1] as u32) << 16)
        | ((data[offset + 2] as u32) << 8)
        | (data[offset + 3] as u32);
    return value;
}

#[warn(dead_code)]
fn write_uint32(data: &mut [u8], offset: usize, value: u32) {
    data[offset] = (value & 0xFF) as u8;
    data[offset + 1] = ((value >> 8) & 0xFF) as u8;
    data[offset + 2] = ((value >> 16) & 0xFF) as u8;
    data[offset + 3] = ((value >> 24) & 0xFF) as u8;
}

fn read_uleb128(data: &[u8], offset: &mut usize) -> u128 {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = data[*offset];
        *offset += 1;
        result |= ((byte & 0x7F) as u128) << shift;
        println!("byte: {:x}, result: {:x}, shift: {:x},offset: {:x}", byte, result, shift,*offset-1);
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    return result;
}

fn read_sleb128(data: &[u8], offset: &mut usize) -> i128 {
    let mut result: i128 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8;
    loop {
        byte = data[*offset];
        *offset += 1;
        result |= ((byte & 0x7F) as i128) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }
    // Sign extend if necessary
    if byte & 0x40 != 0 {
        result -= 1 << shift;
    }
    return result;
}

fn modify_dylib_symbols(fat_data: &mut [u8],fat_offset: usize,size: usize, old_ordinal: i32, new_ordinal: i32) {
    let data=&mut fat_data[fat_offset..fat_offset+size];
    
    let magic = read_uint32(data, 0);
    if magic != 0xFEEDFACF {
        panic!("Not a valid Mach-O 64-bit binary");
    }

    let ncmds = read_uint32(data, 16);
    const LOAD_COMMAND_START: usize = 32;

    let mut offset: usize = LOAD_COMMAND_START;
    for _ in 0..ncmds {
        let cmd=read_uint32(data,offset);
        let cmdsize:usize=read_uint32(data,offset+4) as usize;

        if cmd == 0x80000022{
            for i in [16,24,32]{
                let mut index:usize=read_uint32(data,offset+i) as usize;
                let bind_size=read_uint32(data,offset+i+4) as usize;
                let end=index+bind_size;
                while index<end{
                    let byte=data[index];
                    let opcode=byte & 0xF0;
                    let immediate=(byte & 0x0F) as i32;
                    
                    if opcode == 0x00{ // # BIND_OPCODE_DONE
                        index+=1;
                    }else if opcode == 0x10{ //# BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                        if immediate ==old_ordinal{
                            data[index]=if new_ordinal<0 {0x30}else{0x10} | ((new_ordinal & 0x0F) as u8);
                        }
                        index+=1;
                    }else if opcode == 0x20{  //  # BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
                        index+=1;
                        read_uleb128(data,&mut index);
                    }else if opcode == 0x30{  // # BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
                        let trans_immediate = (byte | 0xf0) as i32;
                        if trans_immediate == old_ordinal{
                            data[index]=if new_ordinal<0 {0x30}else{0x10} | ((new_ordinal & 0x0F) as u8);
                        }
                        index+=1;
                    }else if opcode == 0x40{    //# BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
                        while data[index]!=0 && index<end{
                            index+=1;
                        }
                        index+=1;
                    }else if opcode == 0x50{     // # BIND_OPCODE_SET_TYPE_IMM
                        index+=1;
                    }else if opcode == 0x60{     //# BIND_OPCODE_SET_ADDEND_SLEB
                        index+=1;
                        read_sleb128(data,&mut index);
                    }else if opcode == 0x70{     //# BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                        index+=1;
                        read_uleb128(data,&mut index);
                    }else if opcode == 0x80{    //# BIND_OPCODE_ADD_ADDR_ULEB
                        index+=1;
                        read_uleb128(data,&mut index);
                    }else if opcode == 0x90{   // # BIND_OPCODE_DO_BIND
                        index+=1;
                    }else if opcode == 0xA0{   //# BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
                        index+=1;
                        read_uleb128(data,&mut index);
                    }else if opcode == 0xB0{    //# BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
                        index+=1;
                    }else if opcode == 0xC0{     //# BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                        index+=1;
                        read_uleb128(data,&mut index);
                        read_uleb128(data,&mut index);
                    }else{
                        panic!("Unknown bind opcode");
                    }

                }    

            }
        }else if cmd==0x2{
            let sym_off= read_uint32(data,offset+8);
            let sym_size= read_uint32(data,offset+12);

            let mut index:usize=sym_off as usize;
            let end=index+sym_size as usize*16;
            while index<end{
                // let strx=read_uint32(data,index) as usize;
                // let type_byte=data[index+4];
                // let sect=data[index+5];
                let desc:u16=data[index+6] as u16 | ((data[index+7] as u16)<<8);
                // let value:u64=data[index+8] as u64
                    // | ((data[index+9] as u64)<<8)
                    // | ((data[index+10] as u64)<<16)
                    // | ((data[index+11] as u64)<<24)
                    // | ((data[index+12] as u64)<<32)
                    // | ((data[index+13] as u64)<<40)
                    // | ((data[index+14] as u64)<<48)
                    // | ((data[index+15] as u64)<<56);

                if desc!=0{
                    let ordinal:i32=data[index+7] as i32;
                    if ordinal==old_ordinal{
                        data[index+7]=(new_ordinal&0xff) as u8;
                    }
                }
                index+=16;
            }
        }
        offset+=cmdsize;
    }
}

pub fn modify_dylib(file: String, old_ordinal: i32, new_ordinal: i32) {
    let mut fat_data = std::fs::read(&file).expect("Failed to read file");

    let magic = read_uint32(&fat_data, 0);
    if magic == 0xbebafeca {
        let nfat_arch = read_uint32_be(&fat_data, 4);
        let mut offset=8;
        for _i in 0..nfat_arch {
            let arch_offset: usize = read_uint32_be(&fat_data, offset + 8) as usize;
            let arch_size: usize = read_uint32_be(&fat_data, offset + 12) as usize;
            modify_dylib_symbols(&mut fat_data, arch_offset, arch_size, old_ordinal, new_ordinal);
            offset += 20;
        }
    }else if magic == 0xFEEDFACF {
        let size = fat_data.len() as usize;
        modify_dylib_symbols(&mut fat_data, 0, size, old_ordinal, new_ordinal);
    }

    std::fs::write(&file, &fat_data).expect("Failed to write file");
}

