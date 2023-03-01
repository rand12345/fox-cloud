#[derive(Debug, Default)]
pub struct ModbusFrame {
    function: u8,
    address: u16,
    counter: u16,
    len: u8,
    payload: Vec<u8>,
    crc: u16,
}
impl ModbusFrame {
    pub fn decode_hdlc_frame(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut decoded: Vec<u8> = Vec::new();
        let mut in_escape: bool = false;

        for byte in data {
            if in_escape {
                decoded.push(*byte ^ 0x20);
                in_escape = false;
            } else if *byte == 0x7D {
                in_escape = true;
            } else {
                decoded.push(*byte);
            }
        }

        if decoded.len() < 3 {
            return None;
        }

        let crc = (decoded[decoded.len() - 2] as u16) << 8 | decoded[decoded.len() - 1] as u16;
        let expected_crc = self.crc16(&decoded[..decoded.len() - 2]);
        if crc != expected_crc {
            println!("Bad crc {:02x?} {:02x?}", crc, expected_crc);
            return None;
        }
        self.crc = crc;
        self.function = decoded[0];
        self.address = u16::from_be_bytes([decoded[1], decoded[2]]);
        self.payload = decoded[3..decoded.len() - 2].to_vec();
        Some(self.payload.to_owned())
    }

    fn crc16(&mut self, data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;

        for byte in data {
            crc ^= u16::from(*byte);
            for _ in 0..8 {
                if (crc & 0x0001) == 0x0001 {
                    crc = (crc >> 1) ^ 0xA001;
                } else {
                    crc >>= 1;
                }
            }
        }

        crc
    }

    pub fn decode_modbus_request(&mut self, data: &[u8]) -> Option<ModbusFrame> {
        if data.len() < 5 {
            return None;
        }

        self.function = data[0];
        self.address = u16::from_be_bytes([data[1], data[2]]);
        self.counter = u16::from_be_bytes([data[3], data[4]]);
        self.payload = data[5..data.len() - 2].to_vec();
        let crc = self.crc16(&data[..data.len() - 2]);
        self.crc = u16::from_be_bytes([data[data.len() - 1], data[data.len() - 2]]);
        if crc == self.crc {
            println!("CRC OK")
        } else {
            eprintln!("{:02x?} != {:02x?}", self.crc, crc)
        };
        Some(ModbusFrame {
            function: self.function,
            address: self.address,
            counter: self.counter,
            len: self.len,
            payload: self.payload.to_owned(),
            crc: self.crc,
        })
    }
    pub fn decode_modbus_response(&mut self, data: &[u8]) -> Option<ModbusFrame> {
        if data.len() < 5 {
            return None;
        }

        self.function = data[0];
        self.address = u16::from_be_bytes([data[1], data[2]]);
        self.counter = u16::from_be_bytes([data[3], data[4]]);
        self.len = data[6];
        self.payload = data[7..data.len() - 2].to_vec();
        let crc = self.crc16(&data[..data.len() - 2]);
        self.crc = u16::from_be_bytes([data[data.len() - 1], data[data.len() - 2]]);
        if crc == self.crc {
            println!("CRC OK")
        } else {
            eprintln!("{:02x?} != {:02x?}", self.crc, crc)
        };
        Some(ModbusFrame {
            function: self.function,
            address: self.address,
            counter: self.counter,
            len: self.len,
            payload: self.payload.to_owned(),
            crc: self.crc,
        })
    }
}
