use std::default;

#[derive(Debug)]
pub enum DecodeError {
    IoError(std::io::Error),
}

impl From<std::io::Error> for DecodeError {
    fn from(err: std::io::Error) -> Self {
        DecodeError::IoError(err)
    }
}

#[derive(Debug)]
pub enum Mode {
    Request(FrameType),
    Response(FrameType),
    Info,
}
#[derive(Default, Debug)]
pub enum FrameType {
    #[default]
    Broadcast,
    Structured, //change all these values to actuals
    Unstructured,
    Unknown,
}
#[derive(Debug)]
pub struct Middleware {
    pub raw: Vec<u8>,
    pub modbus: Option<ModbusFrame>,
    // pub mode: Mode,
}

impl Middleware {
    pub fn new(raw: &[u8]) -> Result<Self, DecodeError> {
        if raw[0..2] == [0x7F, 0x7F] {
            let modbus_decoder = ModbusFrame::default().decode_modbus(raw)?;

            Ok(Self {
                raw: raw.to_owned(),
                modbus: Some(modbus_decoder),
            })
        } else {
            let (data, _frame_type) = HdlcFrame::default().decode_hdlc_frame(raw)?;
            println!("HDLC Frame {raw:?}");
            Err(DecodeError::IoError(std::io::ErrorKind::NotFound.into()))
        }
    }
}

#[derive(Default, Debug)]
struct HdlcFrame {
    function: u8,
    pub address: u16,
    counter: u16,
    pub payload: Vec<u8>,
}
impl HdlcFrame {
    fn mode(&self) -> FrameType {
        match self.function {
            6 => FrameType::Broadcast,
            _ => FrameType::Unknown,
        }
    }
    fn decode_hdlc_frame(&mut self, data: &[u8]) -> Result<(Vec<u8>, FrameType), DecodeError> {
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
            return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into()));
        }

        self.function = data[0];
        self.address = u16::from_be_bytes([data[1], data[2]]);
        self.counter = u16::from_be_bytes([data[3], data[4]]);
        self.payload = data[5..data.len() - 2].to_vec();

        Ok((decoded, self.mode()))
    }
}

#[derive(Debug, Default)]
pub struct ModbusFrame {
    function: u8,
    pub address: u16,
    counter: u16,
    len: u16,
    pub payload: Vec<u8>,
    crc: u16,
    pub mode: ModbusMode,
}
#[derive(Debug, Default)]
pub enum ModbusMode {
    #[default]
    Request = 0x11,
    Response = 0x91,
    Unknown = 0,
}

#[derive(Debug)]
enum ReadModes {
    SystemTime = 40000,
    BasicParameters1 = 40006,
    WorkModParameters = 41000,
    ChargingTime = 41001,
    BasicParameters2 = 41007,
    Unknown,
    // BatteryVoltage1_50 =
}
impl ReadModes {
    fn decode(address: u16) -> ReadModes {
        match address {
            40000 => ReadModes::SystemTime,
            40006 => ReadModes::BasicParameters1,
            _ => ReadModes::Unknown,
        }
    }
}
impl ModbusFrame {
    /*

    40000/3072 = systime
    40006/5120 = BP1
    41000/512 = wmp
    41001/3072 = ct

        [7e, 7e, aa, 63, ff, 14, 81, 00, 05, 01, 01, 01, 00, 00, 60, 68, e7, e7]
    ModbusFrame { function: 00, address: 00, counter: 00, len: 00, payload: [], crc: 6860 }
    */
    pub fn decode_modbus(&mut self, data: &[u8]) -> Result<ModbusFrame, DecodeError> {
        if data.len() < 5 {
            return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into()));
        }

        // ab, 63, ff, 17, 0c, 00, 01, 01, fb, ca,
        println!("Decoder << {data:?}");
        let function = data[2];
        let mode = match function {
            0x11 => ModbusMode::Request,
            0x91 => ModbusMode::Response,
            _ => ModbusMode::Unknown,
        };
        let address = u16::from_be_bytes([data[0xb], data[0xc]]);
        if matches!(mode, ModbusMode::Request) {
            println!("Read mode {:?}", ReadModes::decode(address))
        }
        let counter = u16::from_be_bytes([data[3], data[4]]);
        let (len, payload) = match mode {
            ModbusMode::Request => (0, data[0x5..data.len() - 2].to_vec()),
            ModbusMode::Response => (
                u16::from_be_bytes([data[0xd], data[0xe]]),
                data[0xf..data.len() - 2].to_vec(),
            ),
            ModbusMode::Unknown => (0, data[0x5..data.len() - 2].to_vec()),
        };

        let crc_calc = self.crc16(&data[2..data.len() - 4]);
        let crc = u16::from_le_bytes([data[data.len() - 4], data[data.len() - 3]]);
        if crc_calc != crc {
            eprintln!("{:02x?} != {:02x?}", crc_calc, crc);
            return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into()));
        };

        println!(
            "Debug Addr: {address} be {} le {}",
            u16::from_be_bytes([data[0xb], data[0xc]]),
            u16::from_le_bytes([data[0xb], data[0xc]])
        );
        Ok(ModbusFrame {
            function,
            address,
            counter,
            len,
            payload,
            crc,
            mode,
        })
    }

    // 7e, 7e, 02, 63, fe, ad, aa, 00, f4, 00, 00, 00, 00, 00, 00, 00, 00

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
}
