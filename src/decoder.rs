use lazy_static::lazy_static;
use std::collections::HashMap;
use tokio::sync::Mutex;

lazy_static! {
    static ref DATA_STORE: Mutex<HashMap<ReadModes, Vec<u8>>> = Mutex::new(HashMap::new());
    static ref REQUEST_STORE: Mutex<HashMap<u32, Option<ReadModes>>> = Mutex::new(HashMap::new());
}

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
            // let (data, _frame_type) = HdlcFrame::default().decode_hdlc_frame(raw)?;
            // println!("HDLC Frame {raw:?}");
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
pub enum ModbusMode {
    #[default]
    Request = 0x11,
    Response = 0x91,
    Unknown = 0,
}

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub enum ReadModes {
    SystemTime,
    BasicParameters1,
    WorkModeParameters,
    ChargingTime,
    BasicParameters2,
    SafetyStartParameters,
    SafetyVoltageParameters,
    SafetyFrequency,
    SafetyPowerFactor,
    SafetyPU,
    SafetyDci,
    SafetyReactive,
    // Operation,
    BatteryVoltage150,
    BatteryVoltage51100,
    BatteryVoltage101144,
    BatteryTemperature,
    Unknown,
    // BatteryVoltage1_50 =
}
impl ReadModes {
    fn decode(address: u16) -> ReadModes {
        match address {
            40000 => ReadModes::SystemTime,              //3072
            40006 => ReadModes::BasicParameters1,        //5120
            41000 => ReadModes::WorkModeParameters,      //512
            41001 => ReadModes::ChargingTime,            //3072
            41007 => ReadModes::BasicParameters2,        //8193
            42000 => ReadModes::SafetyStartParameters,   //4608
            42100 => ReadModes::SafetyVoltageParameters, //6144
            42200 => ReadModes::SafetyFrequency,         //5120
            42300 => ReadModes::SafetyPowerFactor,       //10100
            42700 => ReadModes::SafetyPU,                //4096
            42800 => ReadModes::SafetyDci,               //2560
            43000 => ReadModes::SafetyReactive,          //13824
            // 60000 => ReadModes::Operation,
            60000 => ReadModes::BatteryVoltage150,    //25600
            60050 => ReadModes::BatteryVoltage51100,  //25600
            60100 => ReadModes::BatteryVoltage101144, //22528
            61000 => ReadModes::BatteryTemperature,   //16896

            _ => ReadModes::Unknown,
        }
    }
}

#[derive(Debug, Default)]
pub struct ModbusFrame {
    pub id: u32,
    pub function: u8,
    pub address: u16,
    pub len: u16,
    pub payload: Vec<u8>,
    pub crc: u16,
    pub mode: ModbusMode,
    pub readmode: Option<ReadModes>,
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

        // request
        // fn    count    *LEN*       Addrs *Len*  (Requested number of registers)
        // 11 71 EA EF 34 00 06 01 03 EE 48 00 21 F1 0D (61000)
        //                           Len* - response length
        // 91 71 EA EF 34 00 45 01 03 42 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6E 91

        //    Cntr
        // 11 90 E9 EF 34 00 06 01 03 EA C4 00 2C 80 6A (60100)
        // 91 90 E9 EF 34 00 5B 01 03 58 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4E 20

        // 11 B6 49 F0 34 00 06 01 03 A4 10 00 09 AC B1
        // 91 B6 49 F0 34 00 15 01 03 12 00 00 00 3C 03 E8 00 3C 03 E8 0A 6C 07 01 14 5A 12 84 D5 1A

        // response
        // fn             *LEN*             |<--  Data          ---->| CRC16
        // 91 75 E5 EF 34 00 0D 01 03 0A 00 03 01 2C 00 32 03 84 00 08 74 68 (response to 42300)
        // 91 C0 E4 EF 34 00 13 01 03 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 14 E7
        // 91 04 DF EF 34 00 21 01 03 1E 00 21 12 5C 12 5C 12 5C 00 00 13 97 13 B0 15 A4 00 14 00 05 00 1E 00 A7 00 64 00 64 00 00 E8 75
        // 91 71 EA EF 34 00 45 01 03 42 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6E 91
        // let hex_string = data
        //     .iter()
        //     .map(|b| format!("{:02X}", b))
        //     .collect::<Vec<String>>()
        //     .join(" ");
        // println!("Decoder << {hex_string}");

        let function = data[2];
        let id = u32::from_be_bytes([data[3], data[4], data[5], data[6]]); //ok
                                                                           // let data_len = u16::from_be_bytes([data[7], data[8]]); //ok
        let address = u16::from_be_bytes([data[11], data[12]]); // req only

        let crc_calc = self.crc16(&data[2..data.len() - 4]);
        let crc = u16::from_le_bytes([data[data.len() - 4], data[data.len() - 3]]);
        if crc_calc != crc {
            eprintln!("{:02x?} != {:02x?}", crc_calc, crc);
            return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into()));
        };

        let mode = match function {
            0x11 => ModbusMode::Request,
            0x91 => ModbusMode::Response,
            _ => ModbusMode::Unknown,
        };
        // let request_len = u16::from_be_bytes([data[13], data[14]]); //req only
        // let response_len = u16::from_be_bytes([0, data[11]]); //resp only
        let (len, payload) = match mode {
            ModbusMode::Request | ModbusMode::Unknown => {
                (u16::from_be_bytes([data[13], data[14]]), vec![])
            }
            ModbusMode::Response => (
                u16::from_be_bytes([0, data[11]]),
                data[12..data.len() - 4].to_vec(),
            ),
        };
        let readmode = Some(ReadModes::decode(address));
        // println!(
        //     "Debug Addr: {address} be {} le {}",
        //     u16::from_be_bytes([data[0xb], data[0xc]]),
        //     u16::from_le_bytes([data[0xb], data[0xc]])
        // );

        Ok(ModbusFrame {
            id,
            function,
            address,
            len,
            payload,
            crc,
            mode,
            readmode,
        })
    }

    pub async fn decode_request_payload(&self) {
        let mut req_store = REQUEST_STORE.lock().await;
        let _insert = req_store.insert(self.id, self.readmode.clone());
        println!("Recorded {:?} to {:?} as request", self.id, self.readmode);
    }
    pub async fn decode_response_payload(&self) -> Result<(), DecodeError> {
        let mut req_store = REQUEST_STORE.lock().await;
        let address = if let Some(addr) = req_store.remove(&self.id) {
            println!("Recovered request {:?} for id: {}", addr, self.id);
            addr
        } else {
            return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into()));
        };
        drop(req_store);
        let mut data_store = DATA_STORE.lock().await;
        let stored = data_store.insert(address.to_owned().unwrap(), self.payload.clone());
        println!(
            "Replaced value: {:02x?} at {:?} with {:?}",
            stored, address, self.payload
        );
        Ok(())
    }
    pub async fn decode_readmodes(&self) -> Result<(), DecodeError> {
        let readmode = match &self.readmode {
            Some(rm) => rm,
            None => return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into())),
        };
        let data_store = DATA_STORE.lock().await;
        let d = if let Some(val) = data_store.get(readmode) {
            val
        } else {
            return Err(DecodeError::IoError(std::io::ErrorKind::InvalidData.into()));
        };
        match readmode {
            ReadModes::SystemTime => {
                println!(
                    "Date {}/{}/{} Time {}:{}:{}",
                    d[1], d[3], d[5], d[7], d[9], d[11]
                );
            } //[0, 23, 0, 3, 0, 1, 0, 19, 0, 9, 0, 25]}
            ReadModes::BasicParameters1 => {
                println!("Modbus RTU address: {}", d[13]);
                //0, 3, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 247, 0, 0, 0, 180, 0, 255
            }
            _ => (), /*
                     ReadModes::WorkModeParameters => todo!(),
                     ReadModes::ChargingTime => todo!(),
                     ReadModes::BasicParameters2 => todo!(),
                     ReadModes::SafetyStartParameters => todo!(),
                     ReadModes::SafetyVoltageParameters => todo!(),
                     ReadModes::SafetyFrequency => todo!(),
                     ReadModes::SafetyPowerFactor => todo!(),
                     ReadModes::SafetyPU => todo!(),
                     ReadModes::SafetyDci => todo!(),
                     ReadModes::SafetyReactive => todo!(),
                     ReadModes::BatteryVoltage150 => todo!(),
                     ReadModes::BatteryVoltage51100 => todo!(),
                     ReadModes::BatteryVoltage101144 => todo!(),
                     ReadModes::BatteryTemperature => todo!(),
                     ReadModes::Unknown => todo!(), */
        };
        Ok(())
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
}
