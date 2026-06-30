use alloc::vec::Vec;

#[derive(Debug)]
pub struct LinkLayerControlPdu<'a> {
    pub dsap_address: u8,
    pub ssap_address: u8,
    pub control: ControlField,
    pub data: alloc::borrow::Cow<'a, [u8]>,
}
#[derive(Debug)]
pub enum ControlField {
    Information {
        send_sequence: u8,
        receive_sequence: u8,
        poll_final: PollFinal,
    },
    Supervisory {
        command: SupervisoryCommand,
        receive_sequence: u8,
        poll_final: PollFinal,
    },
    Unnumbered {
        modifier: u8,
        poll_final: PollFinal,
    },
}
#[derive(Debug, Eq, PartialEq)]
pub enum PollFinal {
    Command,
    Response,
}
#[derive(Debug, Eq, PartialEq)]
pub enum SupervisoryCommand {
    ReceiveReady,
    Reject,
    ReceiveNotReady,
}

#[derive(Debug)]
pub struct SnapPdu<'a> {
    pub protocol: SnapProtocol,
    pub data: alloc::borrow::Cow<'a, [u8]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SnapProtocol {
    EtherType(u16),
    Organisational { oui: u32, protocol: u16 },
}

impl<'a> LinkLayerControlPdu<'a> {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.dsap_address);
        out.push(self.ssap_address);
        match &self.control {
            ControlField::Information {
                send_sequence,
                receive_sequence,
                poll_final,
            } => {
                out.push((send_sequence << 1) | 0b00000001);
                out.push(
                    (receive_sequence << 1)
                        | if *poll_final == PollFinal::Response {
                            0b00000001
                        } else {
                            0
                        },
                );
            }
            ControlField::Supervisory {
                command,
                receive_sequence,
                poll_final,
            } => {
                match command {
                    SupervisoryCommand::ReceiveReady => {
                        out.push(0b0000_00_10);
                    }
                    SupervisoryCommand::ReceiveNotReady => {
                        out.push(0b0000_01_10);
                    }
                    SupervisoryCommand::Reject => {
                        out.push(0b0000_10_10);
                    }
                }
                out.push(
                    (receive_sequence << 1)
                        | if *poll_final == PollFinal::Response {
                            0b00000001
                        } else {
                            0
                        },
                );
            }
            ControlField::Unnumbered {
                modifier,
                poll_final,
            } => {
                out.push(
                    0b00000011
                        | ((modifier & 0b11) << 2)
                        | (((modifier >> 2) & 0b111) << 5)
                        | if *poll_final == PollFinal::Response {
                            0b00010000
                        } else {
                            0
                        },
                );
            }
        }
        out.extend_from_slice(self.data.as_ref());
        out
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 4 {
            return Err("frame too short");
        }
        let dsap_address = data[0];
        let ssap_address = data[1];
        let control_1 = data[2];
        if control_1 & 0b1 == 0 {
            let send_sequence = control_1 >> 1;
            let control_2 = data[3];
            let poll_final = if control_2 & 0b1 == 0 {
                PollFinal::Command
            } else {
                PollFinal::Response
            };
            let receive_sequence = control_2 >> 1;
            Ok(Self {
                dsap_address,
                ssap_address,
                control: ControlField::Information {
                    send_sequence,
                    receive_sequence,
                    poll_final,
                },
                data: alloc::borrow::Cow::Borrowed(&data[4..]),
            })
        } else {
            if control_1 & 0b10 == 0 {
                let command = (control_1 >> 2) & 0b11;
                let command = match command {
                    0b00 => SupervisoryCommand::ReceiveReady,
                    0b01 => SupervisoryCommand::ReceiveNotReady,
                    0b10 => SupervisoryCommand::Reject,
                    _ => return Err("invalid supervisory command ID"),
                };
                let control_2 = data[3];
                let poll_final = if control_2 & 0b1 == 0 {
                    PollFinal::Command
                } else {
                    PollFinal::Response
                };
                let receive_sequence = control_2 >> 1;
                Ok(Self {
                    dsap_address,
                    ssap_address,
                    control: ControlField::Supervisory {
                        command,
                        receive_sequence,
                        poll_final,
                    },
                    data: alloc::borrow::Cow::Borrowed(&data[4..]),
                })
            } else {
                let modifier_1 = (control_1 >> 2) & 0b11;
                let modifier_2 = (control_1 >> 5) & 0b111;
                let modifier = modifier_1 | (modifier_2 << 2);
                let poll_final = if control_1 & 0b10000 == 0 {
                    PollFinal::Command
                } else {
                    PollFinal::Response
                };
                Ok(Self {
                    dsap_address,
                    ssap_address,
                    control: ControlField::Unnumbered {
                        modifier,
                        poll_final,
                    },
                    data: alloc::borrow::Cow::Borrowed(&data[3..]),
                })
            }
        }
    }
}

impl<'a> SnapPdu<'a> {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.data.len());
        match self.protocol {
            SnapProtocol::EtherType(t) => {
                out.extend_from_slice(&[0, 0, 0]);
                out.extend_from_slice(&t.to_be_bytes());
            }
            SnapProtocol::Organisational { oui, protocol } => {
                let oui = oui.to_be_bytes();
                out.extend_from_slice(&[oui[1], oui[2], oui[3]]);
                out.extend_from_slice(&protocol.to_be_bytes());
            }
        }
        out.extend_from_slice(self.data.as_ref());
        out
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 5 {
            return Err("frame too short");
        }
        let oui = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let protocol = u16::from_be_bytes([data[3], data[4]]);
        Ok(Self {
            protocol: if oui == 0 {
                SnapProtocol::EtherType(protocol)
            } else {
                SnapProtocol::Organisational { oui, protocol }
            },
            data: alloc::borrow::Cow::Borrowed(&data[5..]),
        })
    }
}
