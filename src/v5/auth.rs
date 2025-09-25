use super::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum AuthReason {
    /// Authentication is successful.
    Success = 0x00,
    /// Continue the authentication with another step.
    ContinueAuthentication = 0x18,
    /// Initiate a re-authentication.
    ReAuthenticate = 0x19,
}

/// Maps a number to Reason Code
pub fn reason(num: u8) -> Result<AuthReason, Error> {
    match num {
        0x00 => Ok(AuthReason::Success),
        0x18 => Ok(AuthReason::ContinueAuthentication),
        0x19 => Ok(AuthReason::ReAuthenticate),
        reason => Err(Error::InvalidReason(reason)),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthProperties {
    /// Method of authentication
    pub authentication_method: Option<String>,
    /// Authentication data
    pub authentication_data: Option<Bytes>,
    /// Reason String
    pub reason_string: Option<String>,
    /// List of user properties
    pub user_properties: Vec<(String, String)>,
}

impl AuthProperties {
    fn _new() -> AuthProperties {
        AuthProperties {
            authentication_method: None,
            authentication_data: None,
            reason_string: None,
            user_properties: Vec::new(),
        }
    }

    fn read(mut bytes: &mut Bytes) -> Result<Option<AuthProperties>, Error> {
        let mut authentication_method = None;
        let mut authentication_data = None;
        let mut reason_string = None;
        let mut user_properties = Vec::new();

        let (properties_len_len, properties_len) = length(bytes.iter())?;
        bytes.advance(properties_len_len);
        if properties_len == 0 {
            return Ok(None);
        }

        let mut cursor = 0;
        // read until cursor reaches property length. properties_len = 0 will skip this loop
        while cursor < properties_len {
            let prop = read_u8(&mut bytes)?;
            cursor += 1;
            match property(prop)? {
                PropertyType::AuthenticationMethod => {
                    let method = read_mqtt_string(&mut bytes)?;
                    cursor += 2 + method.len();
                    authentication_method = Some(method);
                }
                PropertyType::AuthenticationData => {
                    let data = read_mqtt_bytes(&mut bytes)?;
                    cursor += 2 + data.len();
                    authentication_data = Some(data);
                }
                PropertyType::ReasonString => {
                    let reason = read_mqtt_string(&mut bytes)?;
                    cursor += 2 + reason.len();
                    reason_string = Some(reason);
                }
                PropertyType::UserProperty => {
                    let key = read_mqtt_string(&mut bytes)?;
                    let value = read_mqtt_string(&mut bytes)?;
                    cursor += 2 + key.len() + 2 + value.len();
                    user_properties.push((key, value));
                }
                _ => return Err(Error::InvalidPropertyType(prop)),
            }
        }

        Ok(Some(AuthProperties {
            authentication_method,
            authentication_data,
            reason_string,
            user_properties,
        }))
    }

    fn len(&self) -> usize {
        let mut len = 0;

        if let Some(authentication_method) = &self.authentication_method {
            len += 1 + 2 + authentication_method.len();
        }

        if let Some(authentication_data) = &self.authentication_data {
            len += 1 + 2 + authentication_data.len();
        }

        if let Some(reason) = &self.reason_string {
            len += 1 + 2 + reason.len();
        }

        for (key, value) in self.user_properties.iter() {
            len += 1 + 2 + key.len() + 2 + value.len();
        }

        len
    }

    fn write(&self, buffer: &mut BytesMut) -> Result<(), Error> {
        let len = self.len();
        write_remaining_length(buffer, len)?;

        if let Some(authentication_method) = &self.authentication_method {
            buffer.put_u8(PropertyType::AuthenticationMethod as u8);
            write_mqtt_string(buffer, authentication_method);
        }

        if let Some(authentication_data) = &self.authentication_data {
            buffer.put_u8(PropertyType::AuthenticationData as u8);
            write_mqtt_bytes(buffer, authentication_data);
        }

        if let Some(reason) = &self.reason_string {
            buffer.put_u8(PropertyType::ReasonString as u8);
            write_mqtt_string(buffer, reason);
        }

        for (key, value) in self.user_properties.iter() {
            buffer.put_u8(PropertyType::UserProperty as u8);
            write_mqtt_string(buffer, key);
            write_mqtt_string(buffer, value);
        }

        Ok(())
    }
}

/// Authentication-exchange packet
#[derive(Debug, Clone, PartialEq)]
pub struct Auth {
    /// Reason code
    pub reason: AuthReason,
    /// Properties
    pub properties: Option<AuthProperties>,
}

impl Auth {
    pub fn new() -> Auth {
        Auth {
            reason: AuthReason::Success,
            properties: None,
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 1;

        match &self.properties {
            Some(properties) => {
                let properties_len = properties.len();
                let properties_len_len = len_len(properties_len);
                len += properties_len_len + properties_len;
            }
            None => {
                // just 1 byte representing 0 len
                len += 1;
            }
        }

        len
    }

    pub fn read(fixed_header: FixedHeader, mut bytes: Bytes) -> Result<Self, Error> {
        let variable_header_index = fixed_header.fixed_header_len;
        bytes.advance(variable_header_index);

        // No properties len or properties if remaining len > 2 but < 4
        let auth_reason = read_u8(&mut bytes)?;
        if fixed_header.remaining_len < 4 {
            return Ok(Auth {
                reason: reason(auth_reason)?,
                properties: None,
            });
        }

        let auth = Auth {
            reason: reason(auth_reason)?,
            properties: AuthProperties::read(&mut bytes)?,
        };

        Ok(auth)
    }

    pub fn write(&self, buffer: &mut BytesMut) -> Result<usize, Error> {
        let len = self.len();

        buffer.put_u8(0b1111_0000);

        let count = write_remaining_length(buffer, len)?;

        // Reason code is optional with success if there are no properties
        if self.reason == AuthReason::Success && self.properties.is_none() {
            return Ok(4);
        }

        buffer.put_u8(self.reason as u8);
        if let Some(properties) = &self.properties {
            properties.write(buffer)?;
        }

        Ok(1 + count + len)
    }
}
