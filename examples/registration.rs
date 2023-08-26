use blstrs::Scalar;
use ff::Field;
use srs_opaque::{
    ciphersuite::{Bytes, Digest},
    error::InternalError,
    opaque::{ClientLoginFlow, ClientRegistrationFlow, ServerLoginFlow, ServerRegistrationFlow},
    payload::Payload,
    primitives::derive_keypair,
    Result,
};
use typenum::{U20, U4, U8};

#[derive(Clone)]
pub struct KsfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: Option<usize>,
}

impl Payload for KsfParams {
    type Len = U20;

    fn serialize(&self) -> Result<Bytes<Self::Len>> {
        use generic_array::sequence::Concat;
        let mut m_cost = Bytes::<U4>::default();
        let mut t_cost = Bytes::<U4>::default();
        let mut p_cost = Bytes::<U4>::default();
        let mut output_len = Bytes::<U8>::default();
        m_cost.copy_from_slice(&self.m_cost.to_be_bytes()[..]);
        t_cost.copy_from_slice(&self.t_cost.to_be_bytes()[..]);
        p_cost.copy_from_slice(&self.p_cost.to_be_bytes()[..]);
        output_len.copy_from_slice(&self.output_len.unwrap_or(0).to_be_bytes()[..]);
        Ok(m_cost.concat(t_cost).concat(p_cost).concat(output_len))
    }

    fn deserialize(buf: &Bytes<Self::Len>) -> Result<Self>
    where
        Self: Sized,
    {
        let m_cost = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let t_cost = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let p_cost = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let output_len = usize::from_be_bytes(buf[12..].try_into().unwrap());
        Ok(KsfParams {
            m_cost,
            t_cost,
            p_cost,
            output_len: if output_len == 0 {
                None
            } else {
                Some(output_len)
            },
        })
    }
}

fn argon2_stretch(input: &[u8], params: &KsfParams) -> Result<Digest> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            params.output_len,
        )
        .map_err(|_| InternalError::KsfError)?,
    );
    let mut output = Digest::default();
    argon2
        .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
        .map_err(|_| InternalError::KsfError)?;
    Ok(output)
}

fn main() -> Result<()> {
    let server_oprf_key = Scalar::ONE.double();
    let server_keypair = derive_keypair(b"secret seed", b"public info")?;
    let server_identity = "srs.blockshake.io";

    let ksf_params = KsfParams {
        m_cost: 32768,
        p_cost: 1,
        t_cost: 1,
        output_len: None,
    };

    // STEP 1: initiate registration on client
    let username = "my_username";
    let password = b"password";
    let mut client_flow = ClientRegistrationFlow::<KsfParams>::new(
        username,
        password,
        &server_keypair.public_key,
        &ksf_params,
        Some(server_identity),
    );
    let registration_request = client_flow.start();

    // STEP 2: proceed registration on server, evaluate OPRF
    let server_flow = ServerRegistrationFlow::new(&server_oprf_key);
    let registration_response = server_flow.start(&registration_request);

    // STEP 3: finish registration on client, create registration record
    // that's sent to the server and an export key that's used locally
    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &ksf_params);
    let (registration_record, export_key) =
        client_flow.finish(&registration_response, ksf_stretch)?;

    // STEP 4: finish registration on server using the registration record
    server_flow.finish(&registration_record);

    println!(
        "server public key: {:?}",
        server_keypair.public_key.serialize()
    );
    println!(
        "server secret key: {:?}",
        server_keypair.secret_key.serialize()
    );
    println!("server oprf key: {:?}", server_oprf_key);
    println!("client export key: {:?}", export_key);

    ///////////////
    //// LOGIN ////
    ///////////////

    let mut rng = rand::thread_rng();

    // STEP 1: initiate registration on client

    let mut client_flow = ClientLoginFlow::new(username, password);
    let ke1 = client_flow.start(&mut rng)?;

    // STEP 2: evaluate login on server

    let mut server_flow = ServerLoginFlow::new(
        &server_keypair.public_key,
        Some(server_identity),
        &server_keypair,
        &registration_record,
        &server_oprf_key,
        &ke1,
        username,
    );
    let ke2 = server_flow.start()?;

    // STEP 3: finalize on client
    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &ke2.payload);
    let (ke3, client_session_key, export_key) =
        client_flow.finish(Some(server_identity), &ke2, ksf_stretch)?;

    // STEP 4: finalize on server
    let server_session_key = server_flow.finish(&ke3)?;

    println!("client_session_key: {:?}", client_session_key);
    println!("server_session_key: {:?}", server_session_key);
    println!("export_key: {:?}", export_key);

    Ok(())
}
