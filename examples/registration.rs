use blstrs::Scalar;
use ff::Field;
use rand::rngs::ThreadRng;
use srs_opaque::{
    ciphersuite::{Bytes, Digest},
    error::{Error, InternalError},
    opaque::{ClientLoginFlow, ClientRegistrationFlow, ServerLoginFlow, ServerRegistrationFlow},
    oprf,
    primitives::derive_keypair,
    Result,
};
use typenum::{Unsigned, U20, U4, U8};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, ZeroizeOnDrop)]
pub struct KsfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: Option<usize>,
}

impl KsfParams {
    fn to_bytes(&self) -> Result<Bytes<U20>> {
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

    fn from_bytes(buf: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if buf.len() != U20::to_usize() {
            return Err(Error::Internal(InternalError::DeserializeError));
        }
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
    let ksf_params_bytes = ksf_params.to_bytes()?;

    //////////////////////
    //// Registration ////
    //////////////////////

    // STEP 1: initiate registration on client
    let username = "my_username";
    let password = b"password";
    let mut client_flow = ClientRegistrationFlow::<ThreadRng>::new(
        username,
        password,
        &server_keypair.public_key,
        &ksf_params_bytes[..],
        Some(server_identity),
        rand::thread_rng(),
    );
    let registration_request = client_flow.start();

    // STEP 2: proceed registration on server, evaluate OPRF
    let server_flow = ServerRegistrationFlow::new(&server_keypair.public_key);
    let evaluated_element = oprf::blind_evaluate(
        &registration_request.blinded_element,
        registration_request.client_identity.as_bytes(),
        &server_oprf_key,
    );
    let registration_response = server_flow.start(evaluated_element);

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

    // STEP 1: initiate registration on client

    let mut client_flow = ClientLoginFlow::new(username, password, rand::thread_rng());
    let ke1 = client_flow.start()?;

    // STEP 2: evaluate login on server

    let mut server_flow = ServerLoginFlow::new(
        &server_keypair.public_key,
        Some(server_identity),
        &server_keypair,
        &registration_record,
        &ke1,
        username,
        rand::thread_rng(),
    );
    let evaluated_element = oprf::blind_evaluate(
        &ke1.credential_request.blinded_element,
        username.as_bytes(),
        &server_oprf_key,
    );
    let (state, ke2) = server_flow.start(evaluated_element)?;

    // STEP 3: finalize on client
    let ksf_params = KsfParams::from_bytes(&ke2.payload[..])?;
    let ksf_stretch = |input: &[u8]| argon2_stretch(input, &ksf_params);
    let (ke3, client_session_key, export_key) =
        client_flow.finish(Some(server_identity), &ke2, ksf_stretch)?;

    // STEP 4: finalize on server
    let server_session_key = server_flow.finish(&state, &ke3)?;

    println!("client_session_key: {:?}", client_session_key);
    println!("server_session_key: {:?}", server_session_key);
    println!("export_key: {:?}", export_key);

    Ok(())
}
