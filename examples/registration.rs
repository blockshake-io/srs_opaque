use blstrs::Scalar;
use ff::Field;
use srs_opaque::{
    error::InternalError,
    opaque::{ClientRegistrationFlow, ServerRegistrationFlow},
    primitives::derive_keypair,
};

fn main() -> Result<(), InternalError> {
    let server_oprf_key = Scalar::ONE.double();
    let server_keypair = derive_keypair(b"secret seed", b"public info")?;
    let server_identity = "srs.blockshake.io";

    // STEP 1: initiate registration on client
    let username = "my_username";
    let password = b"password";
    let mut client_flow = ClientRegistrationFlow::new(
        username,
        password,
        &server_keypair.public_key,
        Some(server_identity),
    );
    let registration_request = client_flow.start();

    // STEP 2: proceed registration on server, evaluate OPRF
    let server_flow = ServerRegistrationFlow::new(&server_oprf_key);
    let registration_response = server_flow.start(&registration_request);

    // STEP 3: finish registration on client, create registration record
    // that's sent to the server and an export key that's used locally
    let (registration_record, export_key) = client_flow.finish(&registration_response)?;

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

    Ok(())
}
