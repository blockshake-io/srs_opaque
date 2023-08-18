use blstrs::{G2Affine, Gt};

pub struct RegistrationRequest {
    pub blinded_element: G2Affine,
    pub username: String,
}

pub struct RegistrationResponse {
    pub evaluated_element: Gt,
}
