use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub static KEY: [u8; 128] = *b"e62c501c2ea2ad012179e09860bcfacfe99432562bf257fa9a54b22f3adbefc99608dc247aa5b30f9590abe19c64e3056133ec49e663cd8c1667841103065b35";

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub sub: String,
}

pub struct Jwt;

impl Jwt {
    pub fn decode(token: String) -> Claims {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["sub"]);

        let claims =
            jsonwebtoken::decode::<Claims>(&token, &DecodingKey::from_secret(&KEY), &validation);

        claims.unwrap().claims
    }

    pub fn encode(uid: String) -> String {
        let token = jsonwebtoken::encode(
            &Header::default(),
            &Claims { sub: uid },
            &EncodingKey::from_secret(&KEY),
        );

        token.unwrap()
    }
}
