#![allow(non_snake_case)]
// We allow non-snake-case fields in this file to match the naming in PresignaturePublicData,
//which is more concise and readable.

use serde::{Deserialize, Serialize};

use cggmp24::generic_ec::Curve;
use cggmp24::signing::PresignaturePublicData;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct StoredPresignaturePublicData<E: Curve> {
    #[serde(with = "ppd_serde")]
    pub public: PresignaturePublicData<E>,
}

mod ppd_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use cggmp24::generic_ec::{Curve, NonZero, Point};
    use cggmp24::signing::{PresignatureCommitment, PresignaturePublicData};

    #[derive(Serialize, Deserialize)]
    #[serde(bound = "")]
    struct PresignaturePublicDataRepr<E: Curve> {
        pub Gamma: NonZero<Point<E>>,
        pub commitments: Vec<PresignatureCommitmentRepr<E>>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(bound = "")]
    struct PresignatureCommitmentRepr<E: Curve> {
        pub tilde_Delta: Point<E>,
        pub tilde_S: Point<E>,
    }

    pub fn serialize<S, E: Curve>(
        value: &PresignaturePublicData<E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let repr = PresignaturePublicDataRepr::<E> {
            Gamma: value.Gamma.clone(),
            commitments: value
                .commitments
                .iter()
                .map(|c| PresignatureCommitmentRepr::<E> {
                    tilde_Delta: c.tilde_Delta.clone(),
                    tilde_S: c.tilde_S.clone(),
                })
                .collect(),
        };
        repr.serialize(serializer)
    }

    pub fn deserialize<'de, D, E: Curve>(
        deserializer: D,
    ) -> Result<PresignaturePublicData<E>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = PresignaturePublicDataRepr::<E>::deserialize(deserializer)?;
        Ok(PresignaturePublicData::<E> {
            Gamma: repr.Gamma,
            commitments: repr
                .commitments
                .into_iter()
                .map(|c| PresignatureCommitment::<E> {
                    tilde_Delta: c.tilde_Delta,
                    tilde_S: c.tilde_S,
                })
                .collect(),
        })
    }
}

pub fn encode_ppd_msgpack<E: Curve>(
    value: &PresignaturePublicData<E>,
) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    let wrapped = StoredPresignaturePublicData {
        public: value.clone(),
    };
    rmp_serde::to_vec_named(&wrapped)
}

pub fn decode_ppd_msgpack<E: Curve>(
    bytes: &[u8],
) -> Result<PresignaturePublicData<E>, rmp_serde::decode::Error> {
    let wrapped: StoredPresignaturePublicData<E> = rmp_serde::from_slice(bytes)?;
    Ok(wrapped.public)
}
