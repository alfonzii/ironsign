use serde::{Deserialize, Serialize};

// adjust to real paths in your project
use cggmp24::generic_ec::Curve;
use cggmp24::signing::{Presignature, PresignaturePublicData};

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct StoredPresignature<E: Curve> {
    pub presig: Presignature<E>,

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

// Optional convenience helpers you can call from other files.
pub fn encode_msgpack<T: Serialize>(value: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(value)
}

pub fn decode_msgpack<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
}
