use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
};
use ark_bn254::Fr;
// use ark_relations::r1cs::ConstraintSynthesizer;
//use ark_relations::r1cs::SynthesisError;
use ark_relations::r1cs::ConstraintSystemRef;
//use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::ConstraintSystem;

use ark_std::UniformRand;
use ark_ff::{Field,PrimeField,BigInteger};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;

use ark_r1cs_std::boolean::AllocatedBool;
use ark_r1cs_std::boolean::Boolean;
use crate::{Hasher,HashResult};
use serde::{Serialize,Deserialize};
use crate::Bytes32;
use sha3::Keccak256;
use digest::Digest;

use crate::circuit::poseidon_constants::{poseidon_c, poseidon_m};

#[derive(Debug,Clone,Default,Eq,PartialEq/*,Serialize,Deserialize*/)]
pub struct Params {
    c: Vec<Fr>,
    m: Vec<Vec<Fr>>,
}

fn keccak(arg: Bytes32) -> Bytes32 {
    let mut hasher = Keccak256::new();
    hasher.update(arg);
    hasher.finalize().into()
}

impl Params {
    /*
    pub const fn new() -> Self {
        let mut rng = Bytes32::default();
        let mut c = vec![];
        for _i in 0..1000 {
            rng = keccak(rng);
            c.push(vec_to_fr(&rng.clone().into()))
        }
        let mut m = vec![];
        for _i in 0..20 {
            let mut a = vec![];
            for _j in 0..20 {
                rng = keccak(rng);
                a.push(vec_to_fr(&rng.clone().into()))
            }
            m.push(a)
        }
        Params { c, m }
    }*/
    pub fn new() -> Self {
        let mut rng = 0u64;
        let mut c = vec![];
        for _i in 0..1000 {
            rng = rng + 2;
            c.push(Fr::from(rng))
        }
        let mut m = vec![];
        for _i in 0..20 {
            let mut a = vec![];
            for _j in 0..20 {
                rng = rng + 2;
                a.push(Fr::from(rng))
            }
            m.push(a)
        }
        Params { c, m }
    }
}

fn sigma(a: Fr) -> Fr {
    let a2 = a.square();
    let a4 = a2.square();
    a4*a
}

fn ark(v: Vec<Fr>, size: usize, round: usize) -> Vec<Fr> {
    let mut res = vec![];
    for i in 0..v.len() {
        res.push(v[i] + poseidon_c(size, i + round));
    }
    res
}

fn mix(v: Vec<Fr>, size: usize) -> Vec<Fr> {
    let mut res = vec![];
    for i in 0..v.len() {
        let mut lc = Fr::from(0);
        for j in 0..v.len() {
            lc += poseidon_m(size, i, j)*v[j];
        }
        res.push(lc)
    }
    res
}

pub fn poseidon(params: &Params, inputs: Vec<Fr>) -> Fr {
    let n_rounds_p: Vec<usize> = vec![56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
    let size = inputs.len();
    let t = inputs.len() + 1;
    let nRoundsF = 8;
    let nRoundsP = n_rounds_p[t - 2];

    let mut mix_out = vec![];
    for j in 0..t {
        if j > 0 {
            mix_out.push(inputs[j-1])
        } else {
            mix_out.push(Fr::from(0));
        }
    }
    for i in 0..(nRoundsF + nRoundsP) {
        println!("round mix out {} {}", i, mix_out[0]);
        let ark_out = ark(mix_out.clone(), size, t*i);
        println!("round ark out {} {}", i, ark_out[0]);
        let mut mix_in = vec![];
        if i < nRoundsF/2 || i >= nRoundsP + nRoundsF/2 {
            for j in 0..t {
                mix_in.push(sigma(ark_out[j]))
            }
        } else {
            mix_in.push(sigma(ark_out[0]));
            for j in 1..t {
                mix_in.push(ark_out[j])
            }
        }
        println!("round mix in {} {}", i, mix_in[0]);
        mix_out = mix(mix_in, size);
    }
    mix_out[0]
}

#[derive(Debug,Clone,Default,Eq,PartialEq,Serialize,Deserialize)]
pub struct Poseidon {
    #[serde(skip)]
    params: Params,
    #[serde(skip)]
    elems: Vec<Fr>,
}

#[derive(Debug,Clone,Default,Eq,PartialEq,Serialize,Deserialize,Hash)]
pub struct FrHash {
    #[serde(skip)]
    hash: Fr
}

impl FrHash {
    fn new(hash: Fr) -> Self {
        FrHash {
            hash
        }
    }
}

impl std::fmt::Display for FrHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash)
    }
}

impl From<u32> for FrHash {
    fn from(x: u32) -> Self {
        FrHash::new(Fr::from(x))
    }
}

impl Into<Vec<u8>> for FrHash {
    fn into(self) -> Vec<u8> {
        self.hash.into_repr().to_bytes_be()
    }
}

impl Into<Fr> for FrHash {
    fn into(self) -> Fr {
        self.hash.clone()
    }
}

impl HashResult for FrHash {
}

pub fn vec_to_fr(v: &Vec<u8>) -> Fr {
    let mut res = Fr::from(0);
    for e in v.iter() {
        res = res*Fr::from(256) + Fr::from(*e);
    }
    res
}

pub fn bytes32_to_fr(arg: &Bytes32) -> Fr {
    let v : Vec<u8> = arg.clone().into();
    vec_to_fr(&v)
}

impl Hasher<FrHash> for Poseidon {
    fn make() -> Self {
        Poseidon {
            params: Params::new(),
            elems: vec![],
        }
    }
    fn update_title(&mut self, b: &[u8]) {
        // self.i.update(b)
    }
    fn update_u64(&mut self, arg: u64) {
        self.elems.push(Fr::from(arg))
    }
    fn update_usize(&mut self, arg: usize) {
        self.elems.push(Fr::from(arg as u64))
    }
    fn update_u32(&mut self, arg: u32) {
        self.elems.push(Fr::from(arg))
    }
    fn update_hash(&mut self, arg: &FrHash) {
        self.elems.push(arg.hash)
    }
    fn update_bytes32(&mut self, arg: &Bytes32) {
        let v : Vec<u8> = arg.clone().into();
        self.elems.push(vec_to_fr(&v))
    }
    fn update_vec(&mut self, arg: &[u8]) {
        self.elems.push(vec_to_fr(&arg.to_vec()))
    }
    fn result(&mut self) -> FrHash {
        let res = poseidon(&self.params, self.elems.clone());
        self.elems = vec![];
        FrHash::new(res)
    }
}

fn sigma_gadget(a: FpVar<Fr>) -> FpVar<Fr> {
    let a2 = a.square().unwrap();
    let a4 = a2.square().unwrap();
    a4*a
}

fn ark_gadget(v: Vec<FpVar<Fr>>, size: usize, round: usize) -> Vec<FpVar<Fr>> {
    let mut res = vec![];

    for i in 0..v.len() {
        res.push(v[i].clone() + FpVar::Constant(poseidon_c(size, i + round)));
    }
    res
}

fn mix_gadget(v: Vec<FpVar<Fr>>, size: usize) -> Vec<FpVar<Fr>> {
    let mut res = vec![];
    for i in 0..v.len() {
        let mut lc = FpVar::Constant(poseidon_m(size,i,0))*v[0].clone();
        for j in 1..v.len() {
            lc += FpVar::Constant(poseidon_m(size,i,j))*v[j].clone();
        }
        res.push(lc)
    }
    res
}

pub fn poseidon_gadget(params: &Params, inputs: Vec<FpVar<Fr>>) -> FpVar<Fr> {
    let n_rounds_p: Vec<usize> = vec![56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
    let t = inputs.len() + 1;
    let size = inputs.len();
    let nRoundsF = 8;
    let nRoundsP = n_rounds_p[t - 2];

    let mut mix_out = vec![];
    for j in 0..t {
        if j > 0 {
            mix_out.push(inputs[j-1].clone())
        } else {
            mix_out.push(FpVar::Constant(Fr::from(0)));
        }
    }
    for i in 0..(nRoundsF + nRoundsP) {
        let ark_out = ark_gadget(mix_out.clone(), size, t*i);
        let mut mix_in = vec![];
        if i < nRoundsF/2 || i >= nRoundsP + nRoundsF/2 {
            for j in 0..t {
                mix_in.push(sigma_gadget(ark_out[j].clone()))
            }
        } else {
            mix_in.push(sigma_gadget(ark_out[0].clone()));
            for j in 1..t {
                mix_in.push(ark_out[j].clone())
            }
        }
        mix_out = mix_gadget(mix_in, size);
    }
    mix_out[0].clone()
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub path: Vec<Fr>,
    pub selectors: Vec<bool>,
}

impl Proof {
    pub fn default() -> Self {
        Proof {
            path: vec![],
            selectors: vec![],
        }
    }
}

// gadget for variable length merkle tree
// returns the root and index of first elem
pub fn make_path(cs: ConstraintSystemRef<Fr>, num: usize, params : &Params, elem: FpVar<Fr>, proof: &Proof) -> (FpVar<Fr>, FpVar<Fr>) {
    let mut acc = elem.clone();
    let path = &proof.path;
    let selectors = &proof.selectors;
    let mut idx = FpVar::constant(Fr::from(0));
    let mut pow2 = FpVar::constant(Fr::from(1));
    for i in 0..num {
        let elem = if path.len() > i { path[i] } else { Fr::from(0) };
        let sel = if selectors.len() > i { selectors[i] } else { false };
        let skip = selectors.len() <= i;
        let sel_bool = Boolean::from(AllocatedBool::<Fr>::new_witness(cs.clone(), || Ok(sel)).unwrap());
        let skip_bool = Boolean::from(AllocatedBool::<Fr>::new_witness(cs.clone(), || Ok(skip)).unwrap()); // these might need a correctness check (perhaps not)
        let new_idx = idx.clone() + sel_bool.select(&pow2, &FpVar::constant(Fr::from(0))).unwrap();
        let new_pow2 = pow2.clone() + pow2.clone();

        let elem_var = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(elem.clone())).unwrap());
        let leaf1 = sel_bool.select(&elem_var, &acc).unwrap();
        let leaf2 = sel_bool.select(&acc, &elem_var).unwrap();
        let new_acc = poseidon_gadget(&params, vec![leaf1, leaf2]);

        pow2 = skip_bool.select(&pow2, &new_pow2).unwrap();
        acc = skip_bool.select(&acc, &new_acc).unwrap();
        idx = skip_bool.select(&idx, &new_idx).unwrap();
    }
    (acc, idx)
}

pub fn test() {
    let cs_sys = ConstraintSystem::<Fr>::new();
    let cs = ConstraintSystemRef::new(cs_sys);
    let params = Params::new();
    println!("hash {}", poseidon(&params, vec![Fr::from(123), Fr::from(123), Fr::from(123)]));
    let v1 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let v2 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let v3 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let v4 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let v5 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let v6 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let _v7 = FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(123))).unwrap());
    let res = poseidon_gadget(&params, vec![v1, v2, v3]);
    println!("gadget {}", res.value().unwrap());
    println!("constraints {}", cs.num_constraints());
}
