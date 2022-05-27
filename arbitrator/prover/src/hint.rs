use crate::circuit::{MachineHint,ModuleHint};
use crate::machine::{PoseidonMachine,GenModule};
use ark_bls12_381::Fr;
use crate::circuit::hash::Poseidon;
use crate::circuit::hash::FrHash;
use crate::machine::{gen_hash_stack_frame_stack, gen_hash_pc_stack, gen_hash_value_stack};
use crate::merkle::{GenMerkle,MerkleType};

impl PoseidonMachine {
    fn hint(&self) -> MachineHint {
        MachineHint {
            valueStack: gen_hash_value_stack::<FrHash,Poseidon>(&self.value_stack).into(),
            internalStack: gen_hash_value_stack::<FrHash,Poseidon>(&self.internal_stack).into(),
            blockStack: gen_hash_pc_stack::<FrHash,Poseidon>(&self.block_stack).into(),
            frameStack: gen_hash_stack_frame_stack::<FrHash,Poseidon>(&self.frame_stack).into(),
            
            globalStateHash: self.global_state.gen_hash::<FrHash,Poseidon>().into(),
            moduleIdx: Fr::from(self.pc.module as u64),
            functionIdx: Fr::from(self.pc.func as u64),
            functionPc: Fr::from(self.pc.inst as u64),
            modulesRoot: self.get_modules_root().into(),
        }
    }
}

type PoseidonModule = GenModule<FrHash, Poseidon>;

impl PoseidonModule {
    fn hint(&self) -> ModuleHint {
        let merkle : GenMerkle<FrHash,Poseidon> = GenMerkle::new(
            MerkleType::Value,
            self.globals.iter().map(|v| v.gen_hash::<FrHash,Poseidon>()).collect(),
        );
        ModuleHint {
            globalsMerkleRoot: merkle.root().into(),
            moduleMemory: self.memory.hash().into(),
            tablesMerkleRoot: self.tables_merkle.root().into(),
            functionsMerkleRoot: self.funcs_merkle.root().into(),
            internalsOffset: Fr::from(self.internals_offset),
        }
    }
}

