use crate::circuit::{MachineHint,ModuleHint,InstructionHint,InstProof,InstDropHint};
use crate::machine::{PoseidonMachine,GenModule};
use ark_bls12_381::Fr;
use crate::circuit::hash::Poseidon;
use crate::circuit::hash::FrHash;
use crate::machine::{gen_hash_stack_frame_stack, gen_hash_pc_stack, gen_hash_value_stack};
use crate::merkle::{GenMerkle,MerkleType};
use crate::circuit::hash::Proof;
use crate::wavm::Opcode;

struct Witness {
    machine_hint: MachineHint,
    proof: InstProof,
    inst: InstructionHint,
    mole: ModuleHint,
    mod_proof: Proof,
    inst_proof: Proof,
    func_proof: Proof,
}

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

    fn witness(&self) -> Option<Witness> {
        // get op
        let params = Params::new();
        let inst = self.get_next_instruction().unwrap();
        match inst.opcode {
            Opcode::Drop => {
                let mut mach = self.clone();
                let v = mach.value_stack.pop().unwrap();
                let machine_hint = mach.hint();
                let proof = InstDropHint {
                    val: v.hint().hash(&params),
                };
                Some(Witness {
                    machine_hint,
                    proof: InstProof::InstDrop(proof),
                    inst: inst.hint(),
                })
            }
            _ => None,
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

