use crate::circuit::{
    MachineHint,ModuleHint,InstructionHint,InstProof,InstDropHint,InstConstHint,InstLocalGetHint,
    StackFrameHint,
};
use crate::machine::{PoseidonMachine,GenModule,StackFrame};
use ark_bls12_381::Fr;
use crate::circuit::hash::Poseidon;
use crate::circuit::hash::FrHash;
use crate::machine::{gen_hash_stack_frame_stack, gen_hash_pc_stack, gen_hash_value_stack};
use crate::merkle::{GenMerkle,MerkleType};
use crate::circuit::hash::Proof;
use crate::wavm::Opcode;
use crate::circuit::hash::Params;
use crate::circuit::Witness;

fn make_proof(loc: usize, proof: Vec<FrHash>) -> Proof {
    let mut selectors = vec![];
    let mut loc = loc;
    for _el in proof.iter() {
        let bit = loc % 2 != 0;
        selectors.push(bit);
        loc = loc/2;
    }
    Proof {
        path: proof.iter().map(|a| a.clone().into()).collect(),
        selectors,
    }
}

impl PoseidonMachine {
    pub fn hint(&self) -> MachineHint {
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

    pub fn witness(&self) -> Option<Witness> {
        // get op
        let params = Params::new();
        let inst = self.get_next_instruction().unwrap();
        let mole = self.modules[self.pc.module].clone();
        let mod_proof = make_proof(self.pc.module, self.get_modules_merkle().prove_gen(self.pc.module).unwrap());
        let func = &mole.funcs[self.pc.func];
        let inst_proof = make_proof(self.pc.inst, func.code_merkle.prove_gen(self.pc.inst).unwrap());
        let func_proof = make_proof(self.pc.func, mole.funcs_merkle.prove_gen(self.pc.func).unwrap());
        match inst.opcode {
            /*
            Opcode::Drop => {
                println!("module hash {}", mole.hash());
                let mut mach = self.clone();
                let v = mach.value_stack.pop().unwrap();
                let machine_hint = mach.hint();
                println!("value hash {}", v.gen_hash::<FrHash,Poseidon>());
                println!("value stack {}", machine_hint.valueStack);
                println!("internal stack {}", machine_hint.internalStack);
                println!("block stack {}", machine_hint.blockStack);
                println!("frame stack {}", machine_hint.frameStack);
                let proof = InstDropHint {
                    val: v.hint().hash(&params),
                };
                Some(Witness {
                    machine_hint,
                    proof: InstProof::Drop(proof),
                    inst: inst.hint(),
                    mole: mole.hint(),
                    mod_proof,
                    func_proof,
                    inst_proof,
                })
            }
            Opcode::I32Const => {
                println!("module hash {}", mole.hash());
                let mut mach = self.clone();
                let machine_hint = mach.hint();
                println!("value stack {}", machine_hint.valueStack);
                println!("internal stack {}", machine_hint.internalStack);
                println!("block stack {}", machine_hint.blockStack);
                println!("frame stack {}", machine_hint.frameStack);
                Some(Witness {
                    machine_hint,
                    proof: InstProof::ConstI32(InstConstHint {}),
                    inst: inst.hint(),
                    mole: mole.hint(),
                    mod_proof,
                    func_proof,
                    inst_proof,
                })
            }
            */
            Opcode::LocalGet => {
                println!("module hash {}", mole.hash());
                let mut mach = self.clone();
                let orig_hint = mach.hint();
                let idx = inst.argument_data as usize;
                let frame = mach.frame_stack.pop().unwrap();
                let locals_merkle: GenMerkle<FrHash,Poseidon> = GenMerkle::new(
                    MerkleType::Value,
                    frame.locals.iter().map(|v| v.gen_hash::<FrHash,Poseidon>()).collect()
                );
                let merkle_proof = make_proof(idx, locals_merkle.prove_gen(idx).unwrap());
                let v = frame.locals[idx];
                let machine_hint = mach.hint();
                println!("local get idx {}", idx);
                println!("value stack {}", machine_hint.valueStack);
                println!("internal stack {}", machine_hint.internalStack);
                println!("block stack {}", machine_hint.blockStack);
                println!("frame stack {} orig {}", machine_hint.frameStack, orig_hint.frameStack);
                println!("frame hash {}", frame.hash::<FrHash,Poseidon>());
                let proof = InstLocalGetHint {
                    val: v.hint().hash(&params), // value to get from local frame
                    proof: merkle_proof,
                    frame: frame.hint(),
                };
                Some(Witness {
                    machine_hint,
                    proof: InstProof::LocalGet(proof),
                    inst: inst.hint(),
                    mole: mole.hint(),
                    mod_proof,
                    func_proof,
                    inst_proof,
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
        println!("func hash {}", self.funcs[0].hash());
        ModuleHint {
            globalsMerkleRoot: merkle.root().into(),
            moduleMemory: self.memory.hash().into(),
            tablesMerkleRoot: self.tables_merkle.root().into(),
            functionsMerkleRoot: self.funcs_merkle.root().into(),
            internalsOffset: Fr::from(self.internals_offset),
        }
    }
}

impl StackFrame {
    fn hint(&self) -> StackFrameHint {
        let merkle : GenMerkle<FrHash,Poseidon> = GenMerkle::new(
            MerkleType::Value,
            self.locals.iter().map(|v| v.gen_hash::<FrHash,Poseidon>()).collect(),
        );
        println!(
            "making hint ret {}, root {}, mole {}, internal {}",
            self.return_ref.gen_hash::<FrHash,Poseidon>(),
            merkle.root(),
            Fr::from(self.caller_module),
            Fr::from(self.caller_module_internals),
        );
        StackFrameHint {
            returnPc: self.return_ref.hint(),
            localsMerkleRoot: merkle.root().into(),
            callerModule: Fr::from(self.caller_module),
            callerModuleInternals: Fr::from(self.caller_module_internals),
        }
    }
}
