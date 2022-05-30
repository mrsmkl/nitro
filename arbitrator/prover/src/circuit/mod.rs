use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{
    fields::fp::{AllocatedFp, FpVar},
};
use ark_bls12_381::Fr;
// use ark_relations::r1cs::ConstraintSynthesizer;
// use ark_relations::r1cs::SynthesisError;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::boolean::{ /*AllocatedBool,*/Boolean};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::ToBitsGadget;

use crate::circuit::hash::{Params, poseidon_gadget, Proof, make_path, poseidon};

pub mod hash;
pub mod keccak;

use ark_r1cs_std::R1CSVar;

#[derive(Debug, Clone)]
pub struct Machine {
    valueStack : FpVar<Fr>,
    internalStack : FpVar<Fr>,
    blockStack : FpVar<Fr>,
    frameStack : FpVar<Fr>,

    globalStateHash : FpVar<Fr>,
    moduleIdx : FpVar<Fr>,
    functionIdx : FpVar<Fr>,
    functionPc : FpVar<Fr>,
    modulesRoot : FpVar<Fr>,
}

#[derive(Debug, Clone)]
pub struct MachineHint {
    pub valueStack : Fr,
    pub internalStack : Fr,
    pub blockStack : Fr,
    pub frameStack : Fr,

    pub globalStateHash : Fr,
    pub moduleIdx : Fr,
    pub functionIdx : Fr,
    pub functionPc : Fr,
    pub modulesRoot : Fr,
}

fn witness(cs: &ConstraintSystemRef<Fr>, default: &Fr) -> FpVar<Fr> {
    FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(default.clone())).unwrap())
}

impl MachineHint {
    fn default() -> Self {
        MachineHint {
            valueStack: Fr::from(0),
            internalStack: Fr::from(0),
            blockStack: Fr::from(0),
            frameStack: Fr::from(0),
            globalStateHash: Fr::from(0),
            moduleIdx: Fr::from(0),
            functionIdx: Fr::from(0),
            functionPc: Fr::from(0),
            modulesRoot: Fr::from(0),
        }
    }
    fn convert(&self, cs: ConstraintSystemRef<Fr>) -> Machine {
        Machine {
            valueStack : witness(&cs, &self.valueStack),
            internalStack : witness(&cs, &self.internalStack),
            blockStack : witness(&cs, &self.blockStack),
            frameStack : witness(&cs, &self.frameStack),
        
            globalStateHash : witness(&cs, &self.globalStateHash),
            moduleIdx : witness(&cs, &self.moduleIdx),
            functionIdx : witness(&cs, &self.functionIdx),
            functionPc : witness(&cs, &self.functionPc),
            modulesRoot : witness(&cs, &self.modulesRoot),
        }
    }
}

pub fn hash_machine(params: &Params, mach: &Machine) -> FpVar<Fr> {
    poseidon_gadget(&params, vec![
        mach.valueStack.clone(),
        mach.internalStack.clone(),
        mach.blockStack.clone(),
        mach.frameStack.clone(),
        mach.globalStateHash.clone(),
        mach.moduleIdx.clone(),
        mach.functionIdx.clone(),
        mach.functionPc.clone(),
        mach.modulesRoot.clone(),
    ])
}

#[derive(Debug, Clone)]
pub struct Module {
    globalsMerkleRoot: FpVar<Fr>,
    moduleMemory: FpVar<Fr>,
    tablesMerkleRoot: FpVar<Fr>,
    functionsMerkleRoot: FpVar<Fr>,
    internalsOffset: FpVar<Fr>,
}

#[derive(Debug,Clone)]
pub struct ModuleHint {
    pub globalsMerkleRoot: Fr,
    pub moduleMemory: Fr,
    pub tablesMerkleRoot: Fr,
    pub functionsMerkleRoot: Fr,
    pub internalsOffset: Fr,
}

impl ModuleHint {
    fn default() -> Self {
        ModuleHint {
            globalsMerkleRoot: Fr::from(0),
            moduleMemory: Fr::from(0),
            tablesMerkleRoot: Fr::from(0),
            functionsMerkleRoot: Fr::from(0),
            internalsOffset: Fr::from(0),
        }
    }
    fn convert(&self, cs: ConstraintSystemRef<Fr>) -> Module {
        Module {
            globalsMerkleRoot: witness(&cs, &self.globalsMerkleRoot),
            moduleMemory: witness(&cs, &self.moduleMemory),
            tablesMerkleRoot: witness(&cs, &self.tablesMerkleRoot),
            functionsMerkleRoot: witness(&cs, &self.functionsMerkleRoot),
            internalsOffset: witness(&cs, &self.internalsOffset),
        }
    }
}

pub fn hash_module(params: &Params, mach: &Module) -> FpVar<Fr> {
    poseidon_gadget(&params, vec![
        mach.globalsMerkleRoot.clone(),
        mach.moduleMemory.clone(),
        mach.tablesMerkleRoot.clone(),
        mach.functionsMerkleRoot.clone(),
        mach.internalsOffset.clone(),
    ])
}

#[derive(Debug, Clone)]
pub struct Instruction {
    opcode: FpVar<Fr>,
    argumentData: FpVar<Fr>,
}

fn hash_instruction(params: &Params, inst: &Instruction) -> FpVar<Fr> {
    poseidon_gadget(&params, vec![
        inst.opcode.clone(),
        inst.argumentData.clone(),
    ])
}

#[derive(Debug, Clone)]
pub struct Value {
    value: FpVar<Fr>,
    ty: FpVar<Fr>,
}

#[derive(Debug, Clone)]
pub struct ValueHint {
    pub value: u64,
    pub ty: u32,
}

#[derive(Debug, Clone)]
pub struct InstructionHint {
    pub opcode: u64,
    pub argumentData: u64,
}

impl Value {
    fn default() -> Self {
        Value {
            value: FpVar::constant(Fr::from(0)),
            ty: FpVar::constant(Fr::from(0)),
        }
    }
}

impl ValueHint {
    pub fn hash(&self, params: &Params) -> Fr {
        poseidon(&params, vec![
            Fr::from(self.ty.clone()),
            Fr::from(self.value.clone()),
        ])
    }
    fn default() -> Self {
        ValueHint {
            value: 0,
            ty: 0,
        }
    }
    fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> Value {
        Value {
            value: witness(cs, &Fr::from(self.value)),
            ty: witness(cs, &Fr::from(self.ty)),
        }
    }
}

impl InstructionHint {
    fn default() -> InstructionHint {
        InstructionHint {
            opcode: 0,
            argumentData: 0,
        }
    }
    
    fn convert(&self, cs: ConstraintSystemRef<Fr>) -> Instruction {
        Instruction {
            opcode: FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.opcode))).unwrap()),
            argumentData: FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.argumentData))).unwrap()),
        }
    }
}

fn hash_value(params: &Params, inst: &Value) -> FpVar<Fr> {
    poseidon_gadget(&params, vec![
        inst.ty.clone(),
        inst.value.clone(),
    ])
}

pub fn prove_instr(
    cs: ConstraintSystemRef<Fr>,
    params : &Params,
    machine: &Machine,
    mole: &Module,
    inst_var: FpVar<Fr>,
    mod_proof: &Proof,
    inst_proof: &Proof,
    func_proof: &Proof,
) {
    let mole_hash = hash_module(params, mole);
    println!("Module hash {}", mole_hash.value().unwrap());
    let (mole_root, mole_idx) = make_path(cs.clone(), 16, params, mole_hash, mod_proof);
    mole_root.enforce_equal(&machine.modulesRoot).unwrap();
    println!("Module root {}, idx {}, got {}, got idx {}",
        machine.modulesRoot.value().unwrap(), machine.moduleIdx.value().unwrap(),
        mole_root.value().unwrap(), mole_idx.value().unwrap());
    mole_idx.enforce_equal(&machine.moduleIdx).unwrap();
    println!("Inst hash {} at {}", inst_var.value().unwrap(), machine.functionPc.value().unwrap());
    let (inst_root, inst_idx) = make_path(cs.clone(), 20, params, inst_var.clone(), inst_proof);
    inst_idx.enforce_equal(&machine.functionPc).unwrap();
    println!("Inst root {}, inst idx {}", inst_root.value().unwrap(), inst_idx.value().unwrap());
    let func_hash = poseidon_gadget(&params, vec![inst_root]);
    println!("Func hash {}", func_hash.value().unwrap());
    let (func_root, func_idx) = make_path(cs.clone(), 16, params, func_hash, func_proof);
    func_root.enforce_equal(&mole.functionsMerkleRoot).unwrap();
    func_idx.enforce_equal(&machine.functionIdx).unwrap();
    println!("func root {}, got {}", mole.functionsMerkleRoot.value().unwrap(), func_root.value().unwrap());
    println!("func idx {}, got {}", machine.functionIdx.value().unwrap(), func_idx.value().unwrap());
}

#[derive(Debug, Clone)]
pub struct Stack {
    values: Vec<FpVar<Fr>>,
    base: FpVar<Fr>,
}

// stack: perhaps there should just be several alternatives for different length stacks ...
pub fn hash_stack(
    params : &Params,
    stack: &Stack
) -> FpVar<Fr> {
    // compute root from base
    let mut root = stack.base.clone();
    for el in stack.values.iter() {
        root = poseidon_gadget(&params, vec![
            el.clone(),
            root.clone(),
        ])
    }
    root
}

impl Stack {
    fn push(&mut self, v: FpVar<Fr>) {
        self.values.push(v.clone());
    }
    fn pop(&mut self) -> FpVar<Fr> {
        self.values.pop().unwrap()
    }
    fn peek(&mut self) -> FpVar<Fr> {
        self.values[self.values.len()-1].clone()
    }
    fn based(v: FpVar<Fr>) -> Self {
        Stack {
            values: vec![],
            base: v,
        }
    }
    fn empty() -> Self {
        Stack {
            values: vec![],
            base: FpVar::constant(Fr::from(0)),
        }
    }
}

const I32_TYPE : u32 = 0u32;
const INTERNAL_TYPE_REF : u32 = 6u32;

#[derive(Debug, Clone)]
pub struct MachineWithStack {
    valueStack : Stack,
    internalStack : Stack,
    blockStack : Stack,
    frameStack : Stack,

    globalStateHash : FpVar<Fr>,
    moduleIdx : FpVar<Fr>,
    functionIdx : FpVar<Fr>,
    functionPc : FpVar<Fr>,
    modulesRoot : FpVar<Fr>,

    valid: Boolean<Fr>,
    inst: Instruction, // Must be the correct instruction
    mole: Module,
}

pub fn hash_machine_with_stack(params: &Params, mach: &MachineWithStack) -> FpVar<Fr> {
    hash_machine(params, &elim_stack(params, mach))
}

// There can be savings by sharing the hashing of stacks ...
pub fn elim_stack(params : &Params, mach: &MachineWithStack) -> Machine {
    Machine {
        valueStack : hash_stack(params, &mach.valueStack),
        internalStack : hash_stack(params, &mach.internalStack),
        blockStack : hash_stack(params, &mach.blockStack),
        frameStack : hash_stack(params, &mach.frameStack),
    
        globalStateHash : mach.globalStateHash.clone(),
        moduleIdx : mach.moduleIdx.clone(),
        functionIdx : mach.functionIdx.clone(),
        functionPc : mach.functionPc.clone(),
        modulesRoot : mach.modulesRoot.clone(),
    }
}

fn intro_stack(mach: &Machine, inst: &Instruction, mole: &Module) -> MachineWithStack {
    MachineWithStack {
        valueStack : Stack::based(mach.valueStack.clone()),
        internalStack : Stack::based(mach.internalStack.clone()),
        blockStack : Stack::based(mach.blockStack.clone()),
        frameStack : Stack::based(mach.frameStack.clone()),
    
        globalStateHash : mach.globalStateHash.clone(),
        moduleIdx : mach.moduleIdx.clone(),
        functionIdx : mach.functionIdx.clone(),
        functionPc : mach.functionPc.clone(),
        modulesRoot : mach.modulesRoot.clone(),

        valid: Boolean::constant(true),
        inst: inst.clone(),
        mole: mole.clone(),
    }
}

pub fn check_instruction(mach: &MachineWithStack, expected: u32) -> MachineWithStack {
    let expected = FpVar::constant(Fr::from(expected));
    let mut mach = mach.clone();
    mach.valid = mach.valid.and(&mach.inst.opcode.is_eq(&expected).unwrap()).unwrap();
    mach
}

pub fn change_module(cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack, old_mole: &Module, mod_proof: &Proof) -> MachineWithStack {
    let mole_hash = hash_module(params, &mach.mole);
    let (mole_root, mole_idx) = make_path(cs.clone(), 16, params, mole_hash, mod_proof);

    let old_mole_hash = hash_module(params, &old_mole);
    let (old_mole_root, old_mole_idx) = make_path(cs.clone(), 16, params, old_mole_hash, mod_proof);

    let mut mach = mach.clone();
    mach.valid = mach.valid.and(&old_mole_idx.is_eq(&mach.moduleIdx).unwrap()).unwrap();
    mach.valid = mach.valid.and(&mole_idx.is_eq(&mach.moduleIdx).unwrap()).unwrap();
    mach.valid = mach.valid.and(&old_mole_root.is_eq(&mach.modulesRoot).unwrap()).unwrap();
    mach.modulesRoot = mole_root;
    mach
}

pub fn execute_const(params: &Params, mach: &MachineWithStack, ty: u32) -> MachineWithStack {
    let mut mach = mach.clone();
    let v = Value {
        value: mach.inst.argumentData.clone(),
        ty: FpVar::constant(Fr::from(ty)),
    };
    mach.valueStack.push(hash_value(params, &v));
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

trait Inst {
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack);
    fn code(&self) -> u32;
    fn execute(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let (before, after) = self.execute_internal(params, mach);
        let after = check_instruction(&after, self.code());
        (before, after)
    }
}

trait InstCS {
    fn execute_internal(&self, cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack);
    fn code(&self) -> u32;
    fn execute(&self, cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let (before, after) = self.execute_internal(cs, params, mach);
        let after = check_instruction(&after, self.code());
        (before, after)
    }
}

#[derive(Debug,Clone)]
pub struct InstConstHint {
}

struct InstConst {
    ty: u32,
}

fn default_instruction() -> InstructionHint {
    InstructionHint {
        opcode: 0,
        argumentData: 0,
    }
}

fn convert_instruction(hint: InstructionHint, cs: ConstraintSystemRef<Fr>) -> Instruction {
    Instruction {
        opcode: FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(hint.opcode))).unwrap()),
        argumentData: FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(hint.argumentData))).unwrap()),
    }
}

impl InstConstHint {
    fn default() -> Self {
        InstConstHint { }
    }
    fn convert(&self, _cs: &ConstraintSystemRef<Fr>, ty: u32) -> InstConst {
        InstConst {
            ty,
        }
    }
}

impl Inst for InstConst {
    fn code(&self) -> u32 {
        match self.ty {
            0 => 0x41,
            1 => 0x42,
            2 => 0x43,
            3 => 0x44,
            _ => panic!("bad constant type"),
        }
    }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let before = mach.clone();
        let after = execute_const(params, mach, self.ty);
        (before, after)
    }
}

/*
fn empty_machine() -> MachineWithStack {
    MachineWithStack {
        valueStack: Stack::empty(),
        internalStack: Stack::empty(),
        blockStack: Stack::empty(),
        frameStack: Stack::empty(),

        globalStateHash: FpVar::constant(Fr::from(0)),
        moduleIdx: FpVar::constant(Fr::from(0)),
        functionIdx: FpVar::constant(Fr::from(0)),
        functionPc: FpVar::constant(Fr::from(0)),
        modulesRoot: FpVar::constant(Fr::from(0)),

        valid: Boolean::constant(false),
    }    
}
*/

pub fn enforce_i32(v: FpVar<Fr>) {
    let bits = v.to_bits_le().unwrap();
    let res = Boolean::le_bits_to_fp_var(&bits[0..32]).unwrap();
    res.enforce_equal(&v).unwrap();
}

pub fn execute_drop(_params: &Params, mach: &MachineWithStack) -> MachineWithStack {
    let mut mach = mach.clone();
    let _popped = mach.valueStack.pop();
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

#[derive(Debug,Clone)]
pub struct InstDropHint {
    pub val: Fr,
}

pub struct InstDrop {
    val: FpVar<Fr>,
}

impl Inst for InstDrop {
    fn code(&self) -> u32 {
        0x1A
    }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.valueStack.push(self.val.clone());
        println!("drop value {}", self.val.value().unwrap());
        let before = mach.clone();
        let after = execute_drop(params, &mach);
        let before_elim = elim_stack(params, &before);
        let after_elim = elim_stack(params, &after);
        (before, after)
    }
}

impl InstDropHint {
    pub fn default() -> Self {
        InstDropHint {
            val: Fr::from(0),
        }
    }
    fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstDrop {
        InstDrop {
            val: FpVar::Var(AllocatedFp::<Fr>::new_witness(cs.clone(), || Ok(self.val)).unwrap()),
        }
    }
}

/*
fn drop_default_machine() -> MachineWithStack {
    let mut mach = empty_machine();
    mach.valueStack.push(FpVar::constant(Fr::from(0)));
    mach
}
*/

pub fn execute_select(_params: &Params, mach: &MachineWithStack) -> MachineWithStack {
    let mut mach = mach.clone();
    let selector = mach.valueStack.pop();
    let b = mach.valueStack.pop();
    let a = mach.valueStack.pop();

    let sel_bool = selector.is_eq(&FpVar::constant(Fr::from(0))).unwrap();
    let a_b = sel_bool.select(&a, &b).unwrap();
    mach.valueStack.push(a_b);
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

struct InstSelect {
    val1: FpVar<Fr>,
    val2: FpVar<Fr>,
    val3: FpVar<Fr>,
}

#[derive(Debug,Clone)]
pub struct InstSelectHint {
    val1: Fr,
    val2: Fr,
    val3: Fr,
}

impl Inst for InstSelect {
    fn code(&self) -> u32 { 23 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.valueStack.push(self.val1.clone());
        mach.valueStack.push(self.val2.clone());
        mach.valueStack.push(self.val3.clone());
        let before = mach.clone();
        let after = execute_select(params, &mach);
        (before, after)
    }
}

impl InstSelectHint {
    pub fn default() -> Self {
        InstSelectHint {
            val1: Fr::from(0),
            val2: Fr::from(0),
            val3: Fr::from(0),
        }
    }
    fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstSelect {
        InstSelect {
            val1: witness(&cs, &self.val1),
            val2: witness(&cs, &self.val2),
            val3: witness(&cs, &self.val3),
        }
    }
}

pub fn execute_block(_params: &Params, mach: &MachineWithStack) -> MachineWithStack {
    let mut mach = mach.clone();
    let target_pc = mach.functionPc.clone();
    enforce_i32(target_pc.clone());
    mach.blockStack.push(target_pc);
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

#[derive(Debug,Clone)]
pub struct InstBlockHint {
}

struct InstBlock {
}

impl Inst for InstBlock {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let before = mach.clone();
        let after = execute_block(params, &mach);
        (before, after)
    }
}

impl InstBlockHint {
    pub fn default() -> Self {
        InstBlockHint {
        }
    }
    fn convert(&self, _cs: &ConstraintSystemRef<Fr>) -> InstBlock {
        InstBlock {
        }
    }
}

pub fn execute_branch(_params: &Params, mach: &MachineWithStack) -> MachineWithStack {
    let mut mach = mach.clone();
    mach.functionPc = mach.blockStack.pop();
    mach
}

pub struct InstBranch {
    val: FpVar<Fr>,
    block: FpVar<Fr>,
}

#[derive(Debug,Clone)]
pub struct InstBranchHint {
    val: Fr,
    block: Fr,
}

impl Inst for InstBranch {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.valueStack.push(self.val.clone());
        mach.blockStack.push(self.block.clone());
        let before = mach.clone();
        let after = execute_branch(params, &mach);
        (before, after)
    }
}

impl InstBranchHint {
    pub fn default() -> Self {
        InstBranchHint {
            val: Fr::from(0),
            block: Fr::from(0),
        }
    }
    fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstBranch {
        InstBranch {
            val: witness(&cs, &self.val),
            block: witness(&cs, &self.block),
        }
    }
}

pub fn execute_branch_if(params: &Params, mach: &MachineWithStack) -> MachineWithStack {
    let mut mach = mach.clone();
    let selector = mach.valueStack.pop();

    let sel_bool = selector.is_eq(&FpVar::constant(Fr::from(0))).unwrap();
    // There are two alternative block stacks, they have to be computed here
    let mut bs_1 = mach.blockStack.clone();
    let bs_2 = mach.blockStack.clone();
    let _popped = bs_1.pop();

    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach.functionPc = sel_bool.select(&mach.blockStack.pop(), &mach.functionPc).unwrap();
    mach.blockStack = Stack::based(sel_bool.select(&hash_stack(params, &bs_1), &hash_stack(params, &bs_2)).unwrap());
    mach
}

pub struct InstBranchIf {
    val1: FpVar<Fr>,
    val2: FpVar<Fr>,
    block: FpVar<Fr>,
}

#[derive(Debug,Clone)]
pub struct InstBranchIfHint {
    val1: Fr,
    val2: Fr,
    block: Fr,
}

impl Inst for InstBranchIf {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.valueStack.push(self.val1.clone());
        mach.valueStack.push(self.val2.clone());
        mach.blockStack.push(self.block.clone());
        let before = mach.clone();
        let after = execute_branch_if(params, &mach);
        (before, after)
    }
}

impl InstBranchIfHint {
    pub fn default() -> Self {
        InstBranchIfHint {
            val1: Fr::from(0),
            val2: Fr::from(0),
            block: Fr::from(0),
        }
    }
    fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstBranchIf {
        InstBranchIf {
            val1: witness(&cs, &self.val1),
            val2: witness(&cs, &self.val2),
            block: witness(&cs, &self.block),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    returnPc: Value,
    localsMerkleRoot: FpVar<Fr>,
    callerModule: FpVar<Fr>,
    callerModuleInternals: FpVar<Fr>,
}

#[derive(Debug, Clone)]
pub struct StackFrameHint {
    pub returnPc: ValueHint,
    pub localsMerkleRoot: Fr,
    pub callerModule: Fr,
    pub callerModuleInternals: Fr,
}

impl StackFrame {
    fn default() -> Self {
        StackFrame {
            returnPc: Value::default(),
            localsMerkleRoot: FpVar::constant(Fr::from(0)),
            callerModule: FpVar::constant(Fr::from(0)),
            callerModuleInternals: FpVar::constant(Fr::from(0)),
        }
    }
}

impl StackFrameHint {
    fn default() -> Self {
        StackFrameHint {
            returnPc: ValueHint::default(),
            localsMerkleRoot: Fr::from(0),
            callerModule: Fr::from(0),
            callerModuleInternals: Fr::from(0),
        }
    }
    fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> StackFrame {
        StackFrame {
            returnPc: self.returnPc.convert(cs),
            localsMerkleRoot: witness(cs, &self.localsMerkleRoot),
            callerModule: witness(cs, &self.callerModule),
            callerModuleInternals: witness(cs, &self.callerModuleInternals),
        }
    }
}

fn hash_stack_frame(params: &Params, frame: &StackFrame) -> FpVar<Fr> {
    poseidon_gadget(&params, vec![
        hash_value(params, &frame.returnPc),
        frame.localsMerkleRoot.clone(),
        frame.callerModule.clone(),
        frame.callerModuleInternals.clone(),
    ])
}

pub fn execute_return(params: &Params, mach: &MachineWithStack, frame: &StackFrame) -> MachineWithStack {
    let mut mach = mach.clone();
    let type_eq = frame.returnPc.ty.is_eq(&FpVar::constant(Fr::from(INTERNAL_TYPE_REF))).unwrap();
    let frame_hash = mach.frameStack.pop();
    let hash_eq = frame_hash.is_eq(&hash_stack_frame(&params, frame)).unwrap();
    mach.valid = mach.valid.and(&hash_eq).unwrap().and(&type_eq).unwrap();
    let data = frame.returnPc.value.to_bits_le().unwrap();
    mach.functionPc = Boolean::le_bits_to_fp_var(&data[0..32]).unwrap();
    mach.functionIdx = Boolean::le_bits_to_fp_var(&data[32..64]).unwrap();
    mach.moduleIdx = Boolean::le_bits_to_fp_var(&data[64..96]).unwrap();
    mach
}

#[derive(Debug,Clone)]
pub struct InstReturnHint {
    pub frame: StackFrameHint,
}

pub struct InstReturn {
    frame: StackFrame,
}

impl Inst for InstReturn {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.frameStack.push(hash_stack_frame(&params, &self.frame));
        let before = mach.clone();
        let after = execute_return(params, &mach, &self.frame);
        (before, after)
    }
}

impl InstReturnHint {
    pub fn default() -> Self {
        InstReturnHint { frame: StackFrameHint::default() }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstReturn {
        InstReturn { frame: self.frame.convert(cs) }
    }
}

fn create_return_value(mach: &MachineWithStack) -> Value {
    let value =
        mach.functionPc.clone() +
        mach.functionIdx.clone() * FpVar::constant(Fr::from(1u128 << 32)) +
        mach.moduleIdx.clone() * FpVar::constant(Fr::from(1u128 << 64));
    Value {
        value,
        ty: FpVar::constant(Fr::from(INTERNAL_TYPE_REF)),
    }
}

fn create_i32_value(value: FpVar<Fr>) -> Value {
    enforce_i32(value.clone());
    Value { value, ty: FpVar::constant(Fr::from(I32_TYPE)) }
}

pub fn execute_call(params: &Params, mach: &MachineWithStack, frame: &StackFrame) -> MachineWithStack {
    let mut mach = mach.clone();
    mach.valueStack.push(hash_value(params, &create_return_value(&mach)));
    mach.frameStack.peek().enforce_equal(&hash_stack_frame(params, frame)).unwrap();
    mach.valueStack.push(hash_value(params, &create_i32_value(frame.callerModule.clone())));
    mach.valueStack.push(hash_value(params, &create_i32_value(frame.callerModuleInternals.clone())));
    mach.functionIdx = mach.inst.argumentData.clone();
    enforce_i32(mach.inst.argumentData.clone());
    mach.functionPc = FpVar::constant(Fr::from(0));
    mach
}

pub struct InstCall {
    frame: StackFrame,
}

#[derive(Debug,Clone)]
pub struct InstCallHint {
    frame: StackFrameHint,
}

impl Inst for InstCall {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.frameStack.push(hash_stack_frame(&params, &self.frame));
        let before = mach.clone();
        let after = execute_call(params, &mach, &self.frame);
        (before, after)
    }
}

impl InstCallHint {
    pub fn default() -> Self {
        InstCallHint { frame: StackFrameHint::default() }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstCall {
        InstCall { frame: self.frame.convert(cs) }
    }
}

pub fn execute_cross_module_call(params: &Params, mach: &MachineWithStack) -> MachineWithStack {
    let mut mach = mach.clone();
    mach.valueStack.push(hash_value(params, &create_return_value(&mach)));
    mach.valueStack.push(hash_value(params, &create_i32_value(mach.moduleIdx.clone())));
    mach.valueStack.push(hash_value(params, &create_i32_value(mach.mole.internalsOffset.clone())));
    let data = mach.inst.argumentData.to_bits_le().unwrap();
    mach.functionIdx = Boolean::le_bits_to_fp_var(&data[0..32]).unwrap();
    mach.moduleIdx = Boolean::le_bits_to_fp_var(&data[32..64]).unwrap();
    mach.functionPc = FpVar::constant(Fr::from(0));
    mach
}

pub struct InstCrossCall {
}

#[derive(Debug,Clone)]
pub struct InstCrossCallHint {
}

impl Inst for InstCrossCall {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mach = mach.clone();
        let before = mach.clone();
        let after = execute_cross_module_call(params, &mach);
        (before, after)
    }
}

impl InstCrossCallHint {
    pub fn default() -> Self {
        InstCrossCallHint { }
    }
    pub fn convert(&self, _cs: &ConstraintSystemRef<Fr>) -> InstCrossCall {
        InstCrossCall {  }
    }
}

pub fn execute_local_get(cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack, proof: &Proof, var: FpVar<Fr>, frame: &StackFrame) -> MachineWithStack {
    let mut mach = mach.clone();
    let (root, idx) = make_path(cs.clone(), 20, params, var.clone(), proof);
    mach.frameStack.peek().enforce_equal(&hash_stack_frame(params, frame)).unwrap();
    mach.valid = mach.valid.and(&root.is_eq(&frame.localsMerkleRoot).unwrap()).unwrap();
    mach.valid = mach.valid.and(&idx.is_eq(&mach.inst.argumentData).unwrap()).unwrap();
    mach.valueStack.push(var);
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

pub struct InstLocalGet {
    frame: StackFrame,
    val: FpVar<Fr>,
    proof: Proof,
}

#[derive(Debug,Clone)]
pub struct InstLocalGetHint {
    frame: StackFrameHint,
    val: Fr,
    proof: Proof,
}

impl InstCS for InstLocalGet {
    fn code(&self) -> u32 { 0x20 }
    fn execute_internal(&self, cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.frameStack.push(hash_stack_frame(&params, &self.frame));
        let before = mach.clone();
        let after = execute_local_get(cs.clone(), params, &mach, &self.proof, self.val.clone(), &self.frame);
        (before, after)
    }
}

impl InstLocalGetHint {
    pub fn default() -> Self {
        InstLocalGetHint {
            frame: StackFrameHint::default(),
            val: Fr::from(0),
            proof: Proof::default(),
        }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstLocalGet {
        InstLocalGet {
            frame: self.frame.convert(cs),
            val: witness(cs, &self.val),
            proof: self.proof.clone(),
        }
    }
}

pub fn execute_local_set(cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack, inst: &Instruction, proof: &Proof, old_var: &FpVar<Fr>, frame: &StackFrame) -> MachineWithStack {
    let mut mach = mach.clone();
    let var = mach.valueStack.pop();
    let (root, idx) = make_path(cs.clone(), 20, params, old_var.clone(), proof);
    mach.frameStack.pop().enforce_equal(&hash_stack_frame(params, frame)).unwrap();
    mach.valid = mach.valid.and(&root.is_eq(&frame.localsMerkleRoot).unwrap()).unwrap();
    mach.valid = mach.valid.and(&idx.is_eq(&inst.argumentData).unwrap()).unwrap();
    let (root2, idx2) = make_path(cs.clone(), 20, params, var.clone(), proof);
    idx2.enforce_equal(&idx).unwrap();
    let mut frame = frame.clone();
    frame.localsMerkleRoot = root2;
    mach.frameStack.push(hash_stack_frame(params, &frame));
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

pub struct InstLocalSet {
    frame: StackFrame,
    val: FpVar<Fr>,
    old_val: FpVar<Fr>,
    proof: Proof,
}

#[derive(Debug,Clone)]
pub struct InstLocalSetHint {
    frame: StackFrameHint,
    val: Fr,
    old_val: Fr,
    proof: Proof,
}

impl InstCS for InstLocalSet {
    fn code(&self) -> u32 { 0x21 }
    fn execute_internal(&self, cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.frameStack.push(hash_stack_frame(&params, &self.frame));
        mach.valueStack.push(self.old_val.clone());
        let before = mach.clone();
        let after = execute_local_get(cs.clone(), params, &mach, &self.proof, self.val.clone(), &self.frame);
        (before, after)
    }
}

impl InstLocalSetHint {
    pub fn default() -> Self {
        InstLocalSetHint {
            frame: StackFrameHint::default(),
            val: Fr::from(0),
            old_val: Fr::from(0),
            proof: Proof::default(),
        }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstLocalSet {
        InstLocalSet {
            frame: self.frame.convert(cs),
            val: witness(cs, &self.val),
            old_val: witness(cs, &self.old_val),
            proof: self.proof.clone(),
        }
    }
}

pub fn execute_global_get(cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack, proof: &Proof, var: FpVar<Fr>) -> MachineWithStack {
    let mut mach = mach.clone();
    let (root, idx) = make_path(cs.clone(), 20, params, var.clone(), proof);
    mach.valid = mach.valid.and(&root.is_eq(&mach.mole.globalsMerkleRoot).unwrap()).unwrap();
    mach.valid = mach.valid.and(&idx.is_eq(&mach.inst.argumentData).unwrap()).unwrap();
    mach.valueStack.push(var);
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

pub struct InstGlobalGet {
    val: FpVar<Fr>,
    proof: Proof,
}

#[derive(Debug,Clone)]
pub struct InstGlobalGetHint {
    val: Fr,
    proof: Proof,
}

impl InstCS for InstGlobalGet {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mach = mach.clone();
        let before = mach.clone();
        let after = execute_global_get(cs.clone(), params, &mach, &self.proof, self.val.clone());
        (before, after)
    }
}

impl InstGlobalGetHint {
    pub fn default() -> Self {
        InstGlobalGetHint {
            val: Fr::from(0),
            proof: Proof::default(),
        }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstGlobalGet {
        InstGlobalGet {
            val: witness(cs, &self.val),
            proof: self.proof.clone(),
        }
    }
}

pub fn execute_global_set(cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack, proof: &Proof, old_var: &FpVar<Fr>) -> MachineWithStack {
    let mut mach = mach.clone();
    let var = mach.valueStack.pop();
    let (root, idx) = make_path(cs.clone(), 20, params, old_var.clone(), proof);
    mach.valid = mach.valid.and(&root.is_eq(&mach.mole.globalsMerkleRoot).unwrap()).unwrap();
    mach.valid = mach.valid.and(&idx.is_eq(&mach.inst.argumentData).unwrap()).unwrap();
    let (root2, idx2) = make_path(cs.clone(), 20, params, var.clone(), proof);
    idx2.enforce_equal(&idx).unwrap();
    let mut mole = mach.mole.clone();
    mole.globalsMerkleRoot = root2;
    mach.mole = mole;
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

pub struct InstGlobalSet {
    val: FpVar<Fr>,
    old_val: FpVar<Fr>,
    proof: Proof,
    mod_proof: Proof,
}

#[derive(Debug,Clone)]
pub struct InstGlobalSetHint {
    val: Fr,
    old_val: Fr,
    proof: Proof,
    mod_proof: Proof,
}

impl InstCS for InstGlobalSet {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, cs: ConstraintSystemRef<Fr>, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.valueStack.push(self.old_val.clone());
        let before = mach.clone();
        let after = execute_global_get(cs.clone(), params, &mach, &self.proof, self.val.clone());
        let after = change_module(cs.clone(), params, &after, &before.mole, &self.mod_proof);
        (before, after)
    }
}

impl InstGlobalSetHint {
    pub fn default() -> Self {
        InstGlobalSetHint {
            val: Fr::from(0),
            old_val: Fr::from(0),
            proof: Proof::default(),
            mod_proof: Proof::default(),
        }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstGlobalSet {
        InstGlobalSet {
            val: witness(cs, &self.val),
            old_val: witness(cs, &self.old_val),
            proof: self.proof.clone(),
            mod_proof: self.mod_proof.clone(),
        }
    }
}

// TODO: set module after global set

pub fn execute_init_frame(params: &Params, mach: &MachineWithStack, returnPc: &Value) -> MachineWithStack {
    let mut mach = mach.clone();
    let callerModuleInternals = mach.valueStack.pop();
    let callerModule = mach.valueStack.pop();
    let returnPcHash = mach.valueStack.pop();
    mach.valid = mach.valid.and(&hash_value(params, &returnPc).is_eq(&returnPcHash).unwrap()).unwrap();
    let frame = StackFrame {
        callerModuleInternals,
        callerModule,
        returnPc: returnPc.clone(),
        localsMerkleRoot: mach.inst.argumentData.clone(),
    };
    mach.frameStack.push(hash_stack_frame(params, &frame));
    mach.functionPc = mach.functionPc.clone() + FpVar::constant(Fr::from(1));
    mach
}

pub struct InstInitFrame {
    val1: FpVar<Fr>,
    val2: FpVar<Fr>,
    val3: FpVar<Fr>,
    return_pc: Value,
}

#[derive(Debug,Clone)]
pub struct InstInitFrameHint {
    val1: Fr,
    val2: Fr,
    val3: Fr,
    return_pc: ValueHint,
}

impl Inst for InstInitFrame {
    fn code(&self) -> u32 { 234 }
    fn execute_internal(&self, params: &Params, mach: &MachineWithStack) -> (MachineWithStack, MachineWithStack) {
        let mut mach = mach.clone();
        mach.valueStack.push(self.val1.clone());
        mach.valueStack.push(self.val2.clone());
        mach.valueStack.push(self.val3.clone());
        let before = mach.clone();
        let after = execute_init_frame(params, &mach, &self.return_pc);
        (before, after)
    }
}

impl InstInitFrameHint {
    pub fn default() -> Self {
        InstInitFrameHint {
            val1: Fr::from(0),
            val2: Fr::from(0),
            val3: Fr::from(0),
            return_pc: ValueHint::default(),
        }
    }
    pub fn convert(&self, cs: &ConstraintSystemRef<Fr>) -> InstInitFrame {
        InstInitFrame {
            val1: witness(cs, &self.val1),
            val2: witness(cs, &self.val2),
            val3: witness(cs, &self.val3),
            return_pc: self.return_pc.convert(cs),
        }
    }
}

/* Combining instructions, how should it work.
   Probably need a lot of witness variables...
in the end, maybe just select a valid alternative
*/

#[derive(Debug,Clone)]
pub enum InstProof {
    ConstI32(InstConstHint),
    ConstI64(InstConstHint),
    ConstF32(InstConstHint),
    ConstF64(InstConstHint),
    Drop(InstDropHint),
    Select(InstSelectHint),
    Branch(InstBranchHint),
    BranchIf(InstBranchIfHint),
    Block(InstBlockHint),
    Return(InstReturnHint),
    Call(InstCallHint),
    CrossCall(InstCrossCallHint),
    LocalGet(InstLocalGetHint),
    LocalSet(InstLocalSetHint),
    GlobalGet(InstGlobalGetHint),
    GlobalSet(InstGlobalSetHint),
    InitFrame(InstInitFrameHint),
}

struct InstWitness {
    const_i32: InstConst,
    const_i64: InstConst,
    const_f32: InstConst,
    const_f64: InstConst,
    drop: InstDrop,
    select: InstSelect,
    branch: InstBranch,
    branch_if: InstBranchIf,
    block: InstBlock,
    retvrn: InstReturn,
    call: InstCall,
    cross_call: InstCrossCall,
    local_get: InstLocalGet,
    local_set: InstLocalSet,
    global_get: InstGlobalGet,
    global_set: InstGlobalSet,
    init_frame: InstInitFrame,
}

fn proof_to_witness(proof: InstProof, cs: ConstraintSystemRef<Fr>) -> InstWitness {
    let mut hint_const_i32 = InstConstHint::default();
    let mut hint_const_i64 = InstConstHint::default();
    let mut hint_const_f32 = InstConstHint::default();
    let mut hint_const_f64 = InstConstHint::default();
    let mut hint_drop = InstDropHint::default();
    let mut hint_select = InstSelectHint::default();
    let mut hint_branch = InstBranchHint::default();
    let mut hint_branch_if = InstBranchIfHint::default();
    let mut hint_block = InstBlockHint::default();
    let mut hint_return = InstReturnHint::default();
    let mut hint_call = InstCallHint::default();
    let mut hint_cross_call = InstCrossCallHint::default();
    let mut hint_local_get = InstLocalGetHint::default();
    let mut hint_local_set = InstLocalSetHint::default();
    let mut hint_global_get = InstGlobalGetHint::default();
    let mut hint_global_set = InstGlobalSetHint::default();
    let mut hint_init_frame = InstInitFrameHint::default();
    use crate::circuit::InstProof::*;
    match proof {
        ConstI32(hint) => {
            hint_const_i32 = hint;
        }
        ConstI64(hint) => {
            hint_const_i64 = hint;
        }
        ConstF32(hint) => {
            hint_const_f32 = hint;
        }
        ConstF64(hint) => {
            hint_const_f64 = hint;
        }
        Drop(hint) => {
            hint_drop = hint;
        }
        Select(hint) => {
            hint_select = hint;
        }
        Branch(hint) => {
            hint_branch = hint;
        }
        BranchIf(hint) => {
            hint_branch_if = hint;
        }
        Block(hint) => {
            hint_block = hint;
        }
        Return(hint) => {
            hint_return = hint;
        }
        Call(hint) => {
            hint_call = hint;
        }
        CrossCall(hint) => {
            hint_cross_call = hint;
        }
        LocalGet(hint) => {
            hint_local_get = hint;
        }
        LocalSet(hint) => {
            hint_local_set = hint;
        }
        GlobalGet(hint) => {
            hint_global_get = hint;
        }
        GlobalSet(hint) => {
            hint_global_set = hint;
        }
        InitFrame(hint) => {
            hint_init_frame = hint;
        }
    };
    InstWitness {
        const_i32: hint_const_i32.convert(&cs, 0),
        const_i64: hint_const_i64.convert(&cs, 1),
        const_f32: hint_const_f32.convert(&cs, 2),
        const_f64: hint_const_f64.convert(&cs, 3),
        drop: hint_drop.convert(&cs),
        select: hint_select.convert(&cs),
        branch: hint_branch.convert(&cs),
        branch_if: hint_branch_if.convert(&cs),
        block: hint_block.convert(&cs),
        retvrn: hint_return.convert(&cs),
        call: hint_call.convert(&cs),
        cross_call: hint_cross_call.convert(&cs),
        local_get: hint_local_get.convert(&cs),
        local_set: hint_local_set.convert(&cs),
        global_get: hint_global_get.convert(&cs),
        global_set: hint_global_set.convert(&cs),
        init_frame: hint_init_frame.convert(&cs),
    }
}

fn select_machine(params: &Params, v: Vec<(MachineWithStack, MachineWithStack)>) -> (FpVar<Fr>, FpVar<Fr>) {
    let mut valid = FpVar::constant(Fr::from(0));
    let mut before = FpVar::constant(Fr::from(0));
    let mut after = FpVar::constant(Fr::from(0));
    for (be,af) in v {
        let is_valid : FpVar<Fr> = From::from(af.valid.clone());
        valid = valid + is_valid.clone();
        let hash_be = hash_machine_with_stack(params, &be);
        let hash_af = hash_machine_with_stack(params, &af);
        before = before + hash_be*is_valid.clone();
        after = after + hash_af*is_valid.clone();
    }
    valid.enforce_equal(&FpVar::constant(Fr::from(1))).unwrap();
    (before, after)
}

fn make_proof(
    cs: ConstraintSystemRef<Fr>,
    params: &Params,
    machine_hint: &MachineHint,
    proof: InstProof,
    inst: InstructionHint,
    mole: &ModuleHint,
    mod_proof: &Proof,
    inst_proof: &Proof,
    func_proof: &Proof
) -> (FpVar<Fr>, FpVar<Fr>) {
    let base_machine = machine_hint.convert(cs.clone());
    let inst = convert_instruction(inst, cs.clone());
    let mole = mole.convert(cs.clone());

    let inst_hashed = hash_instruction(params, &inst);

    // Base machine is enough for correctness of the instruction
    prove_instr(
        cs.clone(),
        params,
        &base_machine,
        &mole,
        inst_hashed,
        mod_proof,
        inst_proof,
        func_proof,
    );

    let base_machine = intro_stack(&base_machine, &inst, &mole);
    let witness = proof_to_witness(proof, cs.clone());
    let const_i32 = witness.const_i32.execute(params, &base_machine);
    let const_i64 = witness.const_i64.execute(params, &base_machine);
    let const_f32 = witness.const_f32.execute(params, &base_machine);
    let const_f64 = witness.const_f64.execute(params, &base_machine);
    let drop = witness.drop.execute(params, &base_machine);
    let select = witness.select.execute(params, &base_machine);
    let branch = witness.branch.execute(params, &base_machine);
    let branch_if = witness.branch_if.execute(params, &base_machine);
    let block = witness.block.execute(params, &base_machine);
    let retvrn = witness.retvrn.execute(params, &base_machine);
    let call = witness.call.execute(params, &base_machine);
    let cross_call = witness.cross_call.execute(params, &base_machine);
    let local_get = witness.local_get.execute(cs.clone(), params, &base_machine);
    let local_set = witness.local_set.execute(cs.clone(), params, &base_machine);
    let global_get = witness.global_get.execute(cs.clone(), params, &base_machine);
    let global_set = witness.global_set.execute(cs.clone(), params, &base_machine);
    let init_frame = witness.init_frame.execute(params, &base_machine);

    select_machine(params, vec![
        const_i32,
        const_i64,
        const_f32,
        const_f64,
        drop,
        select,
        branch,
        branch_if,
        block,
        retvrn,
        call,
        cross_call,
        local_get,
        local_set,
        global_get,
        global_set,
        init_frame,
    ])
}

#[derive(Debug,Clone)]
pub struct Witness {
    pub machine_hint: MachineHint,
    pub proof: InstProof,
    pub inst: InstructionHint,
    pub mole: ModuleHint,
    pub mod_proof: Proof,
    pub inst_proof: Proof,
    pub func_proof: Proof,
}

pub fn test(w: Witness) {
    use ark_relations::r1cs::ConstraintSystem;
    let cs_sys = ConstraintSystem::<Fr>::new();
    let cs = ConstraintSystemRef::new(cs_sys);
    let params = Params::new();
    let (before, after) = make_proof(
        cs.clone(),
        &params,
        &w.machine_hint,
        w.proof,
        w.inst,
        &w.mole,
        &w.mod_proof,
        &w.inst_proof,
        &w.func_proof,
    );
    println!("constraints {} {}", cs.num_constraints(), cs.is_satisfied().unwrap());
    println!("before {}, after {}", before.value().unwrap(), after.value().unwrap());
}

