// Copyright 2023 iamywang
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ============================================================================
// Branch Predictor Security Evaluation Framework (Symbolic Simulator)
//
// author: iamywang
// date: 2023/06/05
// ============================================================================
use crate::simulator;

// ============================================================================
// Function: baseline_bp
// description:
//   - This function is used to derive all three-step vulnerablities.
// ============================================================================
fn baseline_bp() {
    println!("Branch Predictor");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let btb_ind_exlude_states: Vec<i32> = Vec::new();
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: lock_bp
// description:
//   - This technique removes the $A_{inv}$, $A_{pc}$, $A_{his}$, $A_{alias}$
//     operations for the BTB from the three-step branch predictor.
// ============================================================================
fn lock_bp() {
    println!("Lock-BTB");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let mut btb_ind_exlude_states: Vec<i32> = Vec::new();
    btb_ind_exlude_states.push(3);
    btb_ind_exlude_states.push(7);
    btb_ind_exlude_states.push(9);
    btb_ind_exlude_states.push(11);
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(3);
    btb_call_exlude_states.push(7);
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    btb_call_exlude_states.push(11);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(3);
    btb_ret_exlude_states.push(7);
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    btb_ret_exlude_states.push(11);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: brb_bp
// description:
//   - This technique removes the $A_{pc}$, $A_{his}$ operations for the PHT
//     from the three-step branch predictor.
// ============================================================================
fn brb_bp() {
    println!("BRB");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(7);
    pht_exlude_states.push(9);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let btb_ind_exlude_states: Vec<i32> = Vec::new();
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: noisy_bp
// description:
//   - This technique removes the $A_{pc}$ operation for the PHT from the
//     three-step branch predictor.
//   - This technique removes the $A_{pc}$, $A_{alias}$, $V_{pc}$, $V_{alias}$
//     operations for the BTB from the three-step branch predictor.
// ============================================================================
fn noisy_bp() {
    println!("Noisy-XOR-BP");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(7);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let mut btb_ind_exlude_states: Vec<i32> = Vec::new();
    btb_ind_exlude_states.push(7);
    btb_ind_exlude_states.push(8);
    btb_ind_exlude_states.push(11);
    btb_ind_exlude_states.push(12);
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(7);
    btb_call_exlude_states.push(8);
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    btb_call_exlude_states.push(11);
    btb_call_exlude_states.push(12);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(7);
    btb_ret_exlude_states.push(8);
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    btb_ret_exlude_states.push(11);
    btb_ret_exlude_states.push(12);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: psc_bp
// description:
//   - This technique removes the $A_{pc}$, $A_{his}$, $V_{pc}$, $V_{his}$
//     operations for the PHT from the three-step branch predictor.
// ============================================================================
fn psc_bp() {
    println!("PSC");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(7);
    pht_exlude_states.push(8);
    pht_exlude_states.push(9);
    pht_exlude_states.push(10);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let btb_ind_exlude_states: Vec<i32> = Vec::new();
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: ls_bp
// description:
//   - This technique removes the $A_{pc}$ operation for the PHT from the
//     three-step branch predictor.
//   - This technique removes the $A_{pc}$, $A_{alias}$, $V_{pc}$, $V_{alias}$
//     operations for the BTB from the three-step branch predictor.
// ============================================================================
fn ls_bp() {
    println!("LS-BP");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(7);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let mut btb_ind_exlude_states: Vec<i32> = Vec::new();
    btb_ind_exlude_states.push(7);
    btb_ind_exlude_states.push(8);
    btb_ind_exlude_states.push(11);
    btb_ind_exlude_states.push(12);
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(7);
    btb_call_exlude_states.push(8);
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    btb_call_exlude_states.push(11);
    btb_call_exlude_states.push(12);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(7);
    btb_ret_exlude_states.push(8);
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    btb_ret_exlude_states.push(11);
    btb_ret_exlude_states.push(12);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: hy_bp
// description:
//   - This technique removes the $A_{pc}$ operation for the PHT from the
//     three-step branch predictor.
//   - This technique removes the $A_{inv}$, $A_{pc}$, $A_{alias}$, $V_{inv}$,
//     $V_{pc}$, $V_{alias}$ operations for the BTB from the three-step branch
//     predictor.
// ============================================================================
fn hy_bp() {
    println!("HyBP");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(7);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let mut btb_ind_exlude_states: Vec<i32> = Vec::new();
    btb_ind_exlude_states.push(3);
    btb_ind_exlude_states.push(4);
    btb_ind_exlude_states.push(7);
    btb_ind_exlude_states.push(8);
    btb_ind_exlude_states.push(11);
    btb_ind_exlude_states.push(12);
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(3);
    btb_call_exlude_states.push(4);
    btb_call_exlude_states.push(7);
    btb_call_exlude_states.push(8);
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    btb_call_exlude_states.push(11);
    btb_call_exlude_states.push(12);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(3);
    btb_ret_exlude_states.push(4);
    btb_ret_exlude_states.push(7);
    btb_ret_exlude_states.push(8);
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    btb_ret_exlude_states.push(11);
    btb_ret_exlude_states.push(12);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: csf_stt
// description:
//   - This technique removes the $V_{val}$ operation for the PHT in the second
//     step from the three-step branch predictor.
// ============================================================================
fn csf_stt() {
    println!("CSF-LFENCE/STT");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(6);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let btb_ind_exlude_states: Vec<i32> = Vec::new();
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: invisi_cache
// description:
//   - This technique removes the $A_{cc}$ (cache) operation for the PHT from
//     the three-step branch predictor.
// ============================================================================
fn invisi_cache() {
    println!("InvisiSpec (Cache)");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(0);
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    simulator::spec_simulator(pht_exlude_states, "PHT".to_string(), false);

    let btb_ind_exlude_states: Vec<i32> = Vec::new();
    simulator::spec_simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), false);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    simulator::spec_simulator(btb_call_exlude_states, "BTB (call)".to_string(), false);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    simulator::spec_simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), false);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(3);
    rsb_exlude_states.push(5);
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    rsb_exlude_states.push(11);
    simulator::spec_simulator(rsb_exlude_states, "RSB".to_string(), false);
}

// ============================================================================
// Function: exp3_baseline_bp
// description:
//   - This function is used to evaluate the security of the baseline branch
//     predictor against speculative attacks (with RSB refilling).
// ============================================================================
pub fn exp3_baseline_bp() {
    println!("========= BP-SEC-SIM =========");
    baseline_bp();
    println!("== DONE!: BP-SEC-SIM (exp3) ==");
    println!("\n");
}

// ============================================================================
// Function: exp3_secure_bp
// description:
//   - This function is used to evaluate the security of 8 existing secure
//     branch predictors against speculative attacks (with RSB refilling).
// ============================================================================
pub fn exp3_secure_bp() {
    println!("========= BP-SEC-SIM =========");
    lock_bp();
    println!("==============================");
    brb_bp();
    println!("==============================");
    noisy_bp();
    println!("==============================");
    psc_bp();
    println!("==============================");
    ls_bp();
    println!("==============================");
    hy_bp();
    println!("== DONE!: BP-SEC-SIM (exp3) ==");
    println!("\n");
}

// ============================================================================
// Function: exp3_hw_defenses
// description:
//   - This function is used to evaluate the security of 4 hardware-based
//     defenses against speculative attacks (with RSB refilling).
// ============================================================================
pub fn exp3_hw_defenses() {
    println!("========= BP-SEC-SIM =========");
    invisi_cache();
    println!("==============================");
    csf_stt();
    println!("== DONE!: BP-SEC-SIM (exp3) ==");
    println!("\n");
}
