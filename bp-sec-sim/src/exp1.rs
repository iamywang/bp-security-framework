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
    simulator::simulator(pht_exlude_states, "PHT".to_string(), true);

    let btb_ind_exlude_states: Vec<i32> = Vec::new();
    simulator::simulator(btb_ind_exlude_states, "BTB (ind)".to_string(), true);

    let mut btb_call_exlude_states: Vec<i32> = Vec::new();
    btb_call_exlude_states.push(9);
    btb_call_exlude_states.push(10);
    simulator::simulator(btb_call_exlude_states, "BTB (call)".to_string(), true);

    let mut btb_ret_exlude_states: Vec<i32> = Vec::new();
    btb_ret_exlude_states.push(9);
    btb_ret_exlude_states.push(10);
    simulator::simulator(btb_ret_exlude_states, "BTB (ret)".to_string(), true);

    let mut rsb_exlude_states: Vec<i32> = Vec::new();
    rsb_exlude_states.push(7);
    rsb_exlude_states.push(8);
    rsb_exlude_states.push(9);
    rsb_exlude_states.push(10);
    simulator::simulator(rsb_exlude_states, "RSB".to_string(), true);
}

// ============================================================================
// Function: exp1_derivation
// description:
//   - This function is used to derive all three-step vulnerablities.
// ============================================================================
pub fn exp1_derivation() {
    println!("========= BP-SEC-SIM =========");
    baseline_bp();
    println!("== DONE!: BP-SEC-SIM (exp1) ==");
    println!("\n");
}
