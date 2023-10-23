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
// date: 2023/10/05
// ============================================================================
use crate::simulator;

// ============================================================================
// Function: tage_whole_bp
// description:
//   - This function is used to derive all three-step vulnerablities for TAGE,
//     where all tagged tables are modeled as a single unit.
// ============================================================================
fn tage_whole_bp() {
    println!("TAGE whole");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(9);
    pht_exlude_states.push(10);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    pht_exlude_states.push(17);
    pht_exlude_states.push(18);
    pht_exlude_states.push(19);
    pht_exlude_states.push(20);
    pht_exlude_states.push(21);
    pht_exlude_states.push(22);
    pht_exlude_states.push(23);
    pht_exlude_states.push(24);
    pht_exlude_states.push(25);
    pht_exlude_states.push(26);
    pht_exlude_states.push(27);
    pht_exlude_states.push(28);
    pht_exlude_states.push(29);
    pht_exlude_states.push(30);
    pht_exlude_states.push(31);
    pht_exlude_states.push(32);
    pht_exlude_states.push(33);
    pht_exlude_states.push(34);
    pht_exlude_states.push(35);
    pht_exlude_states.push(36);
    simulator::tage_simulator(pht_exlude_states, "PHT".to_string(), false);
}

// ============================================================================
// Function: tage_sep_bp
// description:
//   - This function is used to derive all three-step vulnerablities for TAGE,
//     where each tagged table is modeled as a separate unit.
// ============================================================================
fn tage_sep_bp() {
    println!("TAGE separate");
    let mut pht_exlude_states: Vec<i32> = Vec::new();
    pht_exlude_states.push(3);
    pht_exlude_states.push(4);
    pht_exlude_states.push(9);
    pht_exlude_states.push(10);
    pht_exlude_states.push(11);
    pht_exlude_states.push(12);
    pht_exlude_states.push(17);
    pht_exlude_states.push(18);
    pht_exlude_states.push(23);
    pht_exlude_states.push(24);
    pht_exlude_states.push(29);
    pht_exlude_states.push(30);
    pht_exlude_states.push(35);
    pht_exlude_states.push(36);
    simulator::tage_simulator(pht_exlude_states, "PHT".to_string(), false);
}

// ============================================================================
// Function: exp4_tage
// description:
//   - This function is used to derive all three-step vulnerablities for TAGE.
// ============================================================================
pub fn exp4_tage() {
    println!("========= BP-SEC-SIM =========");
    tage_whole_bp();
    println!("==============================");
    tage_sep_bp();
    println!("== DONE!: BP-SEC-SIM (exp4) ==");
    println!("\n");
}
