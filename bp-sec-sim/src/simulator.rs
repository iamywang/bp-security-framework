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
// date: 2023/12/15
// ============================================================================
use std::collections::HashMap;

// ============================================================================
// Function: simulator
// args:
//   - exclude_states: states that should not be included in the simulator
//   - bp_type: type of branch predictor
//   - print_res: whether to print the result
//
// description:
//   - This function simulates the three-step branch predictor.
//   - The simulator will exclude the states in the exclude_states.
// ============================================================================
pub fn simulator(exclude_states: Vec<i32>, bp_type: String, print_res: bool) {
    let for_poc_gen: bool = false;
    let total_states: i32 = 13;
    let mut strong_vulnerabilities: i32 = 0;
    let mut strong_internal_hit: i32 = 0;
    let mut strong_internal_miss: i32 = 0;
    let mut strong_external_hit: i32 = 0;
    let mut strong_external_miss: i32 = 0;
    let mut strong_transient: i32 = 0;

    let mut state_to_string: HashMap<i32, String> = HashMap::new();

    if for_poc_gen == true {
        state_to_string.insert(0, "ACC".to_string());
        state_to_string.insert(1, "ASTAR".to_string());
        state_to_string.insert(2, "VSTAR".to_string());
        state_to_string.insert(3, "AINV".to_string());
        state_to_string.insert(4, "VINV".to_string());
        state_to_string.insert(5, "AVAL".to_string());
        state_to_string.insert(6, "VVAL".to_string());
        state_to_string.insert(7, "APC".to_string());
        state_to_string.insert(8, "VPC".to_string());
        state_to_string.insert(9, "AHIS".to_string());
        state_to_string.insert(10, "VHIS".to_string());
        state_to_string.insert(11, "AALIAS".to_string());
        state_to_string.insert(12, "VALIAS".to_string());
    } else {
        state_to_string.insert(0, "$A_{cc}$".to_string());
        state_to_string.insert(1, "$A_{\\star}$".to_string());
        state_to_string.insert(2, "$V_{\\star}$".to_string());
        state_to_string.insert(3, "$A_{inv}$".to_string());
        state_to_string.insert(4, "$V_{inv}$".to_string());
        state_to_string.insert(5, "$A_{val}$".to_string());
        state_to_string.insert(6, "$V_{val}$".to_string());
        state_to_string.insert(7, "$A_{pc}$".to_string());
        state_to_string.insert(8, "$V_{pc}$".to_string());
        state_to_string.insert(9, "$A_{his}$".to_string());
        state_to_string.insert(10, "$V_{his}$".to_string());
        state_to_string.insert(11, "$A_{alias}$".to_string());
        state_to_string.insert(12, "$V_{alias}$".to_string());
    }

    let mut state_update: HashMap<i32, i32> = HashMap::new();
    state_update.insert(0, 0); // unknown state
    state_update.insert(1, 0); // unknown state
    state_update.insert(2, 0); // unknown state
    state_update.insert(3, -1); // invalid state
    state_update.insert(4, -1); // invalid state
    state_update.insert(5, 1); // valid state
    state_update.insert(6, 1); // valid state
    state_update.insert(7, 2); // mispredict state
    state_update.insert(8, 2); // mispredict state
    state_update.insert(9, 2); // mispredict state
    state_update.insert(10, 2); // mispredict state
    state_update.insert(11, 2); // mispredict state
    state_update.insert(12, 2); // mispredict state

    let mut path_to_vulnerability: HashMap<i32, String> = HashMap::new();

    if for_poc_gen == true {
        path_to_vulnerability.insert(0, "UNKNOWN".to_string());
        path_to_vulnerability.insert(1, "FAST".to_string());
        path_to_vulnerability.insert(2, "SLOW".to_string());
    } else {
        path_to_vulnerability.insert(0, "unknown".to_string());
        path_to_vulnerability.insert(1, "fast".to_string());
        path_to_vulnerability.insert(2, "slow".to_string());
    }

    let mut tsca: Vec<String> = Vec::new();
    let mut tea: Vec<String> = Vec::new();

    let secret_op: i32 = 6;

    // loop
    for i in 0..total_states {
        if exclude_states.contains(&i) {
            continue;
        }

        // reduction rule: remove $A_{cc}$ in the first step
        if i == 0 {
            continue;
        }

        // reduction rule: remove $V_{\\star}$ in the first step
        if i == 2 {
            continue;
        }

        // reduction rule: remove $A_{val}$ in the first step
        if i == 5 {
            continue;
        }
        for j in 0..total_states {
            if exclude_states.contains(&j) {
                continue;
            }

            // reduction rule: merge same operation
            if i == j {
                continue;
            }

            // reduction rule: remove $A_{cc}$ in the second step
            if j == 0 {
                continue;
            }

            // reduction rule: remove $A_{\\star}$ and $V_{\\star}$ in the second step
            if j == 1 || j == 2 {
                continue;
            }

            // reduction rule: remove $A_{val}$ in the second step
            if j == 5 {
                continue;
            }
            for k in 0..total_states {
                if exclude_states.contains(&k) {
                    continue;
                }

                // reduction rule: merge same operation
                if (j == k) && (j != secret_op) {
                    continue;
                }

                // reduction rule: remove $A_{\\star}$ and $V_{\\star}$ in the third step
                if k == 1 || k == 2 {
                    continue;
                }

                // reduction rule: remove $A_{val}$ in the third step
                if k == 5 {
                    continue;
                }

                // reduction rule: continue if the three-step does not contain $V_{val}$
                if !(vec![i, j, k].contains(&secret_op)) {
                    continue;
                }

                // steps: {i->j->k}
                let mut paths: Vec<i32> = Vec::new();
                let mut timing: Vec<i32> = Vec::new();
                let mut covert_channel: bool = false;

                // step 1
                if i == secret_op {
                    paths.push(0);
                }
                paths.push(state_update.get(&i).copied().unwrap());

                // step 2
                if j == secret_op {
                    let paths_size = paths.len();
                    for p in 0..paths_size {
                        paths.push(state_update.get(&j).copied().unwrap());

                        // covert channel
                        if paths[p] == 2 {
                            covert_channel = true;
                        }
                    }
                } else {
                    let paths_size = paths.len();
                    for p in 0..paths_size {
                        if state_update.get(&j).copied().unwrap() != 0 {
                            paths[p] = state_update.get(&j).copied().unwrap();
                        }
                    }
                }

                // step 3
                if paths.len() < 2 {
                    continue;
                }

                if k == 0 && covert_channel == true {
                    strong_vulnerabilities += 1;

                    if for_poc_gen == true {
                        tea.push(format!(
                            "vulnerablities.push_back(pattern({}, {}, {}, FAST, TEA));",
                            state_to_string.get(&i).unwrap(),
                            state_to_string.get(&j).unwrap(),
                            state_to_string.get(&k).unwrap()
                        ));
                    } else {
                        tea.push(format!(
                            "& {} & {} & {} ($fast$) & EH & TEA & ",
                            state_to_string.get(&i).unwrap(),
                            state_to_string.get(&j).unwrap(),
                            state_to_string.get(&k).unwrap()
                        ));
                    }
                    strong_external_hit += 1;
                    strong_transient += 1;
                    continue;
                }

                // calculate timing
                for p in 0..paths.len() {
                    // state is 0 unknown
                    if paths[p] == 0 {
                        timing.push(0);
                    }
                    // state is -1 invalid
                    else if paths[p] == -1 {
                        // invalid + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // invalid + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // invalid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(2);
                        }
                        // invalid + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 1 valid
                    else if paths[p] == 1 {
                        // valid + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // valid + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(1);
                        }
                        // valid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(2);
                        }
                        // valid + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 2 mispredict
                    else if paths[p] == 2 {
                        // mispredict + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // mispredict + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(1);
                        }
                        // mispredict + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                }

                // output
                if timing[0] != timing[1] && timing[0] != 0 && timing[1] != 0 {
                    strong_vulnerabilities += 1;
                    // internal or external, hit-based or miss-based
                    let mut attack_category: String = "".to_string();
                    if state_to_string.get(&j).unwrap().contains("$V_")
                        && state_to_string.get(&k).unwrap().contains("$V_")
                    {
                        if timing[1] == 1 {
                            attack_category = "IH".to_string();
                            strong_internal_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "IM".to_string();
                            strong_internal_miss += 1;
                        }
                    } else {
                        if timing[1] == 1 {
                            attack_category = "EH".to_string();
                            strong_external_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "EM".to_string();
                            strong_external_miss += 1;
                        }
                    }

                    if for_poc_gen == true {
                        tsca.push(format!(
                            "vulnerablities.push_back(pattern({}, {}, {}, {}, TSCA));",
                            state_to_string.get(&i).unwrap(),
                            state_to_string.get(&j).unwrap(),
                            state_to_string.get(&k).unwrap(),
                            path_to_vulnerability.get(&timing[1]).unwrap()
                        ));
                    } else {
                        tsca.push(format!(
                            "& {} & {} & {} (${}$) & {} & TSCA/CCA & ",
                            state_to_string.get(&i).unwrap(),
                            state_to_string.get(&j).unwrap(),
                            state_to_string.get(&k).unwrap(),
                            path_to_vulnerability.get(&timing[1]).unwrap(),
                            attack_category,
                        ));
                    }
                } else if timing[0] != timing[1] {
                    // weak vulnerability, ignore
                } else if i == secret_op && k == secret_op && j != 3 && j != 4 {
                    strong_vulnerabilities += 1;
                    let mut attack_category: String = "".to_string();
                    if state_to_string.get(&j).unwrap().contains("$V_")
                        && state_to_string.get(&k).unwrap().contains("$V_")
                    {
                        if timing[1] == 1 {
                            attack_category = "IH".to_string();
                            strong_internal_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "IM".to_string();
                            strong_internal_miss += 1;
                        }
                    } else {
                        if timing[1] == 1 {
                            attack_category = "EH".to_string();
                            strong_external_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "EM".to_string();
                            strong_external_miss += 1;
                        }
                    }

                    if for_poc_gen == true {
                        tsca.push(format!(
                            "vulnerablities.push_back(pattern({}, {}, {}, {}, TSCA));",
                            state_to_string.get(&i).unwrap(),
                            state_to_string.get(&j).unwrap(),
                            state_to_string.get(&k).unwrap(),
                            path_to_vulnerability.get(&timing[1]).unwrap()
                        ));
                    } else {
                        tsca.push(format!(
                            "& {} & {} & {} (${}$) & {} & TSCA/CCA & ",
                            state_to_string.get(&i).unwrap(),
                            state_to_string.get(&j).unwrap(),
                            state_to_string.get(&k).unwrap(),
                            path_to_vulnerability.get(&timing[1]).unwrap(),
                            attack_category,
                        ));
                    }
                }
            }
        }
    }

    println!("bp_type: {}", bp_type);
    println!("strong vulnerabilities: {}", strong_vulnerabilities);
    println!("strong internal hit: {}", strong_internal_hit);
    println!("strong internal miss: {}", strong_internal_miss);
    println!("strong external hit: {}", strong_external_hit);
    println!("strong external miss: {}", strong_external_miss);
    println!("strong transient: {}", strong_transient);
    if print_res == true {
        for i in 0..tsca.len() {
            if i % 2 == 0 {
                println!("{}", tsca[i]);
            } else {
                if for_poc_gen == true {
                    println!("{}", tsca[i]);
                } else {
                    println!("{}\\\\", tsca[i]);
                }
            }
        }
        for i in 0..tea.len() {
            if i % 2 == 0 {
                println!("{}", tea[i]);
            } else {
                if for_poc_gen == true {
                    println!("{}", tea[i]);
                } else {
                    println!("{}\\\\", tea[i]);
                }
            }
        }
    }
}

// ============================================================================
// Function: spec_simulator
// args:
//   - exclude_states: states that should not be included in the simulator
//   - bp_type: type of branch predictor
//   - print_res: whether to print the result
//
// description:
//   - This function simulates the three-step branch predictor.
//   - The simulator will exclude the states in the exclude_states.
// ============================================================================
pub fn spec_simulator(exclude_states: Vec<i32>, bp_type: String, print_res: bool) {
    let total_states: i32 = 13;
    let mut strong_transient: i32 = 0;

    let mut state_to_string: HashMap<i32, String> = HashMap::new();
    state_to_string.insert(0, "$A_{cc}$".to_string());
    state_to_string.insert(1, "$A_{\\star}$".to_string());
    state_to_string.insert(2, "$V_{\\star}$".to_string());
    state_to_string.insert(3, "$A_{inv}$".to_string());
    state_to_string.insert(4, "$V_{inv}$".to_string());
    state_to_string.insert(5, "$A_{val}$".to_string());
    state_to_string.insert(6, "$V_{val}$".to_string());
    state_to_string.insert(7, "$A_{pc}$".to_string());
    state_to_string.insert(8, "$V_{pc}$".to_string());
    state_to_string.insert(9, "$A_{his}$".to_string());
    state_to_string.insert(10, "$V_{his}$".to_string());
    state_to_string.insert(11, "$A_{alias}$".to_string());
    state_to_string.insert(12, "$V_{alias}$".to_string());

    let mut state_update: HashMap<i32, i32> = HashMap::new();
    state_update.insert(0, 0); // unknown state
    state_update.insert(1, 0); // unknown state
    state_update.insert(2, 0); // unknown state
    state_update.insert(3, -1); // invalid state
    state_update.insert(4, -1); // invalid state
    state_update.insert(5, 1); // valid state
    state_update.insert(6, 1); // valid state
    state_update.insert(7, 2); // mispredict state
    state_update.insert(8, 2); // mispredict state
    state_update.insert(9, 2); // mispredict state
    state_update.insert(10, 2); // mispredict state
    state_update.insert(11, 2); // mispredict state
    state_update.insert(12, 2); // mispredict state

    let mut tea: Vec<String> = Vec::new();

    let secret_op: i32 = 6;

    // loop
    for i in 0..total_states {
        if exclude_states.contains(&i) {
            continue;
        }

        // reduction rule: remove $A_{cc}$ in the first step
        if i == 0 {
            continue;
        }

        // reduction rule: remove $V_{\\star}$ in the first step
        if i == 2 {
            continue;
        }

        // reduction rule: remove $A_{val}$ in the first step
        if i == 5 {
            continue;
        }
        for j in 0..total_states {
            if exclude_states.contains(&j) {
                continue;
            }

            // reduction rule: merge same operation
            if i == j {
                continue;
            }

            // reduction rule: remove $A_{cc}$ in the second step
            if j == 0 {
                continue;
            }

            // reduction rule: remove $A_{\\star}$ and $V_{\\star}$ in the second step
            if j == 1 || j == 2 {
                continue;
            }

            // reduction rule: remove $A_{val}$ in the second step
            if j == 5 {
                continue;
            }
            for k in 0..total_states {
                if exclude_states.contains(&k) {
                    continue;
                }

                // reduction rule: merge same operation
                if (j == k) && (j != secret_op) {
                    continue;
                }

                // reduction rule: remove $A_{\\star}$ and $V_{\\star}$ in the third step
                if k == 1 || k == 2 {
                    continue;
                }

                // reduction rule: remove $A_{val}$ in the third step
                if k == 5 {
                    continue;
                }

                // reduction rule: continue if the three-step does not contain $V_{val}$
                if !(vec![i, j, k].contains(&secret_op)) {
                    continue;
                }

                // steps: {i->j->k}
                let mut paths: Vec<i32> = Vec::new();
                let mut covert_channel: bool = false;

                // step 1
                if i == secret_op {
                    paths.push(0);
                }
                paths.push(state_update.get(&i).copied().unwrap());

                // step 2
                if j == secret_op {
                    let paths_size = paths.len();
                    for p in 0..paths_size {
                        paths.push(state_update.get(&j).copied().unwrap());

                        // covert channel
                        if paths[p] == 2 {
                            covert_channel = true;
                        }
                    }
                } else {
                    let paths_size = paths.len();
                    for p in 0..paths_size {
                        if state_update.get(&j).copied().unwrap() != 0 {
                            paths[p] = state_update.get(&j).copied().unwrap();
                        }
                    }
                }

                // step 3
                if paths.len() < 2 {
                    continue;
                }

                if k == 0 && covert_channel == true {
                    tea.push(format!(
                        "& {} & {} & {} ($fast$) & EH & TEA & ",
                        state_to_string.get(&i).unwrap(),
                        state_to_string.get(&j).unwrap(),
                        state_to_string.get(&k).unwrap()
                    ));
                    strong_transient += 1;
                    continue;
                }
            }
        }
    }

    println!("bp_type: {}", bp_type);
    println!("strong transient: {}", strong_transient);
    if print_res == true {
        for i in 0..tea.len() {
            if i % 2 == 0 {
                println!("{}", tea[i]);
            } else {
                println!("{}\\\\", tea[i]);
            }
        }
    }
}

// ============================================================================
// Function: tage_simulator
// args:
//   - exclude_states: states that should not be included in the simulator
//   - bp_type: type of branch predictor
//   - print_res: whether to print the result
//
// description:
//   - This function simulates the three-step branch predictor.
//   - The simulator will exclude the states in the exclude_states.
// ============================================================================
pub fn tage_simulator(exclude_states: Vec<i32>, bp_type: String, print_res: bool) {
    let total_states: i32 = 37;
    let mut strong_vulnerabilities: i32 = 0;
    let mut strong_internal_hit: i32 = 0;
    let mut strong_internal_miss: i32 = 0;
    let mut strong_external_hit: i32 = 0;
    let mut strong_external_miss: i32 = 0;
    let mut strong_transient: i32 = 0;

    let mut state_to_string: HashMap<i32, String> = HashMap::new();
    state_to_string.insert(0, "$A_{cc}$".to_string());
    state_to_string.insert(1, "$A_{\\star}$".to_string());
    state_to_string.insert(2, "$V_{\\star}$".to_string());
    state_to_string.insert(3, "$A_{inv}$".to_string());
    state_to_string.insert(4, "$V_{inv}$".to_string());
    state_to_string.insert(5, "$A_{val}$".to_string());
    state_to_string.insert(6, "$V_{val}$".to_string());
    state_to_string.insert(7, "$A_{pc}$".to_string());
    state_to_string.insert(8, "$V_{pc}$".to_string());
    state_to_string.insert(9, "$A_{his}$".to_string());
    state_to_string.insert(10, "$V_{his}$".to_string());
    state_to_string.insert(11, "$A_{alias}$".to_string());
    state_to_string.insert(12, "$V_{alias}$".to_string());
    state_to_string.insert(13, "$A_{pc1}$".to_string());
    state_to_string.insert(14, "$V_{pc1}$".to_string());
    state_to_string.insert(15, "$A_{his1}$".to_string());
    state_to_string.insert(16, "$V_{his1}$".to_string());
    state_to_string.insert(17, "$A_{alias1}$".to_string());
    state_to_string.insert(18, "$V_{alias1}$".to_string());
    state_to_string.insert(19, "$A_{pc2}$".to_string());
    state_to_string.insert(20, "$V_{pc2}$".to_string());
    state_to_string.insert(21, "$A_{his2}$".to_string());
    state_to_string.insert(22, "$V_{his2}$".to_string());
    state_to_string.insert(23, "$A_{alias2}$".to_string());
    state_to_string.insert(24, "$V_{alias2}$".to_string());
    state_to_string.insert(25, "$A_{pc3}$".to_string());
    state_to_string.insert(26, "$V_{pc3}$".to_string());
    state_to_string.insert(27, "$A_{his3}$".to_string());
    state_to_string.insert(28, "$V_{his3}$".to_string());
    state_to_string.insert(29, "$A_{alias3}$".to_string());
    state_to_string.insert(30, "$V_{alias3}$".to_string());
    state_to_string.insert(31, "$A_{pc4}$".to_string());
    state_to_string.insert(32, "$V_{pc4}$".to_string());
    state_to_string.insert(33, "$A_{his4}$".to_string());
    state_to_string.insert(34, "$V_{his4}$".to_string());
    state_to_string.insert(35, "$A_{alias4}$".to_string());
    state_to_string.insert(36, "$V_{alias4}$".to_string());

    let mut state_update: HashMap<i32, i32> = HashMap::new();
    state_update.insert(0, 0); // unknown state
    state_update.insert(1, 0); // unknown state
    state_update.insert(2, 0); // unknown state
    state_update.insert(3, -1); // invalid state
    state_update.insert(4, -1); // invalid state
    state_update.insert(5, 1); // valid state
    state_update.insert(6, 1); // valid state
    state_update.insert(7, 2); // mispredict state
    state_update.insert(8, 2); // mispredict state
    state_update.insert(9, 2); // mispredict state
    state_update.insert(10, 2); // mispredict state
    state_update.insert(11, 2); // mispredict state
    state_update.insert(12, 2); // mispredict state
    state_update.insert(13, 3); // mispredict state
    state_update.insert(14, 3); // mispredict state
    state_update.insert(15, 3); // mispredict state
    state_update.insert(16, 3); // mispredict state
    state_update.insert(17, 3); // mispredict state
    state_update.insert(18, 3); // mispredict state
    state_update.insert(19, 4); // mispredict state
    state_update.insert(20, 4); // mispredict state
    state_update.insert(21, 4); // mispredict state
    state_update.insert(22, 4); // mispredict state
    state_update.insert(23, 4); // mispredict state
    state_update.insert(24, 4); // mispredict state
    state_update.insert(25, 5); // mispredict state
    state_update.insert(26, 5); // mispredict state
    state_update.insert(27, 5); // mispredict state
    state_update.insert(28, 5); // mispredict state
    state_update.insert(29, 5); // mispredict state
    state_update.insert(30, 5); // mispredict state
    state_update.insert(31, 6); // mispredict state
    state_update.insert(32, 6); // mispredict state
    state_update.insert(33, 6); // mispredict state
    state_update.insert(34, 6); // mispredict state
    state_update.insert(35, 6); // mispredict state
    state_update.insert(36, 6); // mispredict state

    let mut path_to_vulnerability: HashMap<i32, String> = HashMap::new();
    path_to_vulnerability.insert(0, "unknown".to_string());
    path_to_vulnerability.insert(1, "fast".to_string());
    path_to_vulnerability.insert(2, "slow".to_string());

    let mut tsca: Vec<String> = Vec::new();
    let mut tea: Vec<String> = Vec::new();

    let secret_op: i32 = 6;

    // loop
    for i in 0..total_states {
        if exclude_states.contains(&i) {
            continue;
        }

        // reduction rule: remove $A_{cc}$ in the first step
        if i == 0 {
            continue;
        }

        // reduction rule: remove $V_{\\star}$ in the first step
        if i == 2 {
            continue;
        }

        // reduction rule: remove $A_{val}$ in the first step
        if i == 5 {
            continue;
        }
        for j in 0..total_states {
            if exclude_states.contains(&j) {
                continue;
            }

            // reduction rule: merge same operation
            if i == j {
                continue;
            }

            // reduction rule: remove $A_{cc}$ in the second step
            if j == 0 {
                continue;
            }

            // reduction rule: remove $A_{\\star}$ and $V_{\\star}$ in the second step
            if j == 1 || j == 2 {
                continue;
            }

            // reduction rule: remove $A_{val}$ in the second step
            if j == 5 {
                continue;
            }
            for k in 0..total_states {
                if exclude_states.contains(&k) {
                    continue;
                }

                // reduction rule: merge same operation
                if (j == k) && (j != secret_op) {
                    continue;
                }

                // reduction rule: remove $A_{\\star}$ and $V_{\\star}$ in the third step
                if k == 1 || k == 2 {
                    continue;
                }

                // reduction rule: remove $A_{val}$ in the third step
                if k == 5 {
                    continue;
                }

                // reduction rule: continue if the three-step does not contain $V_{val}$
                if !(vec![i, j, k].contains(&secret_op)) {
                    continue;
                }

                // steps: {i->j->k}
                let mut paths: Vec<i32> = Vec::new();
                let mut timing: Vec<i32> = Vec::new();
                let mut covert_channel: bool = false;

                // step 1
                if i == secret_op {
                    paths.push(0);
                }
                paths.push(state_update.get(&i).copied().unwrap());

                // step 2
                if j == secret_op {
                    let paths_size = paths.len();
                    for p in 0..paths_size {
                        paths.push(state_update.get(&j).copied().unwrap());

                        // covert channel
                        if paths[p] == 2 {
                            covert_channel = true;
                        }
                    }
                } else {
                    let paths_size = paths.len();
                    for p in 0..paths_size {
                        if state_update.get(&j).copied().unwrap() != 0 {
                            paths[p] = state_update.get(&j).copied().unwrap();
                        }
                    }
                }

                // step 3
                if paths.len() < 2 {
                    continue;
                }

                if k == 0 && covert_channel == true {
                    strong_vulnerabilities += 1;
                    tea.push(format!(
                        "& {} & {} & {} ($fast$) & EH & TEA & ",
                        state_to_string.get(&i).unwrap(),
                        state_to_string.get(&j).unwrap(),
                        state_to_string.get(&k).unwrap()
                    ));
                    strong_external_hit += 1;
                    strong_transient += 1;
                    continue;
                }

                // calculate timing
                for p in 0..paths.len() {
                    // state is 0 unknown
                    if paths[p] == 0 {
                        timing.push(0);
                    }
                    // state is -1 invalid
                    else if paths[p] == -1 {
                        // invalid + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // invalid + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // invalid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(2);
                        }
                        // invalid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(2);
                        }
                        // invalid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(2);
                        }
                        // invalid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(2);
                        }
                        // invalid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(2);
                        }
                        // invalid + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 1 valid
                    else if paths[p] == 1 {
                        // valid + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // valid + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(1);
                        }
                        // valid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(2);
                        }
                        // valid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(2);
                        }
                        // valid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(2);
                        }
                        // valid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(2);
                        }
                        // valid + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(2);
                        }
                        // valid + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 2 mispredict
                    else if paths[p] == 2 {
                        // mispredict + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // mispredict + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(1);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(0);
                        }
                        // mispredict + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 3 mispredict
                    else if paths[p] == 3 {
                        // mispredict + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // mispredict + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(1);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(0);
                        }
                        // mispredict + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 4 mispredict
                    else if paths[p] == 4 {
                        // mispredict + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // mispredict + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(1);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(0);
                        }
                        // mispredict + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 5 mispredict
                    else if paths[p] == 5 {
                        // mispredict + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // mispredict + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(1);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(0);
                        }
                        // mispredict + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                    // state is 6 mispredict
                    else if paths[p] == 6 {
                        // mispredict + unknown
                        if state_update.get(&k).copied().unwrap() == 0 {
                            timing.push(0);
                        }
                        // mispredict + valid
                        else if state_update.get(&k).copied().unwrap() == 1 {
                            timing.push(2);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 2 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 3 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 4 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 5 {
                            timing.push(0);
                        }
                        // mispredict + mispredict
                        else if state_update.get(&k).copied().unwrap() == 6 {
                            timing.push(1);
                        }
                        // mispredict + invalid
                        else if state_update.get(&k).copied().unwrap() == -1 {
                            timing.push(0);
                        }
                    }
                }

                // output
                if timing[0] != timing[1] && timing[0] != 0 && timing[1] != 0 {
                    strong_vulnerabilities += 1;
                    // internal or external, hit-based or miss-based
                    let mut attack_category: String = "".to_string();
                    if state_to_string.get(&j).unwrap().contains("$V_")
                        && state_to_string.get(&k).unwrap().contains("$V_")
                    {
                        if timing[1] == 1 {
                            attack_category = "IH".to_string();
                            strong_internal_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "IM".to_string();
                            strong_internal_miss += 1;
                        }
                    } else {
                        if timing[1] == 1 {
                            attack_category = "EH".to_string();
                            strong_external_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "EM".to_string();
                            strong_external_miss += 1;
                        }
                    }
                    tsca.push(format!(
                        "& {} & {} & {} (${}$) & {} & TSCA/CCA & ",
                        state_to_string.get(&i).unwrap(),
                        state_to_string.get(&j).unwrap(),
                        state_to_string.get(&k).unwrap(),
                        path_to_vulnerability.get(&timing[1]).unwrap(),
                        attack_category,
                    ));
                } else if timing[0] != timing[1] {
                    // weak vulnerability, ignore
                } else if i == secret_op && k == secret_op && j != 3 && j != 4 {
                    strong_vulnerabilities += 1;
                    let mut attack_category: String = "".to_string();
                    if state_to_string.get(&j).unwrap().contains("$V_")
                        && state_to_string.get(&k).unwrap().contains("$V_")
                    {
                        if timing[1] == 1 {
                            attack_category = "IH".to_string();
                            strong_internal_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "IM".to_string();
                            strong_internal_miss += 1;
                        }
                    } else {
                        if timing[1] == 1 {
                            attack_category = "EH".to_string();
                            strong_external_hit += 1;
                        } else if timing[1] == 2 {
                            attack_category = "EM".to_string();
                            strong_external_miss += 1;
                        }
                    }
                    tsca.push(format!(
                        "& {} & {} & {} (${}$) & {} & TSCA/CCA & ",
                        state_to_string.get(&i).unwrap(),
                        state_to_string.get(&j).unwrap(),
                        state_to_string.get(&k).unwrap(),
                        path_to_vulnerability.get(&timing[1]).unwrap(),
                        attack_category,
                    ));
                }
            }
        }
    }

    println!("bp_type: {}", bp_type);
    println!("strong vulnerabilities: {}", strong_vulnerabilities);
    println!("strong internal hit: {}", strong_internal_hit);
    println!("strong internal miss: {}", strong_internal_miss);
    println!("strong external hit: {}", strong_external_hit);
    println!("strong external miss: {}", strong_external_miss);
    println!("strong transient: {}", strong_transient);
    if print_res == true {
        for i in 0..tsca.len() {
            if i % 2 == 0 {
                println!("{}", tsca[i]);
            } else {
                println!("{}\\\\", tsca[i]);
            }
        }
        for i in 0..tea.len() {
            if i % 2 == 0 {
                println!("{}", tea[i]);
            } else {
                println!("{}\\\\", tea[i]);
            }
        }
    }
}
