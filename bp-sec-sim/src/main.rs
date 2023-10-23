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
// date: 2023/10/21
// ============================================================================
mod exp1;
mod exp2;
mod exp3;
mod exp4;
mod simulator;

fn main() {
    if std::env::args().len() != 2 {
        println!("========= BP-SEC-SIM =========");
        println!("Usage: ./bp-sec-sim <exp1_derivation|exp2_rsb_refilling|exp2_secure_bp|exp3_baseline_bp|exp3_secure_bp|exp3_hw_defenses|exp4_tage>");
        println!("Example: ./bp-sec-sim exp1_derivation");
        println!("========== LICENSE ===========");
        println!("Copyright 2023 iamywang");
        println!("");
        println!("Licensed under the Apache License, Version 2.0 (the \"License\");");
        println!("you may not use this file except in compliance with the License.");
        println!("You may obtain a copy of the License at");
        println!("");
        println!("    http://www.apache.org/licenses/LICENSE-2.0");
        println!("");
        println!("Unless required by applicable law or agreed to in writing, software");
        println!("distributed under the License is distributed on an \"AS IS\" BASIS,");
        println!("WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.");
        println!("See the License for the specific language governing permissions and");
        println!("limitations under the License.");
        println!("==============================");
        return;
    }
    if std::env::args().nth(1) == Some("exp1_derivation".to_string()) {
        exp1::exp1_derivation();
    }
    if std::env::args().nth(1) == Some("exp2_rsb_refilling".to_string()) {
        exp2::exp2_rsb_refilling();
    }
    if std::env::args().nth(1) == Some("exp2_secure_bp".to_string()) {
        exp2::exp2_secure_bp();
    }
    if std::env::args().nth(1) == Some("exp3_baseline_bp".to_string()) {
        exp3::exp3_baseline_bp();
    }
    if std::env::args().nth(1) == Some("exp3_secure_bp".to_string()) {
        exp3::exp3_secure_bp();
    }
    if std::env::args().nth(1) == Some("exp3_hw_defenses".to_string()) {
        exp3::exp3_hw_defenses();
    }
    if std::env::args().nth(1) == Some("exp4_tage".to_string()) {
        exp4::exp4_tage();
    }
}
