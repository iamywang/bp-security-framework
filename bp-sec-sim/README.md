# Branch Predictor Security Evaluation Framework

This framework is a formal modeling and analysis framework for evaluating the vulnerabilities of timing-based and transient execution-based attacks on branch predictors in modern processors.

## PART I: Symbolic Simulator

Research Artifact of HPCA 2024 Paper: *Modeling, Derivation, and Automated Analysis of Branch Predictor Security Vulnerabilities*. This part contains the source code of our symbolic execution-based branch predictor simulator that can be used to automatically derive and analyze branch predictor security vulnerabilities.

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.10297402.svg)](https://doi.org/10.5281/zenodo.10297402)

<table>
<tbody>
<tr>
<td align="center", width="25%"><img src="../screenshot/badges/Open_Research.png" style="margin: 0 auto;"/></td>
<td align="center", width="25%"><img src="../screenshot/badges/Research_Objects.png" style="margin: 0 auto;"/></td>
<td align="center", width="25%"><img src="../screenshot/badges/Results_Reproduced.png" style="margin: 0 auto;"/></td>
<!-- <td align="center", width="25%"><img src="../screenshot/badges/Findings_Replicated.png" style="margin: 0 auto;"/></td> -->
<tr>
<td align="center">Available</td>
<td align="center">Reviewed</td>
<td align="center">Reproduced</td>
<!-- <td align="center">Replicated</td> -->
</tbody>
</table>

### 0x01 Getting Started

Install Rust:

```bash
Ubuntu: $ sudo apt install rustc
Arch: $ sudo pacman -S rust
```

Clone the repository:

```bash
$ git clone https://github.com/iamywang/bp-security-benchmark.git
```

Build the project:

```bash
$ cd bp-security-benchmark
$ cd bp-sec-sim
$ cargo build --release
```

The executable file is located at `./target/release/bp-sec-sim`.

Usage:

```sh
$ ./target/release/bp-sec-sim <exp1_derivation|exp2_rsb_refilling|exp2_secure_bp|exp3_baseline_bp|exp3_secure_bp|exp3_hw_defenses|exp4_tage>
```

### 0x02 File Structure

File | Description
--- | ---
`src/exp1.rs` | Experiment 1: Derivation of All Vulnerabilities
`src/exp2.rs` | Experiment 2: Analysis of Secure BP Designs
`src/exp3.rs` | Experiment 3: Analysis of HW Defenses against Speculative Attacks
`src/exp4.rs` | Experiment 4: Modeling TAGE Branch Predictor
`src/main.rs` | Main Function Used to Run Experiments
`src/simulator.rs` | Core of the Three-Step BP Simulator

### 0x03 Reproducing Results in the Paper

Our directory structure is as follows:

```
bp-sec-sim/
├── res/
├── src/
├── target/
    |── release/
        |── bp-sec-sim
├── Cargo.lock
├── Cargo.toml
├── README.md
```

#### Exp.1: Derivation of All Vulnerabilities

This experiment is used to reproduce Table IV in the paper.

Commands for deriving all 156 vulnerabilities against PHT, BTB, and RSB:

```bash
$ ./target/release/bp-sec-sim exp1_derivation > res/exp1_derivation.out
```

Example output:

```
========= BP-SEC-SIM =========
Branch Predictor
bp_type: PHT
strong vulnerabilities: 28
strong internal hit: 4
strong internal miss: 10
strong external hit: 4
strong external miss: 10
strong transient: 4
& $V_{val}$ & $A_{pc}$ & $V_{val}$ ($slow$) & EM & TSCA/CCA & 
& $V_{val}$ & $V_{pc}$ & $V_{val}$ ($slow$) & IM & TSCA/CCA & \\
...
```

#### Exp.2: Analysis of Secure Branch Predictor Designs

This experiment is used to reproduce Table VI, Table VII and Table VIII in Section V in the paper.

Commands for analyzing RSB refilling defense:

```bash
$ ./target/release/bp-sec-sim exp2_rsb_refilling > res/exp2_rsb_refilling.out
```

Example output:

```
========= BP-SEC-SIM =========
RSB Refilling
bp_type: RSB
strong vulnerabilities: 5
strong internal hit: 2
strong internal miss: 2
strong external hit: 1
strong external miss: 0
strong transient: 1
== DONE!: BP-SEC-SIM (exp2) ==
```

Commands for analyzing secure branch predictor designs:

```bash
$ ./target/release/bp-sec-sim exp2_secure_bp > res/exp2_secure_bp.out
```

Example output:

```
========= BP-SEC-SIM =========
Lock-BTB
bp_type: PHT
strong vulnerabilities: 28
strong internal hit: 4
strong internal miss: 10
strong external hit: 4
strong external miss: 10
strong transient: 4
...
```

#### Exp.3: Analysis of HW Defenses against Speculative Attacks

This experiment is used to reproduce Table IX in Section V in the paper.

Commands for analyzing baseline branch predictor against speculative execution attacks:

```bash
$ ./target/release/bp-sec-sim exp3_baseline_bp > res/exp3_baseline_bp.out
```

Example output:

```
========= BP-SEC-SIM =========
Branch Predictor (without RSB refilling)
bp_type: PHT
strong transient: 4
bp_type: BTB (ind)
strong transient: 6
bp_type: BTB (call)
strong transient: 4
bp_type: BTB (ret)
strong transient: 4
bp_type: RSB
strong transient: 2
==============================
Branch Predictor (with RSB refilling)
bp_type: PHT
strong transient: 4
bp_type: BTB (ind)
strong transient: 6
bp_type: BTB (call)
strong transient: 4
bp_type: BTB (ret)
strong transient: 4
bp_type: RSB
strong transient: 1
== DONE!: BP-SEC-SIM (exp3) ==
```

Commands for analyzing secure branch predictor designs against speculative execution attacks:

```bash
$ ./target/release/bp-sec-sim exp3_secure_bp > res/exp3_secure_bp.out
```

Example output:

```
========= BP-SEC-SIM =========
Lock-BTB
bp_type: PHT
strong transient: 4
bp_type: BTB (ind)
strong transient: 3
bp_type: BTB (call)
strong transient: 2
bp_type: BTB (ret)
strong transient: 2
bp_type: RSB
strong transient: 1
==============================
...
```

Commands for analyzing hardware countermeasures against speculative execution attacks:

```bash
$ ./target/release/bp-sec-sim exp3_hw_defenses > res/exp3_hw_defenses.out
```

Example output:

```
========= BP-SEC-SIM =========
InvisiSpec (Cache)
bp_type: PHT
strong transient: 0
bp_type: BTB (ind)
strong transient: 6
bp_type: BTB (call)
strong transient: 4
bp_type: BTB (ret)
strong transient: 4
bp_type: RSB
strong transient: 1
==============================
...
```

#### Exp.4: Modeling TAGE Branch Predictor

This experiment is used to reproduce Case Study in Section IV-C in the paper.

Commands for modeling TAGE branch predictor:

```bash
$ ./target/release/bp-sec-sim exp4_tage > res/exp4_tage.out
```

Example output(modeling four tagged tables as an entire unit):

```
========= BP-SEC-SIM =========
TAGE whole
bp_type: PHT
strong vulnerabilities: 34
strong internal hit: 6
strong internal miss: 13
strong external hit: 2
strong external miss: 13
strong transient: 2
==============================
```

Example output(modeling each table separately):

```
TAGE separate
bp_type: PHT
strong vulnerabilities: 106
strong internal hit: 18
strong internal miss: 43
strong external hit: 2
strong external miss: 43
strong transient: 2
== DONE!: BP-SEC-SIM (exp4) ==
```
