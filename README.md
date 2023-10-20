# Branch Predictor Security Evaluation Framework

This framework is a formal modeling and analysis framework for evaluating the vulnerabilities of timing-based and transient execution-based attacks on branch predictors in modern processors.

## PART I: Symbolic Simulator

Prerequisites:

- Rust 2021

Build the project:

```bash
$ git clone https://github.com/iamywang/bp-security-benchmark.git
$ cd bp-sec-sim
$ cargo build --release
```

Run the simulator:

```sh
$ ./target/release/bp-sec-sim exp1_derivation
```

Output:

![sim](./screenshot/sim.png)


## PART II: Security Benchmark

Prerequisites:

- CMake >= 3.10
- gcc >= 7.5
- python >= 3.6 (with numpy installed)

Build the project:

```bash
$ git clone https://github.com/iamywang/bp-security-benchmark.git
$ cd bp-security-benchmark
$ mkdir build && cd build
$ cmake ..
$ make
```

Generate the benchmark:

```sh
$ ./build/bp-sec-bench
```

Output:

![bench](./screenshot/bench.png)

## Copyright and License

This project is licensed under the terms of the Apache License 2.0.

```
Copyright 2023 iamywang

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

We would like to thank the authors of the following projects for their useful utility tools:

- [IAIK/transientfail](https://github.com/IAIK/transientfail)
- [fanyao/branchspec](https://github.com/fanyao/branchspec)

We have modified and integrated their tools into our code `bp-sec-bench/utils/util.h`.
