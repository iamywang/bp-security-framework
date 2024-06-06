# Copyright 2024 iamywang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ============================================================================
# Branch Predictor Security Evaluation Framework (Symbolic Simulator)

# author: iamywang
# date: 2024/06/06
# ============================================================================
FROM rust:latest
LABEL authors="iamywang"

WORKDIR /bp-sec-sim

COPY ./ .

RUN cargo build --release

RUN cp ./target/release/bp-sec-sim /usr/bin/bp-sec-sim

CMD ["/bin/bash"]
