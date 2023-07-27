Fork of [Monotree](https://github.com/thyeem/monotree) using [poseidon-rs](https://github.com/arnaucube/poseidon-rs).

Hash uses 21888242871839275222246405745257275088548364400416034343698204186575808495617 as the field modulus.

The chosen field can only represent 253 bits of data, so we split the preimages into chunks of 31 bytes, and pass a vector of field elements into the Poseidon hasher.

Performance of many operations is slow. Optimizations might be possible through parallelization.