// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x205c842cc7ce9f0540c23aab2502ba798b55d117ad27fa49cbc32a5d23f8b2fb), uint256(0x11054fce4ff776026d7b9142eb9e54a9e6baaeacd92cc799c7cae97f0401be1d));
        vk.beta = Pairing.G2Point([uint256(0x24fb27ec142792e656e1e54afdf307c66e5753343622651282570dcc48e6c598), uint256(0x21a907e3d06d1a65f7d69727df3ca08e427676f7a9bdb72ca455505128dcee72)], [uint256(0x1c2278e546e9e23e85a9e9514a04e10fb21f7f0c080a6033bc8193ecf3d20796), uint256(0x2abef0861ce4b5dccbbd51ba84e07051704ec70c51c064da31afb817f0e9c31d)]);
        vk.gamma = Pairing.G2Point([uint256(0x0c52bb88470c896f3cc1edd97cd9ede2818b380da280398e2f0c3fa17bbb525f), uint256(0x2c03d389d6530b8a86090a938c973480715dca4bb1b0ee6017b4295328160cc7)], [uint256(0x21abd32166942c3866999a23f80726133abb42067f6dabc9d7e50fa9911f8423), uint256(0x0e61797f40e2b60d15550fd69f63dc8e0b914cd0a1d3258a4bf6715ffb8bf1d8)]);
        vk.delta = Pairing.G2Point([uint256(0x1d42f4c96e03485b1ccc04b267b8551828026186d871b68e3ff0c4c90a7e001e), uint256(0x11bc69a679ccbf10693ef9161e4d39b76d054ae35b932e83cf7dd76cdcdc3646)], [uint256(0x09e866f3f0e7a1104b3dd75494e3ad2fb8dc42415eacd9b458b38708a0581ac5), uint256(0x09d20a9d5bf1a3a3e668e3dc99a35826de8eef13812201b04c5e7031c8c49653)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1499968806aea64192f1d45b759b58f481ff06106c8d85a7e5d1d1cbf7eaccc4), uint256(0x11619a8518b6574c549456eb982331c21fc1867ed7a31113801521fc59a0d3a3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2d16a80ec17dbec942f3faf2f1b4156d8b2a6dd906516079db29869a3fcaa75c), uint256(0x23d963f09670bfa9ec1386cee016464eeea1bd71a447a85b58d3fc8ff85a6696));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2e8cf9bf55aac301b2bd3cc7ddabeb05eef101e2559e2b99933223dddf422406), uint256(0x0442bcf81188cdf49d5a99e8028dc8f0ff0ba088a05bd8bd6f525bbb0ddb89ed));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x175345e49b964f93990ccdaf38cf76ec3ab26daeec60847d6a71b9e28db9a3f7), uint256(0x2645281d8f7f9ca14dccddfc983c39347f2a32ffd4ebaf360c21be60da848dff));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x045084010152d71d51d22025f6fb77cfa60bca5a450ebe093e287cb15f423d2a), uint256(0x2e35404da5a817be5a1a7124e7573ee24b02fc8aec5a56491b3e5beecccde55a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x164b59e5a969eecdeab3b30e9a076881d8b5b825be3843feec2dae5f0aa0cae6), uint256(0x1ac95db4fbb329c5e54266b0c54e42a5fee18cc9afc10b68ed9e77b059a51533));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0081addb9d1a3d660cc10b4cc978b3da10361204e6006e970daebefee8caf8bb), uint256(0x12859808ffd02894cca8c57d813566947b6d0b84a3b01471364bb731c6c56447));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2303af7c166f80cd4a2a518227121960929f5c889b8d987c359ebb300db778bc), uint256(0x181e72f6c0c3f83fa4227915137212548fd8b5e4f36a4c017252158d6ec75f8b));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2a763a765554aff7ab36ae9211cd0294b764bd9497390ff9b444c8979eb67305), uint256(0x02679f16408fc1bd3e57697f2a24f0d653df3aace46275d8303ccc39370c5401));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[8] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](8);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
