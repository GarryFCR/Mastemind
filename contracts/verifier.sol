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
        vk.alpha = Pairing.G1Point(uint256(0x0791b239c4a0a00d926a767c968fa4ab9a3d2d53beaf366971c347d79a8c3237), uint256(0x20a33b7fc9d31039965f02ab512cb1e2ddbf898a6163ea327b591fe55e0cdf71));
        vk.beta = Pairing.G2Point([uint256(0x083fccf60a5c9e96cbd6bc68dd0168fcb0985f8362b51db6e613614401fcaec4), uint256(0x212af6628108c2df4ee5a7d40fb189a259c13718ac4dd900969d40f1ce413585)], [uint256(0x13946b5f8dbb0d2ab9c0371c70a947f25d398fa3a22a2ec58387bde2f46257d5), uint256(0x1e4dfc7f4211be012f40b5a89b5de2835e97718b19989bcd0247963546dc394e)]);
        vk.gamma = Pairing.G2Point([uint256(0x0d8ae71cb131aac735c69264cf49233c0188fd29f6cdb2a2282850419f0284e1), uint256(0x12db956b47fb4f9e52c42cb6c1e0f3fea7c2141ff04123c98070fd91fce2190f)], [uint256(0x19aeef3d4aedc990fb8474caecd222af72b6b682e127c6172bb13c244a6431a2), uint256(0x1b480a849dc634a6765c36749ad57a65713ee28c2b709e0ab5300231884c5780)]);
        vk.delta = Pairing.G2Point([uint256(0x1a86db71a4c9a0c89aaa8bf5c31c17aed20606d9e52793bca138dd5d48f2acd0), uint256(0x0fe9493533253fe23aa2f1c00f6b2dca139d23e70f0ae4d3ffd4b40f789061cd)], [uint256(0x185eda3abcb92ce62275a68b7a16dcdeadca0fc67dd2908e30c3e5ce8141b690), uint256(0x1b83f5abf50d5b0f1c1954374248a3f1e942d40a008c51f03435c192537abbc3)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x237e9a5d82659ed368587591b406fcdc40744ffb6820bd7ea736dddd29144259), uint256(0x0f24621148afce0badca355c04a9af0728557c5b7a89ffa5453863560415b0cc));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2a8b47d53b307ed28f9d68bc98d043beb5d6feb79a23cdc9a4a14f9354134c03), uint256(0x0b6761d78d77468211afc797e63424bc4dd37fee4a19e6dbec6b2b455a11d12a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x04995cf33ff5133f87c2082a209659ab46506a56b9b0bc5627d6993a0f44c627), uint256(0x1bef43dd399cf4f48469b26308e1bebd2d052b0b6190685fbdaa4eb302a2b649));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2eb99ea8ed2c75c14e63cc2707eafd65512c428ce3f06e8a567552af4c8ea2c1), uint256(0x2eceadbe27f8c2f9a83b359b6a86f6e606fee9dfc690463916a4849dbb816cc6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x155a755fffa181cd8a6bf99e03a79f3902baa2b4a3df7abf6c390f8171cb446b), uint256(0x14ad7643b92ff73b79dd39f915b279816fc8307f6a804ac4f634c0f8350570e0));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x018ad457b4cf8575d28d34e46f46677e06c01a20316473ed52e4896ae39531e7), uint256(0x25154b26b633314f9ae540f8ac59ddc4547ea7aa4483dee542d860254f9facaf));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1f908de7207c93f3e49b5aeadad72221669fafc737722579ebaa0e9e5182f3aa), uint256(0x136dd3c2fc7482b451dae7bd861b689c501dfbbfe62d433f4dfecc048dfc77e7));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x11453054fba330d7876a56bb17ec72ca2274b32fd456f79295fb0c25312e9b24), uint256(0x1ec4f0713257c5ec808c471f14c90beb90b9bb043424895bf547c048a2ef32f1));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x110677fa194b6182d86914f612fc1098b3c011e00684bcc07ba9f6325f943972), uint256(0x07b0de69af0b76b9c4cc36a435c24e85879f823c810137dd25a5ca756023357c));
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
