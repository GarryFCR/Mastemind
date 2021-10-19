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
        vk.alpha = Pairing.G1Point(uint256(0x2c4be53355010a7293c1e57c1958c8cf010611e850dfb1be90cc2586c7582fe5), uint256(0x10066c1a2e4908fdf31a2485a20d25a46b2dd81596bfdda38fa7f0cefef3c805));
        vk.beta = Pairing.G2Point([uint256(0x15bcd91ab1471789ec073bfe49323c67cf04a5f1591e910da649df8cf9920f25), uint256(0x2e5c478ac36aa2a824de0cb3617676047dba7e40360700565a9557a0db01ec2d)], [uint256(0x08e29bceb1fc935e27eb0f7286851ba10bfbe200c982cf641fcbb644b3a92f9c), uint256(0x303df44ebc93a392ad6e30fd8b99a701875d4e8386180e3d1be531450c5354a9)]);
        vk.gamma = Pairing.G2Point([uint256(0x1c6cbf64d3c6e10463031344be4bfe1dc6f86c06dfab82e5bbafd7e32ac195b0), uint256(0x249d46e8f9b81c98e5bdafac393a5dd41e9b9c2311ad9e7b7200d9ca9ea1ab4e)], [uint256(0x0311ac0cf1e7d524c58e46cead96a5b1b7a9447d6b126147d6b957b4d4054a2b), uint256(0x15fd49ccde6711c2fa9bf77b73031a211061543b9ae11a3aaed86fc145afcbd6)]);
        vk.delta = Pairing.G2Point([uint256(0x05d754eb83499455b57b59c22946a125acbcb8015c452591277be02ffe04b4a0), uint256(0x0f24a55c916b738d22aa267deefbadb11f6e6c7330587aefcf3dea49f4798b7c)], [uint256(0x2287208b32487f23f14c601943f60f683685f89f80d1d4d84250d915ff521e77), uint256(0x1a7516eabdec37ae1337dcf0f556c28aca279b37b220890b9d1c4e01274236e0)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x141aa77089c65b11845a64c3c0009abd13d1b598959cc5efab123f294ce1c632), uint256(0x25cbc95af1453a71a2a22576bf5ef9df920fd1df6b29727d7233e9a8e594b5d3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x18eda99a42c93bbc7c1a4df4c15bd79af379692746cb1a56d1e5596340f605aa), uint256(0x034595e911e317fa7c9898c9678225c4c751f5d3bcce5e4da6c178cb33313f11));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2ff4f46213ecc18256d2aa9d9c8f221171b62e25af3b555b8c24984c86a6f248), uint256(0x0a5d7201e0564844adf55209aa4ed12c91f8c0d0a13aed29cc1b9694fb977560));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a8c9b864f53643d1af6a575f04e1a46fbd30a4b9526d12fc7e93422f072b621), uint256(0x171502f548714e9a60d5b7011fe7f5db2a51e15512124cb1ac94b159871d43e8));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2662c3aec737c24606c269223d2761a18aab7943b4748d55c9c72cbb93a1ae7c), uint256(0x229f74c5f12ade0f32308477f293139ee821ea1a1c2883bdc7947d1dc383ec75));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1ef360d85606d83186be564e49375ecbdedba98ab7fce550ea99c23da5ed478f), uint256(0x0aa2c540367a39a57ebe39df3cd6bcd15f0c7ee17149c6c875976630aadf3226));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x231963a2f1d53e33f9ae7d944c2260df5c0d6eef4547d4a01d91fcfacaec6f0f), uint256(0x1fb38561bb78663784ff0db7543c6c220723d144f8cf9180ee833c1e020297e9));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1db45ce1dfaca6dc7fb2ad5e22e913290adac3d94b49fdaa8b68bc80e7342fc3), uint256(0x267a221a73615087b51507769c8add59efc9dbd90c52e60033e8c4317c74795c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x19aa03e5ad0da51838084645fca7a6bc3c238ec1a3f572d261a29480f5dfe925), uint256(0x15e843408dff5b989b2cc4c00b061609ec2eba21c47674f3ad449973c2e0f4df));
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
