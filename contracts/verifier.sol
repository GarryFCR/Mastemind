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
        vk.alpha = Pairing.G1Point(uint256(0x28be28e1660155d0d74a4d97dc673d15e9a3d440a66fb8c57716b54577aad350), uint256(0x12a53f7d85372af524cf5163e8b82db89e613bf5913756fce50bc3803da20d38));
        vk.beta = Pairing.G2Point([uint256(0x0a2a5846435737f88f387f9dff1c89131f40fcfba50d56ed63534e905e28b6f6), uint256(0x23d8843f8cf00078678a2efa518f18d75b70e45bd7937a72cc17a31dbe26af13)], [uint256(0x228054767fb61d491870eb9992370c46ae6ace2f20da174e55d52331005230c9), uint256(0x20dd429328f374faf01f1846ea0a94f9f047298ea81f9ab8ce525b396f1970bb)]);
        vk.gamma = Pairing.G2Point([uint256(0x2cd0aab18f9007a19577bc85afc402fd936aa890a89821fdf16073973c351e43), uint256(0x16ae59840ab57dae2f15ea249b15a6ba52a3c85ac65b6df7509d31e803db4dad)], [uint256(0x0c37903ca256ffb3183ba2e5dc40f0346803934de3f4953ef211f2e1b54f3e17), uint256(0x0672f6f10eb57f4c09a83755230af3625c911190336508230ed98020c820c0a6)]);
        vk.delta = Pairing.G2Point([uint256(0x1f248f2074e84c6073c8b0a9c5d54fb8d590482d63333103e06bc4785bbb2ebb), uint256(0x13597601fa488348066a66cc061e03734cf55fba1da63ebde73b1a2e3d0f33a7)], [uint256(0x26349ed46ec278d7e217e8e8b9d6e7f34b38b6e8bcab24d37eacd1a75c74c056), uint256(0x17e6665204b89e10ea414d6663e9d88dce43669ec8e5e9cf66c25c8d1a07b981)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x276927361e989140d4078736c45b9d04c636839ca5ba61f7b8f7f7720a4812e7), uint256(0x04be2de69209ec45de62535418c59ecacd6bc6a00752d1eb42e0391a5baff03e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2f22ff85f671ed9ff7a103f96da5098370317eec4c8e05d7c20356babad4c4db), uint256(0x14e9b4bb2c1a09a10031865534d597ba518b291480777a049bbbf260c3309dcf));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x28ebf73bf235470fdc2b6a62225e129b82b002639ccb613d5a0343cabc9f2e69), uint256(0x05fb84c89b9033c89a40b7d7162ce3d8d99deb535de2d30fa88914abf95c466e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x26d1a16803f4c3af76f73d0c08de4dfabe2b82906d9e4cc6c5a500957fdccc55), uint256(0x129de58dfd1cf740bfe64ba06e7b57685dc8d9974b24d63734d768d3e7d24be5));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x216f57ec435f474fc8eb5b3decdde2b58f3fe8f2adf5a1bf120f70baf159ead5), uint256(0x1286836a4cd2a10b97bbc20f65c8c6561d2b8fda83bbc039fe51986e25cdfcf9));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x23dfea24b9db6a084352f1be811b60f9bc6c3d3e51e779b9afdccd9ffcbc05eb), uint256(0x0e7f5da5d05fadae1bf6005162fcfb5de7d46d7e7523389af20aa0eab751218f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x142cc5b7d190b6560583e88b5290eb4b8858df80010191b0ab4d33fc8bfa1d8b), uint256(0x1033f126e6ed62405a51e4b8d4c6cc2d8111e57e8a6e9af44645b19557eef2aa));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x09959d75f8021ed19c73494209598f4909726403c38bcdb6d306b658f5e80a1f), uint256(0x0a3a46ff76fe467cda76dca5937112ed10536cc79ba4d1bb3b3d0d4468dda94c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0aa9ebfeca2b09793d2e2fa91e5dc022f8fd6a59aad9a745a02d4c2570db8323), uint256(0x0fa0729f7ed2d0d98f7deda140a61c83d573b150442eb3dca44b5479f66e075f));
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
