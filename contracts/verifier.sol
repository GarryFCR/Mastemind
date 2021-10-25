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
        vk.alpha = Pairing.G1Point(uint256(0x19d015550642a4e34da164c013afcee94af51e5b5c19451f1f7f65599965fdd6), uint256(0x0163ffc4537d03de4da2f344877377569834894e179625474a90fb067b08838d));
        vk.beta = Pairing.G2Point([uint256(0x26938abebabdf71d7265edbec4183e60d18c338efd51eeb1cf787c95dd96e85b), uint256(0x05eef52ca011e74cd09aa001a34e80675a05f502397035082d53fa75706bac90)], [uint256(0x126e015e28c23c4202e348ac14e2d1a18139cc2e21ee65c2a7f034810c4dd6a4), uint256(0x091ab168bd7c21b2bd3d01333520a9608c4b5081cc262f20eaf48745a2fa1387)]);
        vk.gamma = Pairing.G2Point([uint256(0x21e0c1adc3c19d9ad8563d401da541993fb083dae27a06f5f532ee76e9cb7f31), uint256(0x302b2f3077c526e34fbf8e483853e4db8ba7d1b7b065cb900812fcc45f882d43)], [uint256(0x12622b9968c9f2b808104ead437a6fab53f91f1a381566534317711d7054de10), uint256(0x2e247119b1888fac716f8512daa98f638bbe0a60be88d55363de2e1f698d19fc)]);
        vk.delta = Pairing.G2Point([uint256(0x23e86bd496c1f3411f2b160854eaa076e32e53af10210a8e60fcc7b6fee35aa7), uint256(0x2c9fd62a627a9c6c8d8e17a0b1ec23f68be72c41bed70837dd0c7abd4d504a0f)], [uint256(0x247bf4b483ae5648f2b34d14b0fbee1959ca454b29b9b8b78dbabdf9ee97bceb), uint256(0x1d67eca1bbb44cac04c4d993490850a2cdc071f9ddc4d5e16c0856bf24a73ee0)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x28dc392cf79fa491309ab0220119f962d578c4f9c9fe2fcd3e7898771b658254), uint256(0x1d82c7950220f4b2ff56dabfd408f1ab0e14003c79927abb0ba92a1491399be4));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1d117486b57cff565ab5a2a2c3666be4c3f2775e1abd233ba5f9f70b2ea22421), uint256(0x2e473332a575e7cfda112cd47f4598481efebe0cebcd6a0dca97651a34505b37));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2130f02e6ea9b9b33e7a9fffbcc9fd02938d6e026cf969a7066a1c6a025f7555), uint256(0x038373fc1fbbcd848b7bd09b920229611dc5bba0265e476e0728cc20840d3f61));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x00370d235b5d1873983f42eb99ba76d9c2a6359f3de229d626ea115fe4de2c8e), uint256(0x20d226b7b9a1165912bad1d8d742324df75b8342c7bfbe7a00ef2eba0136a644));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x12db508d2b1bdefbd9290ce52df9e131eddb83dd4990c948d35df41d3ef7f644), uint256(0x1cc70f095afa61e960aac6211abf860e5a35e8f9cf70f8014e05e40b1d739afd));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x05a6f6c0ee6b122afe4a076d1dd680a3182e1d7e40875eea786ee444ae5fab4e), uint256(0x2fb15cfcfcc558f5d1c141c214200d3b18a43e60bb07e68319a835e32c1949dc));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0ae20cc223a9f35b66d9c1be8e1b68c105f15af36205d3b7f128a3005c26202a), uint256(0x03e027f80b8741a115518f5771256a19bc5b733926cad5485ea3d43151f0f20f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x056377d418f5b4f75c6fdb0e72ce5b9dab9368a6306f50f72e964d0b1d697757), uint256(0x0b3a68869c941485f401d2209584b74454e7eec04d4bf48289776b415f93cdaf));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2e2bfa392ce7b14b4469259d22da061528764e6ed147a5177aefdd9058c37cf9), uint256(0x08b720ef34c9b13b0e469d9872e03a7df31567bf8db4b62c2c1f332956d8fd4f));
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
