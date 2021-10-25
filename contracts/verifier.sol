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
        vk.alpha = Pairing.G1Point(uint256(0x1bedc3584b1b9b2e95b897c236dfc91a95c17d187eeb22b3fa4dc7e5389d6526), uint256(0x061d37534a2e50b503de498a0cdb6c5fe7e4cce549b095f92b7b6f7c87c461f5));
        vk.beta = Pairing.G2Point([uint256(0x11c5ef6a394fd8373b34118b1471d2eb1990357ce3053310a12a52245af26bb9), uint256(0x2a27c198c9fd7908080739bdb3d08e46f4441ccff3d6bd525872e8490b382c0f)], [uint256(0x2154c7bbd21af24728717f750d879b4ce7a6ae616af21c0f6ec157cf2c1b09f1), uint256(0x059de98ed7e913742e105130c05edb4fa52825183b18e97a82bd877e0470ba77)]);
        vk.gamma = Pairing.G2Point([uint256(0x2bb9a714b0d43369e15f06bf2e292566a39abeca436cd3c16b1c30300906e3d7), uint256(0x087a9a09a17993d67dcbdb8421572c175dfdf57a1c1082787da78bb9691d93b8)], [uint256(0x2beeb246a29ef56e36c56fac4cbc243fa758405e17da951a10d7716ad5436745), uint256(0x03e51d6db9561308e2af6246b200538683832fecbc0fab2509a6fa5216f7686d)]);
        vk.delta = Pairing.G2Point([uint256(0x0238b15b415770a69418688304086176025855f313eaec324fad979f61dc8acb), uint256(0x274657659434d19428c05bc416066eac627b9294da1853535abec34f5cda2706)], [uint256(0x1164cfbbed8c64725a86a765e0711f666cb6bc2ef2e5989f407bc2a7004304c6), uint256(0x202b77f991b08e2e89506355175f6608ae1890354a232a12c0aae9738066ca93)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x260a9f0ade07ef1ee71dba934cb9898f98c1311299b93310ecb802928568be6d), uint256(0x28d7c68d239b8e3c84ad3162d5a8bff84a7f76ba8b743d4e3274a99bade83829));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x24af03fb3fa31916e2fe63f087abddbc5227995c6174f8e71cc38dd84a416012), uint256(0x20133957795eec77517f5464e36b35065d57dd9eccf2b014089cd9a250933c23));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0109dad41bd1657d3757740c38651307ad70f03a7e078707c0d2897d87a09b7c), uint256(0x21fbb0c88e9bf55cfe21c0a488be5db3c3bf1fa706ac8c46f934ba81b2918b14));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a1c8c99a0b2d0100c7d4b727a53c7db09d36e548928fcc5c70aaca880f1f598), uint256(0x2b2702240248458c4abd9f1e2a55a6f69c8b7f9929d7d57d5622bf799ac4b0c9));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2e8f3f2145be6f77166fe0efb4a717435954130fb8d8baa1dacdce4963710a27), uint256(0x103428dd1a027239a9d693e4409f0adef7e153f7ff708664d047db73737787b7));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x02c2450cdd81bd11676b95efd5b9a82c70628c6fd3b35d0ecf2954f78d81a994), uint256(0x0d37bd3d681b373208b4f9d6f2c733ad4aafb81758a66f1a0d972acb14d59b01));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x263bfea673d2ac306bafdc53ecad2984586f82662909c6d6b76ca5d9e9b72cac), uint256(0x06015f58104c54dcc1809926ab05a406deb88250dfefea613b47c665dacfec1a));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x164a2ecab39af433586dd8d6484b12f7a16d583137f536321488b23f1e2fdab2), uint256(0x1da543cf10c6616e175d4dd35434de410642ae50b20c2f8298b043732486c987));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x078dc614b63dd013b4e1b816400089672b12716b5a24b871057ce05e4821cc1f), uint256(0x1c9f90a2aa3fb7156acf18434b1d5746c1d2db723f261f0b55227a72108f8dec));
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
