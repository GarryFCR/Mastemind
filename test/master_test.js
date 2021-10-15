const { initialize } = require('zokrates-js/node');
const { deployContract } = require('ethereum-waffle');
const { expect } = require('chai');

const fs = require("fs")
const  proof  = require('../proof.json')
const master = require("../artifacts/contracts/verifier.sol/Verifier.json");

describe('Test the proof',()=>{
	
		it(' checks the verifier',async ()=>{
            [owner, addr1, addr2, ...addrs] =  await ethers.getSigners();
            contract_master = deployContract(owner, master,[]);
            let proofx = JSON.parse(fs.readFileSync('./proof.json'))
			expect(await contract_master.verifyTx.call(proofx.proof.a, proofx.proof.b, proofx.proof.c, proofx.inputs)
            ).to.equal(true);
			});
})
