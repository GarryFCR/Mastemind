const { ethers } = require('hardhat');
const fs = require("fs")

const verify= async ()=>{

            const Verifier = await ethers.getContractFactory('Verifier');
            const verifier = await Verifier.deploy();
           
            let proofx = JSON.parse(fs.readFileSync('./proof.json'))
            const result = await verifier.verifyTx(proofx.proof, proofx.inputs);
            console.log(result)
            if (result){
                console.log("Yesss")
            }
}
//verify()
module.exports={
	verify
};