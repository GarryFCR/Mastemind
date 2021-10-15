const { initialize } = require('zokrates-js/node');
const { deployContract } = require('ethereum-waffle');
const  proof  = require('../proof.json')
const master = require("../artifacts/contracts/verifier.sol/Verifier.json");


const verification=()=>{

    [owner, addr1, addr2, ...addrs] = ethers.getSigners();
/*    
    contract = deployContract(owner, master,[]);

    proofx = JSON.parse(fs.readFileSync("../proof.json"))
    console.log(proofx)


    if (await contract.verifyTx(proof,)){
        return true
    }
    return false
    */
}
verification();
