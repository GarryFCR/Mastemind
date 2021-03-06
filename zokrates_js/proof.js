/**
a proof generation that uses zokrates.js  which includes compilation 
of zok file,witness computation, proof generation and verifier contract generation.
 */
const fs = require("fs");
const { initialize } = require('zokrates-js/node');
const input  =require('./privsoln.json');
const data  =require('./pubGuess.json');
const guess_data = data.Guess
const { generate_witness } = require('./witness.js')
var args;


//instantiating the circuit used
const source =  ` import "hashes/sha256/512bitPacked" as sha256packed

def loop(u32 i, field[4] privsoln,field[4] pubguess,field[4] correct) -> u32:
    u32 x=0
    
    for u32 j in 0..4 do
        x=if (pubguess[i]==privsoln[j] && correct[j] == 0)  then j+1 else x fi
    endfor
    return x


def main(field nb,field nw, field[4] pubguess,private field[4] privsoln, field[2] pubsoln):
	field nbb = 0
    field nww= 0
    field[4] correct = [0,0,0,0]
    field[4] privsoln_copy = privsoln
    for u32 i in 0..4 do
        nbb =if (pubguess[i] == privsoln[i]) then nbb+1 else nbb fi
        correct[i]=if (pubguess[i] == privsoln[i]) then 1 else 0 fi
    endfor

    u32 pos=0
    u32 x=0
    for u32 i in 0..4 do
        pos = if correct[i]==0 then loop(i,privsoln_copy,pubguess,correct) else  0  fi
        nww = if pos!=0  then nww+1 else nww fi
        x =if pos==0 then 1 else pos fi
        privsoln_copy[x-1]=if pos==0 then privsoln[x-1] else 0 fi
    endfor

  
    field[2] h = sha256packed(privsoln)
    assert(h==pubsoln)
    assert(nb==nbb)
    assert(nw==nww)
    
    return `
 
// instantiating the hash circuit
const hash =`import "hashes/sha256/512bitPacked" as sha256packed

def main(field[4] privsoln) -> field[2]:
    field[2] h = sha256packed(privsoln)
    return h`
    
// generate the proof
// first we generate the arguments by calling generate_witness() and generate the hash of privsoln

const generate_proof=(guess)=>{
  
    initialize().then((zokratesProvider) => {
        
        let pubGuess = guess.slice();
        privSoln = input.Solution
    
        //generate the number of black and white pegs
        witness=generate_witness(input.Solution,pubGuess)
        //compile     
        const artifacts_hash = zokratesProvider.compile(hash);
        //compute hash
        const { _ , output } = zokratesProvider.computeWitness(artifacts_hash, [privSoln]);
        //taking out the hash 128 bits at a time
        a = output.slice(11,50)
        b = output.slice(58,97)
        //constructing the arguments array
        args = [witness[0],witness[1],guess,privSoln,[a,b]]
       
    });
    
    initialize().then((zokratesProvider) => {

        // compilation
        const artifacts = zokratesProvider.compile(source);
        //console.log(args)
        //computation
        const { witness, output } = zokratesProvider.computeWitness(artifacts,args);
        console.log("Witness and Output computed...")
        // run setup
        const keypair = zokratesProvider.setup(artifacts.program);
        // generate proof
        const proof =  zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
        //writing the proof into  json
        fs.writeFile('proof.json', JSON.stringify(proof), (err) => {
        if (err) throw err;
        else console.log("Proof generated...");
        });

        //verify using the generated keypair and proof
        if ( zokratesProvider.verify(keypair.vk, proof)) {
            console.log("Proof is correct...")
        }

        // export solidity verifier
       const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk, "v1");
        fs.writeFile('contracts/verifier.sol', verifier, (err) => {
            if (err) throw err;
            else console.log("contract generated...");
        });
        
    
    });

}
const proof=()=>{
    generate_proof(guess_data)
}


module.exports={
	generate_proof,
    proof
};
