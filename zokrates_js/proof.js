//const   sizeof  = require('object-sizeof');
const fs = require("fs");
const { initialize } = require('zokrates-js/node');
const input  =require('./privsoln.json');
const { generate_witness } = require('./witness.js')
var args;


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
        privsoln_copy[x-1]=if pos==1 then privsoln[x-1] else 0 fi
    endfor

  
    field[2] h = sha256packed(privsoln)
    assert(h==pubsoln)
    assert(nb==nbb)
    assert(nw==nww)
    
    return `
 
const hash =`import "hashes/sha256/512bitPacked" as sha256packed

def main(field[4] privsoln) -> field[2]:
    field[2] h = sha256packed(privsoln)
    return h`
    
const generate_proof=(guess)=>{

    initialize().then((zokratesProvider) => {
        
        let pubGuess = guess.slice();
        privSoln = input.Solution
    
        witness=generate_witness(input.Solution,pubGuess)
            
        const artifacts_hash = zokratesProvider.compile(hash);
        const { _ , output } = zokratesProvider.computeWitness(artifacts_hash, [privSoln]);
        a = output.slice(11,50)
        b = output.slice(58,97)

        args = [witness[0],witness[1],guess,privSoln,[a,b]]
        //console.log(args)
    
    });
    
    initialize().then((zokratesProvider) => {

        // compilation
        const artifacts = zokratesProvider.compile(source);
        //computation
        const { witness, output } = zokratesProvider.computeWitness(artifacts,args);
        console.log("Witness and Output computed...",output)
        // run setup
        const keypair = zokratesProvider.setup(artifacts.program);
        // generate proof
        const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
        fs.writeFile('proof.json', JSON.stringify(proof), (err) => {
        if (err) throw err;
        else console.log("Proof generated...");
        });
/*
        if (zokratesProvider.verify(keypair.vk, proof)) {
            console.log("Verified")
        }
*/
    });

}
//generate_proof(["2","2","3","1"])
module.exports={
	generate_proof
};
