const generate_witness =(pubGuess,privSoln)=>{
    var nw=0,nb=0;
    var correct=[0,0,0,0];
    var correct_colour=[0,0,0,0]
    var privSoln_copy = privSoln

    if (pubGuess.length !== 4 || privSoln.length !== 4){
        throw new Error("Invalid input")
    }

    for(var i=0;i<4;i++){
        if (pubGuess[i]===privSoln[i]){
            correct[i]=1
            nb++;
        }
    }

    for(var j=0;j<4;j++){
        if (correct[j]==0){
            for (var k=0;k<4;k++){
                if (pubGuess[j]==privSoln_copy[k] && correct[k]==0){
                    nw++
                    correct_colour[k]=1
                    privSoln_copy[k]=0
                }
            }
        }
    }

    //console.log(String(nb),String(nw))
    return [String(nb),String(nw)]
}





module.exports={
	generate_witness
};
