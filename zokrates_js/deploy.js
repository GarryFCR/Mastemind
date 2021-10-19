const fs = require('fs');


async function main(){

	const [owner] =  await ethers.getSigners();
	console.log("Owner:",owner.address);

	const Verifier = await ethers.getContractFactory("Verifier");
  	const verifier = await Verifier.deploy();
    console.log("Verifier contract :",verifier.address);


  	const contract ={
  		address: verifier.address,
  		abi: JSON.parse(verifier.interface.format('json'))
  	};

  	fs.writeFileSync('frontend/react-app/src/master.json',JSON.stringify(contract));


}

main().then(()=> process.exit(0))
	.catch(error=>{
		console.error(error);
		process.exit(1);
	});