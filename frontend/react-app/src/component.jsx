import React, {Component} from "react";
import {ethers} from "ethers";
import { generate_proof } from "./zokrates_js/proof.js";
import master from "./master.json"


class App extends Component {
	
	//get account connected via metamask
	requestAccount() {
		window.ethereum.request({method: "eth_requestAccounts"});
	}

	getProof = (val) => {
		
		const pattern = "[1-4]{4}";
		if (val.target.value.match(pattern)) {
			var arr = val.target.value;
			var guess = arr.map(function(e){return e.toString()});
			generate_proof(guess)
		} 
	};

	

	verifyProof=()=>{
		if (typeof window.ethereum !== "undefined") {

			this.requestAccount();
			const provider = new ethers.providers.Web3Provider(window.ethereum);
			
			const signer = provider.getSigner();
			//instatiate the contract
			const contract = new ethers.Contract(master.address, master.abi, signer);
			
			
		}	
		

	}


	render() {
		return (
			<div className="text-center">
				<br />	
				<h1>MASTERMIND GAME</h1>
				<br /><br />
				<br />
				<div > 
					<h5>Guess the Combination/Permutation of 1,2,3,4</h5>
					<br/>
					<input
						type="text"
						//onChange={this.getProof}
						placeholder="Enter Guess"
					></input>
					<button 
						className="btn btn-secondary btn-sm"
						onClick={() => {
							this.getProof;
						}}
					>
						Generate Proof
					</button>
					<br /><br />
				</div>
				<br/><br/>
			</div>
		);
	}
}

export default App;
