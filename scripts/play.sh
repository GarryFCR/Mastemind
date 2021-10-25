#!/bin/bash



# Enter the Guess [n1,n2,n3,n4]
echo "-----------------Enter your guess-----------------"
read -p "Enter first number  : " n1
read -p "Enter second number : " n2
read -p "Enter third number  : " n3
read -p "Enter fourth number : " n4

echo "Your Guess - [$n1,$n2,$n3,$n4]"

# storing the guess in a json file
echo "{\"Guess\":[\"$n1\",\"$n2\",\"$n3\",\"$n4\"]}" > ./zokrates_js/pubGuess.json


# generating the proof by calling proof()
echo "--------------------------------------------------"
echo "-----------------Generating proof-----------------"
node -e 'require("./zokrates_js/proof.js").proof()'
echo "--------------------------------------------------"
# compile the generated contract
npx hardhat compile
# verifying the proof by calling  verifyTX() from the verifier contract
echo "-----------------Veryfying------------------------"
node -e 'require("./zokrates_js/verify.js").verify()'
echo "--------------------------------------------------"


# Running tests to ensure correctness
echo "-----------------Testing--------------------------"
npx hardhat test
echo "--------------------------------------------------"
